import os
import sys
import time
from collections import defaultdict
from typing import FrozenSet, Tuple

# Ensure the 'api' folder and vendored packages are on the system path
_api_path = os.path.dirname(os.path.abspath(__file__))
_vendor_path = os.path.join(_api_path, "vendor")
for _path in (_api_path, _vendor_path):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from flask import Flask, g, jsonify, request, session
from flask_cors import CORS

from auth import (
    get_current_user,
    get_or_create_secret_key,
    init_auth,
    is_auth_enabled,
    is_lea_acknowledged,
    register_session_activity,
    session_timeout_seconds,
)
from cases import get_active_case_id, get_case
from audit import log_structured
from paths import ARGUS_VERSION, ensure_data_dirs
from modules.identity import identity_bp
from modules.webcheck import webcheck_bp
from modules.spiderweb import spiderweb_bp
from modules.recon import recon_bp
from cases import cases_bp
from auth import auth_bp
from evidence import evidence_bp
from supervisor import supervisor_bp
from vault_routes import vault_bp

# ──────────────────────────────────────────────
# Application factory
# ──────────────────────────────────────────────

public_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "public"))
app = Flask(__name__, static_folder=public_dir, static_url_path="/")

ensure_data_dirs()
init_auth()

app.secret_key = get_or_create_secret_key()
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = session_timeout_seconds()

# CORS locked to localhost only
CORS(
    app,
    origins=[
        r"http://127\.0\.0\.1:\d+",
        r"http://localhost:\d+",
    ],
    supports_credentials=True,
)

# Rate limiting — simple in-memory throttle (60 req/min per IP)
_rate_buckets: dict[str, list[float]] = defaultdict(list)
RATE_LIMIT = 60
RATE_WINDOW = 60.0

AUTH_EXEMPT: FrozenSet[str] = frozenset(
    {
        "/api/health",
        "/api/auth/status",
        "/api/auth/profiles",
        "/api/auth/profile/select",
        "/api/auth/acknowledge",
        "/api/auth/login",
        "/api/auth/token",
    }
)

CASE_EXEMPT: FrozenSet[str] = frozenset(
    AUTH_EXEMPT
    | {
        "/api/cases",
        "/api/cases/active",
        "/api/auth/logout",
        "/api/auth/change-password",
        "/api/vault/keys",
        "/api/supervisor/overview",
        "/api/evidence/export",
        "/api/wordlist/info",
    }
)

SENSITIVE_PREFIXES: Tuple[str, ...] = (
    "/api/ip",
    "/api/phone",
    "/api/username",
    "/api/email",
    "/api/breach",
    "/api/infostealer",
    "/api/domain",
    "/api/subdomains",
    "/api/scan-abuseip",
    "/api/scan-virustotal",
    "/api/recon/",
    "/api/search/",
    "/api/scan/",
    "/api/subdomain",
    "/api/crack/",
    "/api/pdf/",
)


def _client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1").split(",")[0].strip()


def _is_sensitive_path(path: str) -> bool:
    if path in CASE_EXEMPT:
        return False
    if not path.startswith("/api/"):
        return False
    return any(path == p or path.startswith(p) for p in SENSITIVE_PREFIXES)


@app.before_request
def security_middleware():
    # Rate limit API routes
    if request.path.startswith("/api/"):
        ip = _client_ip()
        now = time.time()
        bucket = _rate_buckets[ip]
        _rate_buckets[ip] = [t for t in bucket if now - t < RATE_WINDOW]
        if len(_rate_buckets[ip]) >= RATE_LIMIT:
            return jsonify({"error": "Rate limit exceeded. Max 60 requests/minute."}), 429
        _rate_buckets[ip].append(now)

    if not request.path.startswith("/api/"):
        return None

    if request.path in AUTH_EXEMPT:
        return None

    if is_auth_enabled():
        user = get_current_user()
        if not user:
            return (
                jsonify(
                    {
                        "error": "Select an investigator profile first.",
                        "requires_profile": True,
                    }
                ),
                401,
            )
        g.current_user = user  # type: ignore[attr-defined]
        register_session_activity(user)

        if not is_lea_acknowledged() and request.path != "/api/auth/acknowledge":
            return (
                jsonify(
                    {
                        "error": "LEA authorization notice must be acknowledged before use.",
                        "requires_ack": True,
                    }
                ),
                403,
            )

    if _is_sensitive_path(request.path):
        case_id = get_active_case_id()
        if case_id:
            case = get_case(case_id)
            if not case:
                return jsonify({"error": f"Case '{case_id}' not found."}), 404
            if case.get("status") == "closed":
                return jsonify({"error": f"Case '{case_id}' is closed."}), 403
            if not (case.get("authorization_ref") or "").strip():
                return (
                    jsonify(
                        {
                            "error": (
                                "Legal authorization reference required on active case "
                                "before sensitive recon operations."
                            )
                        }
                    ),
                    403,
                )
            g.case_context = case  # type: ignore[attr-defined]

    return None


@app.after_request
def audit_api_requests(response):
    if not request.path.startswith("/api/"):
        return response

    user = getattr(g, "current_user", None) or get_current_user()
    username = (
        user.get("display_name") or user.get("username", "anonymous") if user else "anonymous"
    )
    case = getattr(g, "case_context", None)
    case_id = case.get("case_id") if case else get_active_case_id()

    action = f"{request.method} {request.path}"
    details = ""
    if request.is_json:
        try:
            body = request.get_json(silent=True) or {}
            details = str({k: v for k, v in body.items() if k not in ("password", "value")})
        except Exception:
            pass
    elif request.files:
        details = f"File Upload: {list(request.files.keys())}"

    result_status = "ok" if response.status_code < 400 else "error"
    try:
        result_body = response.get_json(silent=True)
    except Exception:
        result_body = None

    log_structured(
        interface=request.headers.get("X-Interface", "GUI"),
        user=username,
        case_id=case_id,
        authorization_ref=case.get("authorization_ref") if case else None,
        module=request.path.split("/")[2] if len(request.path.split("/")) > 2 else "api",
        target=details[:120],
        action=action,
        result=result_body,
        result_status=result_status,
        ip_address=_client_ip(),
        details=details[:500],
    )
    return response


# Register feature blueprints
app.register_blueprint(identity_bp, url_prefix="/api")
app.register_blueprint(webcheck_bp, url_prefix="/api")
app.register_blueprint(spiderweb_bp, url_prefix="/api")
app.register_blueprint(recon_bp, url_prefix="/api")
app.register_blueprint(cases_bp, url_prefix="/api")
app.register_blueprint(auth_bp, url_prefix="/api")
app.register_blueprint(evidence_bp, url_prefix="/api")
app.register_blueprint(supervisor_bp, url_prefix="/api")
app.register_blueprint(vault_bp, url_prefix="/api")


@app.route("/")
def serve_frontend():
    return app.send_static_file("index.html")


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify(
        {
            "status": "ok",
            "service": "ARGUS Intelligence API",
            "version": ARGUS_VERSION,
            "edition": "LEA",
            "modules": [
                "identity",
                "webcheck",
                "spiderweb",
                "recon",
                "cases",
                "auth",
                "evidence",
                "vault",
            ],
            "auth_enabled": is_auth_enabled(),
        }
    )


if __name__ == "__main__":
    debug = os.environ.get("ARGUS_DEBUG", "").strip() in ("1", "true", "yes")
    app.run(debug=debug, port=int(os.environ.get("ARGUS_PORT", "5000")), host="127.0.0.1")
