"""Local investigator profiles, sessions, and attribution for ARGUS LEA."""

from __future__ import annotations

import json
import os
import re
import secrets
import threading
import time
import uuid
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable, Dict, List, Optional

from flask import Blueprint, jsonify, request, session

from paths import (
    AUTH_CONFIG_FILE,
    LEA_ACK_FILE,
    PROFILES_FILE,
    SECRET_KEY_FILE,
    USERS_FILE,
    ensure_data_dirs,
)

auth_bp = Blueprint("auth_bp", __name__)

_lock = threading.Lock()
VALID_ROLES = frozenset({"investigator", "supervisor", "admin"})
_DISPLAY_NAME_RE = re.compile(r"^[a-zA-Z0-9 _\-.]{2,64}$")
DEFAULT_SESSION_HOURS = 8

# In-memory session registry for supervisor dashboard (session_id -> metadata)
ACTIVE_SESSIONS: Dict[str, Dict[str, Any]] = {}


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_json(path: str, default: Any) -> Any:
    if not os.path.isfile(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return default


def _save_json(path: str, data: Any) -> None:
    ensure_data_dirs()
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def get_auth_config() -> Dict[str, Any]:
    cfg = _load_json(
        AUTH_CONFIG_FILE,
        {"auth_enabled": True, "session_timeout_hours": DEFAULT_SESSION_HOURS},
    )
    cfg.setdefault("auth_enabled", True)
    cfg.setdefault("session_timeout_hours", DEFAULT_SESSION_HOURS)
    return cfg


def is_auth_enabled() -> bool:
    return bool(get_auth_config().get("auth_enabled", True))


def session_timeout_seconds() -> int:
    hours = int(get_auth_config().get("session_timeout_hours", DEFAULT_SESSION_HOURS))
    return max(1, hours) * 3600


def get_or_create_secret_key() -> str:
    ensure_data_dirs()
    if os.path.isfile(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE, "r", encoding="utf-8") as fh:
            key = fh.read().strip()
            if key:
                return key
    key = secrets.token_hex(32)
    with open(SECRET_KEY_FILE, "w", encoding="utf-8") as fh:
        fh.write(key)
    try:
        os.chmod(SECRET_KEY_FILE, 0o600)
    except OSError:
        pass
    return key


def load_profiles() -> Dict[str, Any]:
    return _load_json(PROFILES_FILE, {"profiles": [], "active_sessions": {}})


def save_profiles(data: Dict[str, Any]) -> None:
    data.setdefault("active_sessions", {})
    _save_json(PROFILES_FILE, data)


def _validate_display_name(display_name: str) -> str:
    name = display_name.strip()
    if not _DISPLAY_NAME_RE.match(name):
        raise ValueError(
            "Display name must be 2–64 characters: letters, digits, spaces, hyphen, underscore, period."
        )
    return name


def _profile_public(profile: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": profile.get("id"),
        "display_name": profile.get("display_name"),
        "role": profile.get("role", "investigator"),
        "created_at": profile.get("created_at"),
    }


def find_profile_by_id(profile_id: str) -> Optional[Dict[str, Any]]:
    pid = (profile_id or "").strip()
    if not pid:
        return None
    for profile in load_profiles().get("profiles", []):
        if profile.get("id") == pid:
            return profile
    return None


def find_profile_by_name(display_name: str) -> Optional[Dict[str, Any]]:
    target = (display_name or "").strip().lower()
    if not target:
        return None
    for profile in load_profiles().get("profiles", []):
        if profile.get("display_name", "").strip().lower() == target:
            return profile
    return None


def has_profiles() -> bool:
    """Return True if at least one investigator profile exists."""
    return bool(load_profiles().get("profiles"))


def has_users() -> bool:
    """Backward-compatible alias for first-run setup checks."""
    return has_profiles()


def migrate_users_to_profiles() -> None:
    """Migrate legacy password users from data/users.json to profiles (no passwords)."""
    if os.path.isfile(PROFILES_FILE) and load_profiles().get("profiles"):
        return
    legacy = _load_json(USERS_FILE, {"users": []})
    users = legacy.get("users") or []
    if not users:
        return

    profiles: List[Dict[str, Any]] = []
    for idx, user in enumerate(users):
        display_name = (user.get("username") or user.get("display_name") or f"User{idx + 1}").strip()
        role = (user.get("role") or "investigator").strip().lower()
        if role not in VALID_ROLES:
            role = "investigator"
        if idx == 0 and not any(u.get("role") == "admin" for u in users):
            role = "admin"
        profiles.append(
            {
                "id": user.get("id") or str(uuid.uuid4()),
                "display_name": display_name,
                "role": role,
                "created_at": user.get("created_at") or _utc_now(),
            }
        )

    save_profiles({"profiles": profiles, "active_sessions": {}})


def create_profile(display_name: str, role: str = "investigator") -> Dict[str, Any]:
    """Create a new investigator profile (no password)."""
    name = _validate_display_name(display_name)
    role_name = (role or "investigator").strip().lower()
    if role_name not in VALID_ROLES:
        raise ValueError(f"Invalid role. Choose: {', '.join(sorted(VALID_ROLES))}")

    with _lock:
        data = load_profiles()
        profiles = data.setdefault("profiles", [])
        if not profiles and role_name != "admin":
            role_name = "admin"
        for existing in profiles:
            if existing.get("display_name", "").strip().lower() == name.lower():
                raise ValueError("A profile with this display name already exists.")
        profile: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "display_name": name,
            "role": role_name,
            "created_at": _utc_now(),
        }
        profiles.append(profile)
        save_profiles(data)
    return _profile_public(profile)


def create_admin_profile(display_name: str) -> Dict[str, Any]:
    """Create the initial admin profile during interactive first-run setup."""
    name = _validate_display_name(display_name)
    with _lock:
        data = load_profiles()
        if data.get("profiles"):
            raise ValueError("Investigator profiles already exist.")
        profile: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "display_name": name,
            "role": "admin",
            "created_at": _utc_now(),
        }
        data["profiles"] = [profile]
        save_profiles(data)
    return profile


def list_profiles() -> List[Dict[str, Any]]:
    """Return all profiles."""
    return [_profile_public(p) for p in load_profiles().get("profiles", [])]


def _profile_as_user(profile: Dict[str, Any], auth_method: str) -> Dict[str, Any]:
    """Map profile to legacy user dict shape for audit/cases compatibility."""
    display_name = profile.get("display_name", "")
    return {
        "id": profile.get("id"),
        "username": display_name,
        "display_name": display_name,
        "role": profile.get("role", "investigator"),
        "auth_method": auth_method,
    }


def _session_profile_valid() -> bool:
    expires = session.get("expires_at", 0)
    if expires and time.time() > expires:
        session.clear()
        return False
    return bool(session.get("profile_id"))


def select_profile_session(profile: Dict[str, Any]) -> Dict[str, Any]:
    """Bind an investigator profile to the Flask session."""
    session.clear()
    session["profile_id"] = profile["id"]
    session["profile_name"] = profile["display_name"]
    session["profile_role"] = profile.get("role", "investigator")
    session["expires_at"] = time.time() + session_timeout_seconds()
    session["session_id"] = secrets.token_hex(16)
    session.permanent = True
    return {
        "success": True,
        "profile": _profile_public(profile),
        "session_id": session["session_id"],
    }


def get_current_user() -> Optional[Dict[str, Any]]:
    """Resolve active investigator profile from CLI headers or Flask session."""
    profile_id = (request.headers.get("X-Profile-Id") or "").strip()
    profile_name = (request.headers.get("X-Profile-Name") or "").strip()

    if profile_id or profile_name:
        profile = find_profile_by_id(profile_id) if profile_id else find_profile_by_name(profile_name)
        if profile:
            if profile_name and profile.get("display_name", "").lower() != profile_name.lower():
                return None
            return _profile_as_user(profile, "cli_header")
        return None

    if not _session_profile_valid():
        return None

    profile = find_profile_by_id(session.get("profile_id", ""))
    if not profile:
        session.clear()
        return None

    if profile.get("display_name") != session.get("profile_name"):
        session.clear()
        return None

    return _profile_as_user(profile, "session")


def register_session_activity(user: Dict[str, Any]) -> None:
    sid = session.get("session_id") or request.headers.get("X-Session-Id", "")
    if not sid:
        return
    ACTIVE_SESSIONS[sid] = {
        "session_id": sid,
        "username": user.get("display_name") or user.get("username"),
        "role": user.get("role"),
        "last_seen": _utc_now(),
        "interface": request.headers.get("X-Interface", "GUI"),
        "ip": request.remote_addr or "127.0.0.1",
    }


def get_online_sessions() -> List[Dict[str, Any]]:
    cutoff = time.time() - session_timeout_seconds()
    alive: List[Dict[str, Any]] = []
    stale: List[str] = []
    for sid, meta in ACTIVE_SESSIONS.items():
        try:
            seen = datetime.strptime(meta["last_seen"], "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc
            )
            if seen.timestamp() < cutoff:
                stale.append(sid)
            else:
                alive.append(meta)
        except (KeyError, ValueError):
            stale.append(sid)
    for sid in stale:
        ACTIVE_SESSIONS.pop(sid, None)
    return sorted(alive, key=lambda m: m.get("last_seen", ""), reverse=True)


def require_roles(*roles: str) -> Callable:
    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any):
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
            if user.get("role") not in roles:
                return jsonify({"error": "Insufficient privileges."}), 403
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def is_lea_acknowledged() -> bool:
    return os.path.isfile(LEA_ACK_FILE)


def acknowledge_lea(user: str, interface: str = "GUI") -> None:
    ensure_data_dirs()
    entry = {
        "acknowledged_at": _utc_now(),
        "user": user,
        "interface": interface,
        "notice": (
            "ARGUS is for authorized law enforcement use only. "
            "All operations require valid legal authorization."
        ),
    }
    with open(LEA_ACK_FILE, "w", encoding="utf-8") as fh:
        json.dump(entry, fh, indent=2)
        fh.write("\n")
    try:
        os.chmod(LEA_ACK_FILE, 0o600)
    except OSError:
        pass


@auth_bp.route("/auth/status", methods=["GET"])
def auth_status():
    user = get_current_user()
    profile = None
    if user:
        profile = {
            "id": user.get("id"),
            "display_name": user.get("display_name") or user.get("username"),
            "role": user.get("role"),
        }
    return jsonify(
        {
            "auth_enabled": is_auth_enabled(),
            "authenticated": user is not None,
            "profile": profile,
            "user": (
                {
                    "username": user.get("username"),
                    "display_name": user.get("display_name") or user.get("username"),
                    "role": user.get("role"),
                }
                if user
                else None
            ),
            "lea_acknowledged": is_lea_acknowledged(),
            "session_timeout_hours": get_auth_config().get("session_timeout_hours", DEFAULT_SESSION_HOURS),
        }
    )


@auth_bp.route("/auth/profiles", methods=["GET"])
def profiles_list_route():
    return jsonify({"profiles": list_profiles()})


@auth_bp.route("/auth/profiles", methods=["POST"])
def profiles_create_route():
    data = request.get_json(silent=True) or {}
    display_name = (data.get("display_name") or "").strip()
    role = (data.get("role") or "investigator").strip().lower()

    if not display_name:
        return jsonify({"error": "display_name is required."}), 400

    user = get_current_user()
    profiles_exist = has_profiles()
    if profiles_exist and role in ("admin", "supervisor"):
        if not user or user.get("role") != "admin":
            role = "investigator"

    try:
        if not profiles_exist:
            profile = create_admin_profile(display_name)
        else:
            profile = create_profile(display_name, role)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify({"success": True, "profile": _profile_public(profile)}), 201


@auth_bp.route("/auth/profile/select", methods=["POST"])
def profile_select_route():
    data = request.get_json(silent=True) or {}
    profile_id = (data.get("profile_id") or "").strip()
    display_name = (data.get("display_name") or "").strip()

    profile = None
    if profile_id:
        profile = find_profile_by_id(profile_id)
    elif display_name:
        profile = find_profile_by_name(display_name)

    if not profile:
        return jsonify({"error": "Profile not found."}), 404

    result = select_profile_session(profile)
    return jsonify(result)


@auth_bp.route("/auth/logout", methods=["POST"])
def logout():
    sid = session.get("session_id")
    if sid:
        ACTIVE_SESSIONS.pop(sid, None)
    session.clear()
    return jsonify({"success": True})


@auth_bp.route("/auth/acknowledge", methods=["POST"])
def acknowledge():
    user = get_current_user()
    profile_name = (
        (user.get("display_name") or user.get("username") if user else None)
        or request.headers.get("X-Profile-Name")
        or "anonymous"
    )
    data = request.get_json(silent=True) or {}
    interface = data.get("interface", "GUI")
    acknowledge_lea(profile_name, interface)
    return jsonify({"success": True, "acknowledged_at": _utc_now()})


# Legacy aliases — map old user endpoints to profiles
@auth_bp.route("/auth/users", methods=["GET"])
@require_roles("admin")
def users_list_route():
    profiles = list_profiles()
    users = [
        {
            "id": p["id"],
            "username": p["display_name"],
            "display_name": p["display_name"],
            "role": p["role"],
            "created_at": p.get("created_at"),
        }
        for p in profiles
    ]
    return jsonify({"users": users, "profiles": profiles})


@auth_bp.route("/auth/users", methods=["POST"])
@require_roles("admin")
def users_create_route():
    data = request.get_json(silent=True) or {}
    display_name = (data.get("display_name") or data.get("username") or "").strip()
    role = (data.get("role") or "investigator").strip().lower()

    if not display_name:
        return jsonify({"error": "display_name is required."}), 400

    try:
        profile = create_profile(display_name, role)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify({"success": True, "user": {"username": display_name, "role": role}, "profile": profile}), 201


@auth_bp.route("/auth/login", methods=["POST"])
def login_deprecated():
    return (
        jsonify(
            {
                "error": "Password login removed. Select an investigator profile instead.",
                "requires_profile": True,
            }
        ),
        410,
    )


@auth_bp.route("/auth/token", methods=["POST"])
def cli_token_deprecated():
    return (
        jsonify(
            {
                "error": "CLI bearer token login removed. Select an investigator profile at session start.",
                "requires_profile": True,
            }
        ),
        410,
    )


@auth_bp.route("/auth/change-password", methods=["POST"])
def change_password_deprecated():
    return jsonify({"error": "Passwords are not used. Investigator profiles have no passwords."}), 410


@auth_bp.route("/auth/users/<username>/password", methods=["POST"])
@require_roles("admin")
def users_admin_password_deprecated(username: str):
    return jsonify({"error": "Passwords are not used. Investigator profiles have no passwords."}), 410


def init_auth() -> None:
    """Bootstrap auth keys and migrate legacy users to profiles."""
    ensure_data_dirs()
    get_or_create_secret_key()
    migrate_users_to_profiles()
