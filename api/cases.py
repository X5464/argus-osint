"""Investigation case management for ARGUS LEA."""

from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable, Dict, List, Optional

from flask import Blueprint, jsonify, request, session

from auth import get_current_user
from paths import CASES_FILE, ensure_data_dirs

cases_bp = Blueprint("cases_bp", __name__)
_lock = threading.Lock()


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_cases_store() -> Dict[str, Any]:
    return _load_cases()


def _load_cases() -> Dict[str, Any]:
    ensure_data_dirs()
    if not os.path.isfile(CASES_FILE):
        return {"cases": [], "seq": 0}
    try:
        with open(CASES_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return {"cases": [], "seq": 0}


def _save_cases(data: Dict[str, Any]) -> None:
    ensure_data_dirs()
    tmp = f"{CASES_FILE}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, CASES_FILE)
    try:
        os.chmod(CASES_FILE, 0o600)
    except OSError:
        pass


def _next_case_id(data: Dict[str, Any]) -> str:
    seq = int(data.get("seq", 0)) + 1
    data["seq"] = seq
    day = datetime.now(timezone.utc).strftime("%Y%m%d")
    return f"CASE-{day}-{seq:03d}"


def get_case(case_id: str) -> Optional[Dict[str, Any]]:
    for case in _load_cases().get("cases", []):
        if case.get("case_id") == case_id:
            return case
    return None


def get_active_case_id() -> Optional[str]:
    """Resolve active case for this request.

    Ad-hoc sessions send ``X-Case-Mode: off`` and omit ``X-Case-Id`` so tools
    work without a case file. Case mode sends ``X-Case-Mode: on`` plus the case id.
    Session fallback applies only when the client explicitly enables case mode.
    """
    case_mode = request.headers.get("X-Case-Mode", "").strip().lower()
    if case_mode == "off":
        return None

    header = request.headers.get("X-Case-Id", "").strip()
    if header:
        return header

    body = request.get_json(silent=True) or {}
    if body.get("case_id"):
        return str(body["case_id"]).strip()

    if case_mode == "on":
        return session.get("active_case_id")

    return None


def set_active_case_id(case_id: str) -> None:
    session["active_case_id"] = case_id


def require_case_authorization(fn: Callable) -> Callable:
    """Validate case only when X-Case-Id (or body case_id) is present; ad-hoc mode allowed."""

    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any):
        case_id = get_active_case_id()
        if not case_id:
            return fn(*args, **kwargs)
        case = get_case(case_id)
        if not case:
            return jsonify({"error": f"Case '{case_id}' not found."}), 404
        if case.get("status") == "closed":
            return jsonify({"error": f"Case '{case_id}' is closed."}), 403
        auth_ref = (case.get("authorization_ref") or "").strip()
        if not auth_ref:
            return (
                jsonify(
                    {
                        "error": (
                            "Legal authorization reference (warrant/court order) "
                            f"required on case '{case_id}' before sensitive operations."
                        )
                    }
                ),
                403,
            )
        request.case_context = case  # type: ignore[attr-defined]
        return fn(*args, **kwargs)

    return wrapper


@cases_bp.route("/cases", methods=["GET"])
def list_cases():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Authentication required."}), 401

    status_filter = request.args.get("status", "").strip().lower()
    cases: List[Dict[str, Any]] = _load_cases().get("cases", [])
    if status_filter in ("open", "closed"):
        cases = [c for c in cases if c.get("status") == status_filter]

    active = get_active_case_id()
    return jsonify({"cases": cases, "active_case_id": active})


@cases_bp.route("/cases", methods=["POST"])
def create_case():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Authentication required."}), 401

    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    if not title:
        return jsonify({"error": "Case title is required."}), 400

    with _lock:
        store = _load_cases()
        case = {
            "case_id": _next_case_id(store),
            "title": title,
            "lead_investigator": (data.get("lead_investigator") or user.get("username", "")).strip(),
            "authorization_ref": (data.get("authorization_ref") or "").strip(),
            "legal_basis": (data.get("legal_basis") or "").strip(),
            "status": "open",
            "created_at": _utc_now(),
            "notes": (data.get("notes") or "").strip(),
        }
        store.setdefault("cases", []).append(case)
        _save_cases(store)

    return jsonify({"success": True, "case": case}), 201


@cases_bp.route("/cases/<case_id>", methods=["GET"])
def get_case_detail(case_id: str):
    user = get_current_user()
    if not user:
        return jsonify({"error": "Authentication required."}), 401
    case = get_case(case_id)
    if not case:
        return jsonify({"error": "Case not found."}), 404
    return jsonify({"case": case})


@cases_bp.route("/cases/<case_id>", methods=["PATCH"])
def update_case(case_id: str):
    user = get_current_user()
    if not user:
        return jsonify({"error": "Authentication required."}), 401

    data = request.get_json(silent=True) or {}
    with _lock:
        store = _load_cases()
        found = False
        for case in store.get("cases", []):
            if case.get("case_id") != case_id:
                continue
            found = True
            for field in ("title", "lead_investigator", "authorization_ref", "legal_basis", "notes"):
                if field in data:
                    case[field] = str(data[field]).strip()
            if "status" in data and data["status"] in ("open", "closed"):
                case["status"] = data["status"]
            break
        if not found:
            return jsonify({"error": "Case not found."}), 404
        _save_cases(store)
        updated = get_case(case_id)
    return jsonify({"success": True, "case": updated})


@cases_bp.route("/cases/<case_id>/activate", methods=["POST"])
def activate_case(case_id: str):
    user = get_current_user()
    if not user:
        return jsonify({"error": "Authentication required."}), 401
    case = get_case(case_id)
    if not case:
        return jsonify({"error": "Case not found."}), 404
    set_active_case_id(case_id)
    return jsonify({"success": True, "active_case_id": case_id, "case": case})


@cases_bp.route("/cases/active", methods=["GET"])
def active_case():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Authentication required."}), 401
    cid = get_active_case_id()
    if not cid:
        return jsonify({"active_case_id": None, "case": None})
    case = get_case(cid)
    return jsonify({"active_case_id": cid, "case": case})
