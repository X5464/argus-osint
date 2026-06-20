"""Vault API routes for ARGUS LEA."""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from auth import get_current_user, require_roles
from vault import list_key_status, normalize_service, set_key

vault_bp = Blueprint("vault_bp", __name__)


@vault_bp.route("/vault/keys", methods=["GET"])
def vault_list():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Authentication required."}), 401
    return jsonify({"keys": list_key_status(user.get("username"))})


@vault_bp.route("/vault/keys", methods=["POST"])
@require_roles("admin", "supervisor", "investigator")
def vault_set():
    user = get_current_user()
    data = request.get_json(silent=True) or {}
    service = (data.get("service") or "").strip()
    value = (data.get("value") or "").strip()
    scope = (data.get("scope") or "global").strip().lower()

    if not service:
        return jsonify({"error": "service is required."}), 400
    if not normalize_service(service):
        return jsonify({"error": "Unknown service. Use vt, abuse, or truecaller."}), 400

    username = user.get("username") if scope == "user" else None
    set_key(service, value, username=username, scope=scope)
    return jsonify({"success": True, "keys": list_key_status(user.get("username"))})
