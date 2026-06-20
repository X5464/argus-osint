"""Supervisor dashboard endpoints for ARGUS LEA."""

from __future__ import annotations

from flask import Blueprint, jsonify

from audit import get_recent_entries
from auth import get_online_sessions, require_roles
from cases import get_active_case_id, get_case, load_cases_store

supervisor_bp = Blueprint("supervisor_bp", __name__)


@supervisor_bp.route("/supervisor/overview", methods=["GET"])
@require_roles("admin", "supervisor")
def supervisor_overview():
    cases = load_cases_store().get("cases", [])
    open_cases = [c for c in cases if c.get("status") == "open"]
    return jsonify(
        {
            "active_cases_count": len(open_cases),
            "total_cases": len(cases),
            "open_cases": open_cases[:20],
            "recent_audit": get_recent_entries(50),
            "online_sessions": get_online_sessions(),
        }
    )
