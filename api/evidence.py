"""Evidence export — court-ready bundles for ARGUS LEA."""

from __future__ import annotations

import html
import json
from typing import Any, Dict, List, Optional

from flask import Blueprint, Response, jsonify, request

from audit import log_structured, read_case_audit, read_last_entry
from auth import get_current_user
from cases import get_active_case_id, get_case
from paths import ARGUS_VERSION

evidence_bp = Blueprint("evidence_bp", __name__)


def _esc(text: Any) -> str:
    return html.escape(str(text) if text is not None else "")


def _build_html_report(case: Dict[str, Any], entries: List[Dict[str, Any]]) -> str:
    rows = ""
    for e in entries:
        rows += f"""<tr>
          <td>{_esc(e.get('timestamp',''))}</td>
          <td>{_esc(e.get('user',''))}</td>
          <td>{_esc(e.get('module',''))}</td>
          <td>{_esc(e.get('target',''))}</td>
          <td>{_esc(e.get('action',''))}</td>
          <td class="mono">{_esc(e.get('result_hash',''))[:16]}…</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>ARGUS Evidence Report — {_esc(case.get('case_id',''))}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif; margin: 40px; color: #111; }}
  h1 {{ font-size: 22px; margin-bottom: 4px; }}
  .meta {{ font-size: 13px; color: #444; margin-bottom: 24px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
  th, td {{ border: 1px solid #ccc; padding: 8px 10px; text-align: left; }}
  th {{ background: #f5f5f5; }}
  .mono {{ font-family: ui-monospace, Menlo, monospace; font-size: 11px; }}
  footer {{ margin-top: 32px; font-size: 11px; color: #666; border-top: 1px solid #ddd; padding-top: 12px; }}
  @media print {{ body {{ margin: 20px; }} }}
</style>
</head>
<body>
  <h1>ARGUS Intelligence Platform — Evidence Export</h1>
  <div class="meta">
    <div><strong>Case ID:</strong> {_esc(case.get('case_id'))}</div>
    <div><strong>Title:</strong> {_esc(case.get('title'))}</div>
    <div><strong>Lead Investigator:</strong> {_esc(case.get('lead_investigator'))}</div>
    <div><strong>Authorization Reference:</strong> {_esc(case.get('authorization_ref'))}</div>
    <div><strong>Legal Basis:</strong> {_esc(case.get('legal_basis'))}</div>
    <div><strong>Status:</strong> {_esc(case.get('status'))}</div>
    <div><strong>Created:</strong> {_esc(case.get('created_at'))}</div>
  </div>
  <h2>Chain of Custody Timeline</h2>
  <table>
    <thead><tr>
      <th>Timestamp (UTC)</th><th>User</th><th>Module</th><th>Target</th><th>Action</th><th>Integrity Hash</th>
    </tr></thead>
    <tbody>{rows or '<tr><td colspan="6">No audit entries recorded for this case.</td></tr>'}</tbody>
  </table>
  <footer>
    Exported by ARGUS v{ARGUS_VERSION} · Integrity hashes are SHA-256 of response JSON ·
    Export generated at request time · For authorized law enforcement use only.
  </footer>
</body>
</html>"""


@evidence_bp.route("/evidence/export", methods=["POST"])
def export_evidence():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Authentication required."}), 401

    data = request.get_json(silent=True) or {}
    export_format = (data.get("format") or "json").strip().lower()
    scope = (data.get("scope") or "last").strip().lower()

    case_id = (data.get("case_id") or get_active_case_id() or "").strip()
    case: Optional[Dict[str, Any]] = get_case(case_id) if case_id else None

    if scope == "case":
        if not case_id or not case:
            return jsonify({"error": "Valid case_id required for case export."}), 400
        entries = read_case_audit(case_id)
        bundle: Dict[str, Any] = {
            "export_type": "case_report",
            "argus_version": ARGUS_VERSION,
            "case": case,
            "audit_entries": entries,
            "entry_count": len(entries),
        }
    else:
        entry = read_last_entry()
        if not entry:
            return jsonify({"error": "No recent operation to export."}), 404
        bundle = {
            "export_type": "single_operation",
            "argus_version": ARGUS_VERSION,
            "case": case,
            "operation": entry,
        }
        entries = [entry]

    log_structured(
        interface=request.headers.get("X-Interface", "GUI"),
        user=user.get("username", "unknown"),
        case_id=case_id or None,
        authorization_ref=case.get("authorization_ref") if case else None,
        module="evidence",
        target=case_id or "last",
        action=f"export_{scope}",
        result=bundle,
    )

    if export_format == "html":
        if not case and scope == "case":
            return jsonify({"error": "Case required for HTML report."}), 400
        report_case = case or {
            "case_id": case_id or "N/A",
            "title": "Single Operation Export",
            "lead_investigator": user.get("username"),
            "authorization_ref": entry.get("authorization_ref", "") if scope != "case" else "",
            "legal_basis": "",
            "status": "open",
            "created_at": "",
        }
        html_body = _build_html_report(report_case, entries)
        return Response(html_body, mimetype="text/html")

    return jsonify(bundle)
