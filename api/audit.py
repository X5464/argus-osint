"""Chain-of-custody audit logging for ARGUS LEA."""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from paths import AUDIT_DIR, AUDIT_LOG_FILE, ARGUS_VERSION, ensure_data_dirs

_log_lock = threading.Lock()
_recent_entries: List[Dict[str, Any]] = []
_MAX_RECENT = 200


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hash_result(data: Any) -> str:
    try:
        payload = json.dumps(data, sort_keys=True, default=str)
    except (TypeError, ValueError):
        payload = str(data)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def log_structured(
    *,
    interface: str = "API",
    user: str = "system",
    case_id: Optional[str] = None,
    authorization_ref: Optional[str] = None,
    module: str = "general",
    target: str = "",
    action: str = "",
    result: Any = None,
    result_status: str = "ok",
    ip_address: str = "127.0.0.1",
    details: str = "",
) -> Dict[str, Any]:
    """Append structured audit entry to audit.log and per-case JSONL."""
    entry: Dict[str, Any] = {
        "timestamp": _utc_now(),
        "interface": interface,
        "user": user,
        "case_id": case_id if case_id else None,
        "authorization_ref": authorization_ref or "",
        "module": module,
        "target": target,
        "action": action,
        "result_status": result_status,
        "result_hash": _hash_result(result) if result is not None else "",
        "ip_address": ip_address,
        "details": details,
        "argus_version": ARGUS_VERSION,
    }

    line = json.dumps(entry, default=str) + "\n"
    legacy = (
        f"[{entry['timestamp']}] {interface} | user={user} | case={case_id or '—'} | "
        f"module={module} | action={action} | target={target} | hash={entry['result_hash']}\n"
    )

    try:
        ensure_data_dirs()
        with _log_lock:
            with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as fh:
                fh.write(legacy)

            if case_id:
                case_log = os.path.join(AUDIT_DIR, f"audit_{case_id}.jsonl")
                with open(case_log, "a", encoding="utf-8") as cfh:
                    cfh.write(line)

            _recent_entries.append(entry)
            if len(_recent_entries) > _MAX_RECENT:
                del _recent_entries[: len(_recent_entries) - _MAX_RECENT]
    except OSError as exc:
        print(f"[!] Audit logging error: {exc}", flush=True)

    return entry


def log_action(action: str, details: str = "", **kwargs: Any) -> Dict[str, Any]:
    """Backward-compatible wrapper used by legacy call sites."""
    return log_structured(action=action, details=details, **kwargs)


def read_case_audit(case_id: str, limit: int = 500) -> List[Dict[str, Any]]:
    path = os.path.join(AUDIT_DIR, f"audit_{case_id}.jsonl")
    if not os.path.isfile(path):
        return []
    entries: List[Dict[str, Any]] = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        return []
    return entries[-limit:]


def get_recent_entries(limit: int = 50) -> List[Dict[str, Any]]:
    return list(reversed(_recent_entries[-limit:]))


def read_last_entry() -> Optional[Dict[str, Any]]:
    return _recent_entries[-1] if _recent_entries else None
