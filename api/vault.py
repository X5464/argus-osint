"""Encrypted API key vault for ARGUS LEA — no keys in source code."""

from __future__ import annotations

import base64
import json
import os
import threading
from typing import Any, Dict, Optional

from cryptography.fernet import Fernet, InvalidToken

from paths import VAULT_FILE, VAULT_KEY_FILE, ensure_data_dirs

_lock = threading.Lock()

SERVICE_MAP = {
    "vt": "VT_API_KEY",
    "virustotal": "VT_API_KEY",
    "abuse": "ABUSE_IPDB_KEY",
    "abuseipdb": "ABUSE_IPDB_KEY",
    "truecaller": "TRUECALLER_ID",
    "tc": "TRUECALLER_ID",
    "github": "GITHUB_TOKEN",
    "github_token": "GITHUB_TOKEN",
}


def _get_fernet() -> Fernet:
    ensure_data_dirs()
    if not os.path.isfile(VAULT_KEY_FILE):
        key = Fernet.generate_key()
        with open(VAULT_KEY_FILE, "wb") as fh:
            fh.write(key)
        try:
            os.chmod(VAULT_KEY_FILE, 0o600)
        except OSError:
            pass
    else:
        with open(VAULT_KEY_FILE, "rb") as fh:
            key = fh.read().strip()
    return Fernet(key)


def _load_vault() -> Dict[str, Any]:
    if not os.path.isfile(VAULT_FILE):
        return {"global": {}, "users": {}}
    try:
        fernet = _get_fernet()
        with open(VAULT_FILE, "rb") as fh:
            raw = fernet.decrypt(fh.read())
        return json.loads(raw.decode("utf-8"))
    except (InvalidToken, json.JSONDecodeError, OSError):
        return {"global": {}, "users": {}}


def _save_vault(data: Dict[str, Any]) -> None:
    ensure_data_dirs()
    fernet = _get_fernet()
    payload = fernet.encrypt(json.dumps(data).encode("utf-8"))
    tmp = f"{VAULT_FILE}.tmp"
    with open(tmp, "wb") as fh:
        fh.write(payload)
    os.replace(tmp, VAULT_FILE)
    try:
        os.chmod(VAULT_FILE, 0o600)
    except OSError:
        pass


def normalize_service(name: str) -> Optional[str]:
    return SERVICE_MAP.get(name.strip().lower())


def set_key(service: str, value: str, username: Optional[str] = None, scope: str = "global") -> bool:
    canonical = normalize_service(service)
    if not canonical:
        return False
    with _lock:
        vault = _load_vault()
        if scope == "user" and username:
            vault.setdefault("users", {}).setdefault(username, {})[canonical] = value
        else:
            vault.setdefault("global", {})[canonical] = value
        _save_vault(vault)
    return True


def get_key(service: str, username: Optional[str] = None) -> str:
    canonical = normalize_service(service)
    if not canonical:
        return ""
    vault = _load_vault()
    if username:
        user_keys = vault.get("users", {}).get(username, {})
        if user_keys.get(canonical):
            return user_keys[canonical]
    return vault.get("global", {}).get(canonical, "")


def list_key_status(username: Optional[str] = None) -> Dict[str, str]:
    vault = _load_vault()
    result: Dict[str, str] = {}
    for svc in ("VT_API_KEY", "ABUSE_IPDB_KEY", "TRUECALLER_ID", "GITHUB_TOKEN"):
        val = ""
        if username:
            val = vault.get("users", {}).get(username, {}).get(svc, "")
        if not val:
            val = vault.get("global", {}).get(svc, "")
        result[svc] = "CONFIGURED" if val else "NOT CONFIGURED"
    return result


def get_identity_keys(username: Optional[str] = None) -> Dict[str, str]:
    return {
        "VT_API_KEY": get_key("vt", username),
        "ABUSE_IPDB_KEY": get_key("abuse", username),
        "TRUECALLER_ID": get_key("truecaller", username),
        "GITHUB_TOKEN": get_key("github", username),
    }
