"""Central filesystem paths for ARGUS LEA data stores."""

from __future__ import annotations

import os

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_DIR = os.path.join(ROOT_DIR, "data")
AUDIT_DIR = os.path.join(DATA_DIR, "audit")

USERS_FILE = os.path.join(DATA_DIR, "users.json")
PROFILES_FILE = os.path.join(DATA_DIR, "profiles.json")
CASES_FILE = os.path.join(DATA_DIR, "cases.json")
VAULT_FILE = os.path.join(DATA_DIR, "vault.json")
TOKEN_FILE = os.path.join(DATA_DIR, ".argus_token")
CLI_USERNAME_FILE = os.path.join(DATA_DIR, ".cli_username")
SECRET_KEY_FILE = os.path.join(DATA_DIR, ".secret_key")
VAULT_KEY_FILE = os.path.join(DATA_DIR, ".vault_key")
LEA_ACK_FILE = os.path.join(DATA_DIR, ".lea_ack")
AUTH_CONFIG_FILE = os.path.join(DATA_DIR, "auth_config.json")
AUDIT_LOG_FILE = os.path.join(ROOT_DIR, "audit.log")

ARGUS_VERSION = "3.1.0-LEA"


def ensure_data_dirs() -> None:
    os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
    os.makedirs(AUDIT_DIR, mode=0o700, exist_ok=True)
