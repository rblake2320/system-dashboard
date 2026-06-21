"""BPC secret custody backend.

The default backend uses the Python ``keyring`` package, which maps to Windows
Credential Manager on Windows. The module is optional at runtime: if keyring is
not installed or no OS backend is available, callers get an honest unavailable
status instead of plaintext file fallback.
"""
from __future__ import annotations

import json
import sys
from typing import Any

_SERVICE = "SelfConnect.BPC"


def _load_keyring():
    try:
        import keyring  # type: ignore

        return keyring
    except Exception:
        return None


def status() -> dict[str, Any]:
    keyring = _load_keyring()
    if keyring is None:
        return {
            "backend": "keyring",
            "available": False,
            "reason": "keyring_not_installed",
            "windows_credential_manager": sys.platform == "win32",
        }
    try:
        backend = keyring.get_keyring()
        backend_name = backend.__class__.__name__
    except Exception as exc:
        return {
            "backend": "keyring",
            "available": False,
            "reason": f"backend_error:{exc}",
            "windows_credential_manager": sys.platform == "win32",
        }
    return {
        "backend": "keyring",
        "available": True,
        "provider": backend_name,
        "windows_credential_manager": sys.platform == "win32",
    }


def store_credentials(pair_id: str, credentials: dict[str, Any]) -> dict[str, Any]:
    pair_id = str(pair_id or "").strip()
    if not pair_id:
        return {"stored": False, "reason": "missing_pair_id", **status()}
    keyring = _load_keyring()
    if keyring is None:
        return {"stored": False, **status()}
    try:
        payload = json.dumps(credentials, sort_keys=True, separators=(",", ":"))
        keyring.set_password(_SERVICE, pair_id, payload)
        return {"stored": True, "pair_id": pair_id, **status()}
    except Exception as exc:
        return {"stored": False, "reason": str(exc), **status()}


def has_credentials(pair_id: str) -> bool:
    pair_id = str(pair_id or "").strip()
    if not pair_id:
        return False
    keyring = _load_keyring()
    if keyring is None:
        return False
    try:
        return keyring.get_password(_SERVICE, pair_id) is not None
    except Exception:
        return False


def delete_credentials(pair_id: str) -> dict[str, Any]:
    pair_id = str(pair_id or "").strip()
    keyring = _load_keyring()
    if not pair_id:
        return {"deleted": False, "reason": "missing_pair_id"}
    if keyring is None:
        return {"deleted": False, **status()}
    try:
        keyring.delete_password(_SERVICE, pair_id)
        return {"deleted": True, "pair_id": pair_id}
    except Exception as exc:
        return {"deleted": False, "reason": str(exc)}
