"""Tests for BPC secret-vault adapter."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import bpc_secret_vault


class _FakeKeyring:
    def __init__(self):
        self.values = {}

    def get_keyring(self):
        return self

    def set_password(self, service, username, password):
        self.values[(service, username)] = password

    def get_password(self, service, username):
        return self.values.get((service, username))

    def delete_password(self, service, username):
        self.values.pop((service, username), None)


def test_status_reports_unavailable_without_keyring(monkeypatch):
    monkeypatch.setattr(bpc_secret_vault, "_load_keyring", lambda: None)

    result = bpc_secret_vault.status()

    assert result["available"] is False
    assert result["reason"] == "keyring_not_installed"


def test_store_and_delete_credentials(monkeypatch):
    fake = _FakeKeyring()
    monkeypatch.setattr(bpc_secret_vault, "_load_keyring", lambda: fake)

    stored = bpc_secret_vault.store_credentials("pair-1", {"rawSecret": "redacted"})
    assert stored["stored"] is True
    assert bpc_secret_vault.has_credentials("pair-1") is True

    deleted = bpc_secret_vault.delete_credentials("pair-1")
    assert deleted["deleted"] is True
    assert bpc_secret_vault.has_credentials("pair-1") is False
