"""Route-level tests for dashboard governance controls."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import dashboard
import core.config as cfg
from core import bpc_audit_chain
from core import bpc_ownership


def setup_function():
    cfg._cache = None


def test_bpc_generate_blocked_in_normal_profile(monkeypatch):
    monkeypatch.setattr(cfg, "_cache", {"governance": {"profile": "normal"}})

    response = dashboard.app.test_client().post("/api/bpc/generate", json={"name": "x"})

    assert response.status_code == 403
    assert response.get_json()["profile"] == "normal"


def test_bpc_generate_records_owner_and_vault_metadata(monkeypatch, tmp_path):
    monkeypatch.setattr(
        cfg,
        "_cache",
        {"governance": {"profile": "enterprise", "bpc_url": "http://bpc.local"}},
    )
    monkeypatch.setattr(bpc_ownership, "_DB_PATH", tmp_path / "owners.db")
    monkeypatch.setattr(bpc_audit_chain, "_chain_path", tmp_path / "audit.ndjson")
    monkeypatch.setattr(
        dashboard,
        "generate_bpc_pair",
        lambda _url, name, scope, mode: {
            "pairId": "pair-1",
            "status": "active",
            "privJwk": {"kty": "EC"},
            "pubJwk": {"kty": "EC"},
            "rawSecret": "redacted",
            "name": name,
            "scope": scope,
            "mode": mode,
        },
    )
    monkeypatch.setattr(
        dashboard._bpc_vault,
        "store_credentials",
        lambda pair_id, credentials: {"stored": True, "pair_id": pair_id},
    )

    response = dashboard.app.test_client().post(
        "/api/bpc/generate",
        json={
            "name": "agent-pair",
            "role": "codex-1",
            "machine": "workstation",
            "birth_id": "b-1",
            "store_in_vault": True,
        },
    )

    body = response.get_json()
    assert response.status_code == 200
    assert body["owner"]["role"] == "codex-1"
    assert body["owner"]["profile"] == "enterprise"
    assert body["vault"]["stored"] is True
