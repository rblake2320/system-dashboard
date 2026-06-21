"""Tests for local BPC pair ownership metadata."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import bpc_ownership


def test_record_and_get_owner(monkeypatch, tmp_path):
    monkeypatch.setattr(bpc_ownership, "_DB_PATH", tmp_path / "owners.db")

    owner = bpc_ownership.record_owner(
        "pair-1",
        name="dashboard-pair",
        role="codex-1",
        machine="workstation",
        profile="enterprise",
        birth_id="b-123",
    )

    assert owner["pair_id"] == "pair-1"
    assert bpc_ownership.get_owner("pair-1")["role"] == "codex-1"


def test_annotate_pairs_adds_owner(monkeypatch, tmp_path):
    monkeypatch.setattr(bpc_ownership, "_DB_PATH", tmp_path / "owners.db")
    bpc_ownership.record_owner("pair-1", role="role-a", profile="government")

    pairs = bpc_ownership.annotate_pairs([
        {"id": "pair-1", "status": "active"},
        {"id": "pair-2", "status": "active"},
    ])

    assert pairs[0]["owner"]["role"] == "role-a"
    assert "owner" not in pairs[1]
