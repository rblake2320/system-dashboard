"""Tests for Normal / Enterprise / Government profile behavior."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import core.config as cfg
from core import governance_profile
from core import bpc_monitor


def setup_function():
    cfg._cache = None
    bpc_monitor._cache = {}
    bpc_monitor._cache_ts = 0.0


def test_unknown_profile_normalizes_to_normal():
    assert governance_profile.normalize_profile("surprise") == "normal"


def test_normal_profile_hides_governance(monkeypatch):
    monkeypatch.setattr(cfg, "_cache", {"governance": {"profile": "normal"}})

    result = bpc_monitor.get_governance(force=True)

    assert result["profile"] == "normal"
    assert result["enabled"] is False
    assert result["bpc"]["hidden"] is True
    assert result["tsk"]["anomaly"]["hidden"] is True


def test_enterprise_profile_enables_bpc_tsk(monkeypatch):
    monkeypatch.setattr(cfg, "_cache", {"governance": {"profile": "enterprise"}})
    summary = governance_profile.summary()

    assert summary["enabled"] is True
    assert summary["government"] is False
    assert summary["visible_panels"]["bpc_tsk"] is True


def test_government_profile_enables_government_gates(monkeypatch):
    monkeypatch.setattr(cfg, "_cache", {"governance": {"profile": "government"}})
    summary = governance_profile.summary()

    assert summary["enabled"] is True
    assert summary["government"] is True
    assert summary["visible_panels"]["government_gates"] is True
