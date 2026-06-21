"""Tests for BPC/TSK governance path resolution."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import dashboard
from core import bpc_monitor
import core.config as cfg


def setup_function():
    cfg._cache = None


def test_governance_repo_path_prefers_configured_path(monkeypatch, tmp_path):
    configured = tmp_path / "configured" / "bpc-protocol" / "demo"
    configured.mkdir(parents=True)
    sibling = tmp_path / "bpc-protocol" / "demo"
    sibling.mkdir(parents=True)
    monkeypatch.setattr(dashboard, "_ROOT", tmp_path / "system-dashboard")
    monkeypatch.setattr(
        cfg,
        "_cache",
        {"governance": {"bpc_root": str(configured)}},
    )

    result = dashboard._governance_repo_path("bpc_root", "bpc-protocol", "demo")

    assert result == configured


def test_governance_repo_path_falls_back_to_sibling_checkout(monkeypatch, tmp_path):
    sibling = tmp_path / "bpc-protocol" / "demo"
    sibling.mkdir(parents=True)
    monkeypatch.setattr(dashboard, "_ROOT", tmp_path / "system-dashboard")
    monkeypatch.setattr(cfg, "_cache", {"governance": {}})

    result = dashboard._governance_repo_path("bpc_root", "bpc-protocol", "demo")

    assert result == sibling


def test_tsk_ndjson_prefers_configured_file(tmp_path):
    ndjson = tmp_path / "analytics.ndjson"
    ndjson.write_text("", encoding="utf-8")

    result = bpc_monitor._resolve_default_tsk_ndjson({"tsk_ndjson": str(ndjson)})

    assert result == str(ndjson)


def test_tsk_ndjson_uses_configured_tsk_root(tmp_path):
    ndjson = tmp_path / "tsk-protocol" / "demo" / "analytics.ndjson"
    ndjson.parent.mkdir(parents=True)
    ndjson.write_text("", encoding="utf-8")

    result = bpc_monitor._resolve_default_tsk_ndjson(
        {"tsk_root": str(tmp_path / "tsk-protocol")}
    )

    assert result == str(ndjson)
