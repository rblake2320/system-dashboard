"""Canonical snapshot contracts shared by Status, Review, and Export."""
from __future__ import annotations

import copy
import json

import dashboard
from core import system_snapshot
from daemon.monitor import daemon


def _base_snapshot() -> dict:
    return {
        "ts": "2026-07-25T10:00:00",
        "ts_display": "2026-07-25 10:00:00",
        "system": {
            "cpu_pct": 10,
            "ram_pct": 20,
            "ram_avail_gb": 100,
            "drives": {},
            "gpus": [],
        },
        "processes": {},
        "ports": {},
        "network": {},
        "net_health": {},
        "hooks": [],
        "projects": [],
        "smart_health": {},
        "history": {},
        "disk_io": {},
    }


def _patch_components(monkeypatch):
    monkeypatch.setattr(system_snapshot.collector, "build_snapshot", _base_snapshot)
    monkeypatch.setattr(daemon, "latest", _base_snapshot)
    monkeypatch.setattr(system_snapshot.fleet_registry, "get_fleet", lambda: [])
    monkeypatch.setattr(
        system_snapshot.fleet_guard,
        "get_guard_state",
        lambda: {"state": "ok", "reason": ""},
    )
    monkeypatch.setattr(
        system_snapshot,
        "get_governance",
        lambda force=False: {"enabled": False, "profile": "normal"},
    )
    monkeypatch.setattr(
        system_snapshot, "check_all_keys", lambda force=False: {"openai": {"found": False}}
    )
    monkeypatch.setattr(
        system_snapshot,
        "get_mesh_status",
        lambda force=False: {"mesh_healthy": True},
    )
    monkeypatch.setattr(
        system_snapshot,
        "get_memoryweb_status",
        lambda force=False: {"connected": True, "status": "healthy"},
    )
    system_snapshot.reset_cache()


def test_canonical_snapshot_has_required_evidence_sections(monkeypatch):
    _patch_components(monkeypatch)
    snapshot = system_snapshot.build_system_snapshot(
        freshness="fresh", reason="test"
    )

    assert not (system_snapshot.REQUIRED_SECTIONS - set(snapshot))
    assert snapshot["evidence_integrity"]["schema_valid"] is True
    assert snapshot["evidence_integrity"]["status"] == "complete"
    assert snapshot["fleet_guard"]["state"] == "ok"
    assert snapshot["schema_version"] == system_snapshot.SCHEMA_VERSION
    assert len(snapshot["evidence_hash"]) == 64


def test_component_failure_is_visible_not_omitted(monkeypatch):
    _patch_components(monkeypatch)

    def broken_mesh(force=False):
        raise RuntimeError("mesh probe failed")

    monkeypatch.setattr(system_snapshot, "get_mesh_status", broken_mesh)
    snapshot = system_snapshot.build_system_snapshot(
        freshness="fresh", reason="failure-test"
    )

    assert "mesh" in snapshot
    assert snapshot["mesh"] == {}
    assert snapshot["components"]["mesh"]["status"] == "unavailable"
    assert snapshot["evidence_integrity"]["status"] == "partial"
    assert snapshot["evidence_integrity"]["unavailable_components"] == ["mesh"]


def test_status_review_and_export_share_safety_state(monkeypatch):
    canonical = _base_snapshot()
    canonical.update({
        "snapshot_id": "snapshot-1",
        "generated_at": "2026-07-25T15:00:00+00:00",
        "schema_version": "1.0",
        "dashboard_version": "2.1.0",
        "app_commit": "abc123",
        "evidence_hash": "a" * 64,
        "evidence_integrity": {
            "status": "complete",
            "schema_valid": True,
            "missing_sections": [],
            "unavailable_components": [],
        },
        "issues": [],
        "issue_registry": [],
        "alert_history": [],
        "health_score": 100,
        "fleet": [],
        "fleet_guard": {"state": "hard_stop", "reason": "test"},
        "governance": {"enabled": False},
        "keys": {},
        "mesh": {},
        "memoryweb": {},
        "daemon": {"alive": True, "last_tick_ts": 1},
        "components": {},
        "daemon_alive": True,
        "last_tick_ts": 1,
    })
    monkeypatch.setattr(
        dashboard._snapshots,
        "build_system_snapshot",
        lambda **kwargs: copy.deepcopy(canonical),
    )
    monkeypatch.setattr(
        dashboard._snapshots,
        "latest_system_snapshot",
        lambda **kwargs: copy.deepcopy(canonical),
    )
    monkeypatch.setattr(
        dashboard._snapshots,
        "validate_snapshot",
        lambda snap: canonical["evidence_integrity"],
    )

    client = dashboard.app.test_client()
    status = client.get("/api/status").get_json()
    review = client.get("/api/review?with_ai=false").get_json()
    export_response = client.get("/api/export")
    exported = json.loads(export_response.data)

    assert export_response.status_code == 200
    assert status["snapshot_id"] == review["snapshot_id"] == exported["snapshot_id"]
    assert status["health_score"] == review["health_score"] == exported["health_score"]
    assert status["fleet_guard"] == exported["system"]["fleet_guard"]
