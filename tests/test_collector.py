"""Tests for core.collector."""
from __future__ import annotations

import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import collector
import core.config as cfg


# ── get_system_metrics ────────────────────────────────────────────────────────

def test_get_system_metrics_keys():
    metrics = collector.get_system_metrics()
    for key in ("cpu_pct", "ram_pct", "drives", "gpus"):
        assert key in metrics, f"Missing key: {key}"


def test_get_system_metrics_types():
    metrics = collector.get_system_metrics()
    assert isinstance(metrics["cpu_pct"], (int, float))
    assert isinstance(metrics["ram_pct"], (int, float))
    assert isinstance(metrics["drives"], dict)
    assert isinstance(metrics["gpus"], list)


def test_get_system_metrics_cpu_range():
    metrics = collector.get_system_metrics()
    assert 0 <= metrics["cpu_pct"] <= 100


def test_get_system_metrics_ram_range():
    metrics = collector.get_system_metrics()
    assert 0 <= metrics["ram_pct"] <= 100


# ── get_processes ─────────────────────────────────────────────────────────────

def test_get_processes_returns_dict():
    procs = collector.get_processes()
    assert isinstance(procs, dict)


def test_get_processes_structure():
    """Each entry must have the expected keys."""
    procs = collector.get_processes()
    for name, data in procs.items():
        assert "label" in data, f"{name} missing 'label'"
        assert "count" in data, f"{name} missing 'count'"
        assert "total_mb" in data, f"{name} missing 'total_mb'"
        assert "procs" in data, f"{name} missing 'procs'"
        assert isinstance(data["count"], int)
        assert isinstance(data["procs"], list)


# ── get_port_status ───────────────────────────────────────────────────────────
# These tests use mocks so they are environment-independent (no live services needed).

def test_get_port_status_returns_dict():
    """get_port_status() returns a dict (live call — may be empty on CI)."""
    result = collector.get_port_status()
    assert isinstance(result, dict)


def test_get_port_status_int_keys():
    """All keys returned by get_port_status() must be integers."""
    result = collector.get_port_status()
    for key in result:
        assert isinstance(key, int), f"Key {key!r} is not int"


def test_get_port_status_up_key():
    """Each port entry must contain an 'up' bool key."""
    result = collector.get_port_status()
    for port, data in result.items():
        assert "up" in data, f"Port {port} missing 'up' key"
        assert isinstance(data["up"], bool)


def test_get_port_status_mocked_up_port():
    """Mock psutil.net_connections to report port 9999 as LISTEN: should be up=True."""
    fake_ports = {9999: "Test Service"}
    # Build a fake connection namedtuple-like object
    FakeAddr = MagicMock()
    FakeAddr.port = 9999
    fake_conn = MagicMock()
    fake_conn.status = "LISTEN"
    fake_conn.laddr = FakeAddr
    fake_conn.pid = 1234

    with patch.object(cfg, "ports", return_value=fake_ports), \
         patch("psutil.net_connections", return_value=[fake_conn]), \
         patch("psutil.Process") as mock_proc:
        mock_proc.return_value.name.return_value = "test.exe"
        result = collector.get_port_status()

    assert 9999 in result, "Port 9999 should be in result"
    assert result[9999]["up"] is True


def test_get_port_status_mocked_down_port():
    """Mock psutil.net_connections to return no listeners: port should be up=False."""
    fake_ports = {9998: "Offline Service"}

    with patch.object(cfg, "ports", return_value=fake_ports), \
         patch("psutil.net_connections", return_value=[]):
        result = collector.get_port_status()

    assert 9998 in result, "Port 9998 should be in result"
    assert result[9998]["up"] is False


# ── build_snapshot ────────────────────────────────────────────────────────────

def test_build_snapshot_completes_in_time():
    start = time.time()
    snapshot = collector.build_snapshot()
    elapsed = time.time() - start
    # Allow up to 10s: disk enumeration (especially D:) can be slow on Windows
    assert elapsed < 10.0, f"build_snapshot() took {elapsed:.2f}s (limit: 10s)"
    assert isinstance(snapshot, dict)


def test_build_snapshot_top_level_keys():
    snapshot = collector.build_snapshot()
    for key in ("ts", "system", "processes", "ports"):
        assert key in snapshot, f"Missing snapshot key: {key}"


def test_build_snapshot_ports_are_string_keys():
    """build_snapshot() serializes port keys as strings (JSON-safe).
    Callers must not rely on int keys in the snapshot dict; use cfg.ports() for int keys.
    """
    snapshot = collector.build_snapshot()
    for key in snapshot.get("ports", {}):
        assert isinstance(key, str), (
            f"build_snapshot() port key {key!r} is not a str. "
            "get_port_status() returns int keys but build_snapshot() converts them to str."
        )


# ── Drive edge case: total_gb == 0 ────────────────────────────────────────────

def test_drive_with_zero_total_gb_is_handled():
    """A drive entry with total_gb=0 must not raise and must not trigger issues."""
    from core.issues import detect_issues

    snapshot = {
        "system": {
            "cpu_pct": 0,
            "ram_pct": 0,
            "ram_avail_gb": 100,
            "drives": {
                "Z": {
                    "total_gb": 0,
                    "used_gb": 0,
                    "free_gb": 0,
                    "pct": 0,
                    "failing": False,
                    "warn": False,
                }
            },
            "gpus": [],
        },
        "processes": {},
        "ports": {},
    }

    # Must not raise
    issues = detect_issues(snapshot)
    # Drive Z with total_gb=0 → skipped → no storage issues
    storage_issues = [i for i in issues if i.category == "storage"]
    assert storage_issues == [], "Drive with total_gb=0 should produce no storage issues"
