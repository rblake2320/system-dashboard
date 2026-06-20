"""Tests for core.collector."""
from __future__ import annotations

import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import collector


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

def test_get_port_status_returns_dict():
    result = collector.get_port_status()
    assert isinstance(result, dict)


def test_get_port_status_int_keys():
    result = collector.get_port_status()
    for key in result:
        assert isinstance(key, int), f"Key {key!r} is not int"


def test_get_port_status_up_key():
    result = collector.get_port_status()
    for port, data in result.items():
        assert "up" in data, f"Port {port} missing 'up' key"
        assert isinstance(data["up"], bool)


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
