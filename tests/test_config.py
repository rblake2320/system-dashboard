"""Tests for core.config."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# Force a fresh cache before each test by patching _cache
import core.config as cfg


def setup_function():
    """Reset the config cache before each test so tests are isolated."""
    cfg._cache = None


# ── dashboard() ──────────────────────────────────────────────────────────────

def test_dashboard_returns_dict():
    d = cfg.dashboard()
    assert isinstance(d, dict)


def test_dashboard_has_port_key():
    d = cfg.dashboard()
    assert "port" in d, f"Expected 'port' key in dashboard config, got keys: {list(d.keys())}"


def test_dashboard_port_is_int():
    d = cfg.dashboard()
    assert isinstance(d["port"], int)


def test_dashboard_has_host():
    d = cfg.dashboard()
    assert "host" in d


# ── processes() ──────────────────────────────────────────────────────────────

def test_processes_returns_list():
    procs = cfg.processes()
    assert isinstance(procs, list)


def test_processes_items_are_dicts():
    procs = cfg.processes()
    for item in procs:
        assert isinstance(item, dict), f"Process entry is not a dict: {item!r}"


# ── ports() ──────────────────────────────────────────────────────────────────

def test_ports_returns_dict():
    ports = cfg.ports()
    assert isinstance(ports, dict)


def test_ports_keys_are_ints():
    ports = cfg.ports()
    for key in ports:
        assert isinstance(key, int), f"Port key {key!r} is not int"


# ── storage() ────────────────────────────────────────────────────────────────

def test_storage_returns_dict():
    stor = cfg.storage()
    assert isinstance(stor, dict)


def test_storage_has_drives():
    stor = cfg.storage()
    assert "drives" in stor


# ── _deep_merge ───────────────────────────────────────────────────────────────

def test_deep_merge_override_replaces_scalar():
    base = {"a": 1, "b": 2}
    override = {"b": 99}
    result = cfg._deep_merge(base, override)
    assert result["b"] == 99
    assert result["a"] == 1


def test_deep_merge_nested_keys_merge():
    base = {"dashboard": {"port": 8099, "host": "127.0.0.1"}}
    override = {"dashboard": {"port": 9000}}
    result = cfg._deep_merge(base, override)
    # Overridden key changed
    assert result["dashboard"]["port"] == 9000
    # Non-overridden nested key preserved
    assert result["dashboard"]["host"] == "127.0.0.1"


def test_deep_merge_does_not_mutate_base():
    base = {"x": {"y": 1}}
    override = {"x": {"z": 2}}
    cfg._deep_merge(base, override)
    # base must be unchanged
    assert "z" not in base["x"]


def test_deep_merge_adds_new_key():
    base = {"a": 1}
    override = {"b": 2}
    result = cfg._deep_merge(base, override)
    assert result["a"] == 1
    assert result["b"] == 2


def test_deep_merge_override_replaces_base_value_not_dict():
    """If base has a dict but override provides a scalar, scalar wins."""
    base = {"key": {"nested": 1}}
    override = {"key": "flat_value"}
    result = cfg._deep_merge(base, override)
    assert result["key"] == "flat_value"


# ── get() / reload() ─────────────────────────────────────────────────────────

def test_get_returns_dict():
    result = cfg.get()
    assert isinstance(result, dict)


def test_get_caches_result():
    first = cfg.get()
    second = cfg.get()
    assert first is second, "cfg.get() should return cached object on second call"


def test_reload_clears_cache():
    first = cfg.get()
    reloaded = cfg.reload()
    assert isinstance(reloaded, dict)
    # After reload, a fresh get() must produce the same structure
    assert "dashboard" in reloaded
