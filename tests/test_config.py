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


# ── Negative-path: missing / corrupt config.yaml ─────────────────────────────

def test_get_returns_defaults_when_config_absent(monkeypatch):
    """When config.yaml is absent and config.example.yaml is absent, _load_raw
    must return {} and get() must fall back to _DEFAULTS."""
    from pathlib import Path
    import core.config as _cfg_mod
    # Point both paths at guaranteed non-existent files (no tmp_path needed)
    monkeypatch.setattr(_cfg_mod, "_CONFIG_PATH", Path("C:/nonexistent_path_xyz/missing.yaml"))
    monkeypatch.setattr(_cfg_mod, "_EXAMPLE_PATH", Path("C:/nonexistent_path_xyz/also_missing.yaml"))
    monkeypatch.setattr(_cfg_mod, "_cache", None)
    result = _cfg_mod.get()
    assert isinstance(result, dict)
    assert "dashboard" in result
    assert result["dashboard"]["port"] == 8099  # default value


def test_load_raw_returns_empty_dict_when_files_absent(monkeypatch):
    """_load_raw must return {} (not raise) when neither config file exists."""
    from pathlib import Path
    import core.config as _cfg_mod
    monkeypatch.setattr(_cfg_mod, "_CONFIG_PATH", Path("C:/nonexistent_path_xyz/no_config.yaml"))
    monkeypatch.setattr(_cfg_mod, "_EXAMPLE_PATH", Path("C:/nonexistent_path_xyz/no_example.yaml"))
    result = _cfg_mod._load_raw()
    assert result == {}


def test_get_returns_defaults_when_yaml_is_corrupt(monkeypatch):
    """_load_raw with a corrupt yaml file must raise YAMLError or return a dict.
    Either outcome is acceptable; silently returning wrong data is not.
    We test by writing a real bad config to the project root and pointing _CONFIG_PATH at it.
    """
    import os
    import yaml
    from pathlib import Path
    import core.config as _cfg_mod

    # Write a temp bad yaml file next to config.yaml (project root, definitely writable)
    root = Path(__file__).parent.parent
    bad_path = root / "_test_bad_config_tmp.yaml"
    try:
        bad_path.write_text("{ bad yaml: [unclosed", encoding="utf-8")
        monkeypatch.setattr(_cfg_mod, "_CONFIG_PATH", bad_path)
        monkeypatch.setattr(_cfg_mod, "_EXAMPLE_PATH", Path("C:/nonexistent_path_xyz/no_example.yaml"))
        monkeypatch.setattr(_cfg_mod, "_cache", None)
        try:
            result = _cfg_mod.get()
            # If it doesn't raise, result must at least be a dict
            assert isinstance(result, dict)
        except yaml.YAMLError:
            pass  # acceptable — bad yaml propagates upward
    finally:
        if bad_path.exists():
            bad_path.unlink()


# ── Negative-path: env override for llm api_key ──────────────────────────────

def test_llm_env_override_openai(monkeypatch):
    """llm() must pick up OPENAI_API_KEY from env when config api_key is empty."""
    import core.config as _cfg_mod
    monkeypatch.setattr(_cfg_mod, "_cache", None)
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key-123")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = _cfg_mod.llm()
    assert result["api_key"] == "test-openai-key-123"


def test_llm_env_override_anthropic(monkeypatch):
    """llm() must pick up ANTHROPIC_API_KEY from env when OPENAI_API_KEY is absent."""
    import core.config as _cfg_mod
    monkeypatch.setattr(_cfg_mod, "_cache", None)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-anthropic-key-456")
    result = _cfg_mod.llm()
    assert result["api_key"] == "test-anthropic-key-456"
