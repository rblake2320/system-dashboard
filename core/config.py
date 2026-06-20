"""Config loader — reads config.yaml, falls back to safe defaults."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

_ROOT = Path(__file__).resolve().parent.parent
_CONFIG_PATH = _ROOT / "config.yaml"
_EXAMPLE_PATH = _ROOT / "config.example.yaml"

_DEFAULTS: dict[str, Any] = {
    "dashboard": {"port": 8099, "host": "127.0.0.1", "refresh_interval_seconds": 10},
    "daemon": {"enabled": True, "interval_seconds": 30},
    "llm": {
        "provider": "ollama",
        "model": "gemma3:latest",
        "host": "http://localhost:11434",
        "api_key": "",
        "timeout_seconds": 60,
    },
    "processes": {"tracked": []},
    "services": {"ports": {}},
    "storage": {"drives": ["C", "D"], "warn_free_gb_below": 10.0, "failing_drives": []},
    "projects": [],
    "known_ips": {},
}


def _deep_merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def _load_raw() -> dict:
    path = _CONFIG_PATH if _CONFIG_PATH.exists() else _EXAMPLE_PATH
    if not path.exists() or not _HAS_YAML:
        return {}
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


_cache: dict | None = None


def get() -> dict:
    global _cache
    if _cache is None:
        _cache = _deep_merge(_DEFAULTS, _load_raw())
    return _cache


def reload() -> dict:
    global _cache
    _cache = None
    return get()


# ── Typed accessors ────────────────────────────────────────────────────────────

def dashboard() -> dict:
    return get()["dashboard"]

def daemon() -> dict:
    return get()["daemon"]

def llm() -> dict:
    cfg = get()["llm"]
    # env override for api_key
    cfg["api_key"] = cfg.get("api_key") or os.environ.get("OPENAI_API_KEY", "") or os.environ.get("ANTHROPIC_API_KEY", "")
    return cfg

def processes() -> list[dict]:
    return get()["processes"].get("tracked", [])

def ports() -> dict[int, str]:
    raw = get()["services"].get("ports", {})
    return {int(k): str(v) for k, v in raw.items()}

def storage() -> dict:
    return get()["storage"]

def projects() -> list[dict]:
    raw = get().get("projects", [])
    result = []
    for p in raw:
        path_str = str(p.get("path", "")).replace("~", str(Path.home()))
        result.append({"name": p.get("name", path_str), "path": Path(path_str)})
    return result

def known_ips() -> dict[str, str]:
    return get().get("known_ips", {})
