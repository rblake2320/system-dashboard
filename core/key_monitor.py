"""API key health monitor — validates keys, fetches cost data, masks display."""
from __future__ import annotations

import os
import time
import threading
import urllib.request
import urllib.error
import json
from typing import Any

# ── Provider definitions ───────────────────────────────────────────────────────

_PROVIDERS: dict[str, dict] = {
    "anthropic": {
        "label": "Anthropic (Claude)",
        "env_vars": ["ANTHROPIC_API_KEY"],
        "admin_env_vars": ["ANTHROPIC_ADMIN_KEY"],
        "validate_url": "https://api.anthropic.com/v1/models",
        "validate_method": "header",       # key in x-api-key header
        "validate_headers": {"anthropic-version": "2023-06-01"},
        "cost_url": "https://api.anthropic.com/v1/organizations/cost_report",
        "cost_header": "x-api-key",        # admin key goes here
        "cost_available": True,
        "rotate_url": "https://console.anthropic.com/settings/keys",
        "icon": "A",
    },
    "openai": {
        "label": "OpenAI (GPT)",
        "env_vars": ["OPENAI_API_KEY"],
        "admin_env_vars": ["OPENAI_ADMIN_KEY"],
        "validate_url": "https://api.openai.com/v1/models",
        "validate_method": "bearer",
        "cost_url": "https://api.openai.com/v1/organization/costs",
        "cost_header": "Authorization",    # "Bearer <admin_key>"
        "cost_bearer": True,
        "cost_available": True,
        "rotate_url": "https://platform.openai.com/api-keys",
        "icon": "O",
    },
    "gemini": {
        "label": "Google Gemini",
        "env_vars": ["GOOGLE_API_KEY", "GEMINI_API_KEY"],
        "validate_url": "https://generativelanguage.googleapis.com/v1beta/models",
        "validate_method": "query",        # key as ?key= param
        "cost_available": False,
        "rotate_url": "https://aistudio.google.com/app/apikey",
        "icon": "G",
    },
    "groq": {
        "label": "Groq",
        "env_vars": ["GROQ_API_KEY"],
        "validate_url": "https://api.groq.com/openai/v1/models",
        "validate_method": "bearer",
        "cost_available": False,
        "rotate_url": "https://console.groq.com/keys",
        "icon": "Q",
    },
    "ollama": {
        "label": "Ollama (local)",
        "env_vars": [],                    # no key — just health check
        "validate_url": "http://localhost:11434/",
        "validate_method": "none",
        "cost_available": False,
        "rotate_url": None,
        "local": True,
        "icon": "L",
    },
}

_CACHE_TTL = 300  # 5 minutes — don't hammer provider APIs on every page load
_TIMEOUT = 6      # seconds per request


def _mask(key: str) -> str:
    """Return a masked version showing only the last 4 characters."""
    if not key or len(key) < 8:
        return "****"
    return key[:7] + "..." + key[-4:]


def _find_key(env_vars: list[str]) -> str | None:
    """Return first non-empty env var value found."""
    for var in env_vars:
        val = os.environ.get(var, "").strip()
        if val:
            return val
    return None


def _http_get(url: str, headers: dict[str, str], timeout: int = _TIMEOUT) -> tuple[int, dict | str]:
    """Return (status_code, body_dict_or_str)."""
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode(errors="replace")
            try:
                return resp.status, json.loads(body)
            except json.JSONDecodeError:
                return resp.status, body
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode(errors="replace")
        except Exception:
            body = str(e)
        return e.code, body
    except Exception as e:
        return 0, str(e)


def _validate_key(provider_id: str, pdef: dict, key: str) -> dict:
    """Ping the provider's cheapest endpoint and return status info."""
    url = pdef["validate_url"]
    method = pdef.get("validate_method", "bearer")
    extra_headers = pdef.get("validate_headers", {})

    headers = dict(extra_headers)
    if method == "bearer":
        headers["Authorization"] = f"Bearer {key}"
        status, body = _http_get(url, headers)
    elif method == "header":
        headers["x-api-key"] = key
        status, body = _http_get(url, headers)
    elif method == "query":
        url = f"{url}?key={key}"
        status, body = _http_get(url, headers)
    elif method == "none":
        status, body = _http_get(url, headers)
    else:
        return {"status": "unknown", "error": f"Unknown method: {method}"}

    if status == 200:
        # Count available models if body is a dict with data/models
        model_count = 0
        if isinstance(body, dict):
            model_count = len(body.get("data", body.get("models", [])))
        return {"status": "active", "http": status, "models": model_count}
    elif status == 401:
        return {"status": "invalid", "http": status, "error": "Unauthorized — key rejected"}
    elif status == 429:
        return {"status": "rate_limited", "http": status, "error": "Rate limited (key is valid)"}
    elif status == 0:
        return {"status": "unreachable", "http": 0, "error": str(body)[:80]}
    else:
        return {"status": "error", "http": status, "error": str(body)[:80]}


def _fetch_cost(provider_id: str, pdef: dict, admin_key: str) -> dict | None:
    """Fetch this month's cost via admin key. Returns dict or None."""
    cost_url = pdef.get("cost_url")
    if not cost_url or not admin_key:
        return None

    # Build date range: first of this month → today
    import datetime
    today = datetime.date.today()
    start = today.replace(day=1).isoformat()
    end = today.isoformat()

    headers: dict[str, str] = {}
    if pdef.get("cost_bearer"):
        headers["Authorization"] = f"Bearer {admin_key}"
    else:
        key_header = pdef.get("cost_header", "x-api-key")
        headers[key_header] = admin_key

    url = f"{cost_url}?starting_at={start}&ending_at={end}"
    if provider_id == "anthropic":
        headers["anthropic-version"] = "2023-06-01"

    status, body = _http_get(url, headers, timeout=8)
    if status != 200 or not isinstance(body, dict):
        return {"error": f"HTTP {status}", "raw": str(body)[:120]}

    # Anthropic: body has "data" list with cost_usd per bucket
    if provider_id == "anthropic":
        data = body.get("data", [])
        total = sum(
            float(item.get("cost_usd", item.get("total_cost", 0)) or 0)
            for item in data
        )
        return {"usd": round(total, 4), "buckets": len(data)}

    # OpenAI: body has "data" list with "amount" dicts
    if provider_id == "openai":
        data = body.get("data", [])
        total = 0.0
        for item in data:
            amt = item.get("amount", {})
            if isinstance(amt, dict):
                total += float(amt.get("value", 0) or 0)
            elif isinstance(amt, (int, float)):
                total += float(amt)
        return {"usd": round(total, 4), "buckets": len(data)}

    return {"raw": str(body)[:200]}


# ── Cache ─────────────────────────────────────────────────────────────────────

class _KeyCache:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._data: dict[str, dict] = {}
        self._ts: float = 0.0

    def expired(self) -> bool:
        return time.time() - self._ts > _CACHE_TTL

    def set(self, data: dict[str, dict]) -> None:
        with self._lock:
            self._data = data
            self._ts = time.time()

    def get(self) -> tuple[dict[str, dict], float]:
        with self._lock:
            return dict(self._data), self._ts


_cache = _KeyCache()


# ── Public API ────────────────────────────────────────────────────────────────

def check_all_keys(force: bool = False) -> dict[str, dict]:
    """Return status dict for all configured providers. Uses cache unless force=True."""
    if not force and not _cache.expired():
        data, _ = _cache.get()
        return data

    results: dict[str, dict] = {}
    for pid, pdef in _PROVIDERS.items():
        is_local = pdef.get("local", False)
        key = _find_key(pdef.get("env_vars", []))
        admin_key = _find_key(pdef.get("admin_env_vars", []))

        entry: dict[str, Any] = {
            "label": pdef["label"],
            "icon": pdef.get("icon", "?"),
            "masked": _mask(key) if key else None,
            "found": bool(key) or is_local,
            "rotate_url": pdef.get("rotate_url"),
            "cost_available": pdef.get("cost_available", False),
            "has_admin_key": bool(admin_key),
            "checked_at": time.strftime("%H:%M:%S"),
            "validation": None,
            "cost": None,
        }

        if is_local:
            entry["validation"] = _validate_key(pid, pdef, "")
        elif key:
            entry["validation"] = _validate_key(pid, pdef, key)
            if pdef.get("cost_available") and admin_key:
                entry["cost"] = _fetch_cost(pid, pdef, admin_key)
        else:
            entry["validation"] = {"status": "not_configured", "error": f"Set {', '.join(pdef.get('env_vars', []))}"}

        results[pid] = entry

    _cache.set(results)
    return results


def refresh_provider(provider_id: str) -> dict | None:
    """Force-refresh a single provider and update cache."""
    pdef = _PROVIDERS.get(provider_id)
    if not pdef:
        return None
    current, _ = _cache.get()
    # Temporarily set expired to force rebuild on next call,
    # but run just this one provider immediately.
    is_local = pdef.get("local", False)
    key = _find_key(pdef.get("env_vars", []))
    admin_key = _find_key(pdef.get("admin_env_vars", []))
    entry: dict[str, Any] = {
        "label": pdef["label"],
        "icon": pdef.get("icon", "?"),
        "masked": _mask(key) if key else None,
        "found": bool(key) or is_local,
        "rotate_url": pdef.get("rotate_url"),
        "cost_available": pdef.get("cost_available", False),
        "has_admin_key": bool(admin_key),
        "checked_at": time.strftime("%H:%M:%S"),
        "validation": None,
        "cost": None,
    }
    if is_local:
        entry["validation"] = _validate_key(provider_id, pdef, "")
    elif key:
        entry["validation"] = _validate_key(provider_id, pdef, key)
        if pdef.get("cost_available") and admin_key:
            entry["cost"] = _fetch_cost(provider_id, pdef, admin_key)
    else:
        entry["validation"] = {"status": "not_configured", "error": f"Set {', '.join(pdef.get('env_vars', []))}"}

    current[provider_id] = entry
    _cache.set(current)
    return entry
