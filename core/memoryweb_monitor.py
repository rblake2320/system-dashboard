"""MemoryWeb health monitor — polls the MemoryWeb API for status metrics."""
from __future__ import annotations

import json
import time
import urllib.request
import urllib.error

_TIMEOUT = 5
_CACHE_TTL = 60  # refresh every minute

_cache: dict = {}
_cache_ts: float = 0.0


def _get(url: str) -> tuple[int, dict | None]:
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            body = resp.read().decode(errors="replace")
            return resp.status, json.loads(body)
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception:
        return 0, None


def get_status(force: bool = False) -> dict:
    global _cache, _cache_ts

    if not force and _cache and (time.time() - _cache_ts) < _CACHE_TTL:
        return _cache

    from core import config as cfg
    raw = cfg.get()
    mw_cfg = raw.get("memoryweb", {})
    url = mw_cfg.get("url", "http://localhost:8100")

    result: dict = {
        "url": url,
        "connected": False,
        "status": "unknown",
        "memory_count": None,
        "embedding_coverage_pct": None,
        "last_ingestion": None,
        "search_latency_ms": None,
        "checked_at": time.strftime("%H:%M:%S"),
    }

    # Health check with latency measurement
    t0 = time.time()
    code, body = _get(f"{url}/api/health")
    latency_ms = round((time.time() - t0) * 1000)

    if code == 200 and body:
        result["connected"] = True
        result["status"] = body.get("status", "healthy")
        result["search_latency_ms"] = latency_ms

        # Enrich from /api/stats if available
        _, stats = _get(f"{url}/api/stats")
        if stats:
            result["memory_count"] = stats.get("total", stats.get("count"))
            result["embedding_coverage_pct"] = stats.get(
                "embedding_coverage_pct", stats.get("embedded_pct")
            )
            result["last_ingestion"] = stats.get("last_ingestion") or stats.get(
                "last_updated"
            )
        else:
            # Fallback: count from health body
            result["memory_count"] = body.get("memories") or body.get("count")
    elif code == 0:
        result["status"] = "unreachable"
    else:
        result["status"] = f"http_{code}"

    _cache = result
    _cache_ts = time.time()
    return result
