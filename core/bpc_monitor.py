"""BPC/TSK governance event monitor.

Reads BPC audit events (PostgreSQL bpc_audit table) and TSK anomaly state
(GET /tsk/anomaly endpoint + analytics.ndjson file).

All sources are optional — each falls back gracefully to "not connected."
Configure via config.yaml under the `governance:` key.
"""
from __future__ import annotations

import json
import time
import urllib.request
import urllib.error
from pathlib import Path

_TIMEOUT = 5
_CACHE_TTL = 30   # governance events refresh every 30 seconds
_MAX_EVENTS = 20  # events to return per source

_cache: dict = {}
_cache_ts: float = 0.0


# ── BPC ───────────────────────────────────────────────────────────────────────

def _fetch_bpc_events(pg_dsn: str) -> dict:
    """Query the bpc_audit PostgreSQL table. Returns dict with events list."""
    try:
        import psycopg2  # type: ignore
        import psycopg2.extras  # type: ignore
    except ImportError:
        return {"connected": False, "error": "psycopg2 not installed (pip install psycopg2-binary)", "events": []}

    try:
        conn = psycopg2.connect(pg_dsn, connect_timeout=4)
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(
            """
            SELECT seq, timestamp, action, severity, pair_id, error,
                   ip, method, path, chain_hash
            FROM bpc_audit
            ORDER BY seq DESC
            LIMIT %s
            """,
            (_MAX_EVENTS,),
        )
        rows = [dict(r) for r in cur.fetchall()]
        # chain head for integrity display
        cur.execute("SELECT seq, chain_hash FROM bpc_audit ORDER BY seq DESC LIMIT 1")
        head = cur.fetchone()
        cur.close()
        conn.close()
        return {
            "connected": True,
            "events": rows,
            "chain_head_seq": head["seq"] if head else None,
            "chain_head_hash": (head["chain_hash"] or "")[:16] + "…" if head else None,
        }
    except Exception as exc:
        return {"connected": False, "error": str(exc)[:120], "events": []}


# ── TSK ───────────────────────────────────────────────────────────────────────

def _fetch_tsk_anomaly(tsk_url: str) -> dict:
    """Poll GET /tsk/anomaly for current anomaly engine state."""
    try:
        req = urllib.request.Request(f"{tsk_url}/tsk/anomaly")
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            body = json.loads(resp.read().decode(errors="replace"))
        return {"connected": True, **body}
    except urllib.error.HTTPError as e:
        return {"connected": False, "error": f"HTTP {e.code}"}
    except Exception as exc:
        return {"connected": False, "error": str(exc)[:80]}


def _parse_tsk_ndjson(ndjson_path: str) -> list[dict]:
    """Read the last _MAX_EVENTS lines from TSK analytics.ndjson."""
    p = Path(ndjson_path)
    if not p.exists():
        return []
    try:
        size = p.stat().st_size
        with open(p, "rb") as fh:
            fh.seek(max(0, size - 40_000))
            tail = fh.read().decode("utf-8", errors="replace")
        events = []
        for line in tail.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return events[-_MAX_EVENTS:]
    except Exception:
        return []


# ── Combined ──────────────────────────────────────────────────────────────────

def get_governance(force: bool = False) -> dict:
    """Return merged governance state from BPC + TSK. Uses 30 s cache."""
    global _cache, _cache_ts

    if not force and _cache and (time.time() - _cache_ts) < _CACHE_TTL:
        return _cache

    from core import config as cfg
    gov_cfg = cfg.get().get("governance", {})

    # BPC
    bpc_dsn = gov_cfg.get("bpc_pg_dsn", "")
    bpc = _fetch_bpc_events(bpc_dsn) if bpc_dsn else {
        "connected": False,
        "error": "Set governance.bpc_pg_dsn in config.yaml",
        "events": [],
    }

    # Serialize timestamps for JSON
    for ev in bpc.get("events", []):
        if hasattr(ev.get("timestamp"), "isoformat"):
            ev["timestamp"] = ev["timestamp"].isoformat()

    # TSK anomaly
    tsk_url = gov_cfg.get("tsk_url", "http://localhost:3200")
    tsk_anomaly = _fetch_tsk_anomaly(tsk_url)

    # TSK NDJSON (analytics log)
    tsk_ndjson = gov_cfg.get(
        "tsk_ndjson",
        str(Path.home() / "tsk-protocol" / "demo" / "analytics.ndjson"),
    )
    tsk_events = _parse_tsk_ndjson(tsk_ndjson)

    result = {
        "checked_at": time.strftime("%H:%M:%S"),
        "bpc": bpc,
        "tsk": {
            "anomaly": tsk_anomaly,
            "recent_events": tsk_events,
        },
    }

    _cache = result
    _cache_ts = time.time()
    return result
