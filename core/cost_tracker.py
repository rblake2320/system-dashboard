"""Cost tracker — daily SQLite snapshots of MTD API costs per provider."""
from __future__ import annotations

import datetime
import sqlite3
import threading
import time
from pathlib import Path

from core.key_monitor import check_all_keys

_ROOT = Path(__file__).resolve().parent.parent
_DB_PATH = _ROOT / "data" / "dashboard.db"

_DDL = """
CREATE TABLE IF NOT EXISTS cost_snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    provider    TEXT    NOT NULL,
    date        TEXT    NOT NULL,
    cost_usd    REAL    NOT NULL DEFAULT 0.0,
    sampled_at  INTEGER NOT NULL,
    UNIQUE(provider, date)
);
CREATE INDEX IF NOT EXISTS idx_cs_provider_date ON cost_snapshots(provider, date DESC);
"""

_lock = threading.Lock()
_conn: sqlite3.Connection | None = None


def _get_conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        _conn = sqlite3.connect(
            str(_DB_PATH),
            check_same_thread=False,
            isolation_level=None,
        )
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA synchronous=NORMAL")
        for stmt in _DDL.strip().split(";"):
            s = stmt.strip()
            if s:
                _conn.execute(s)
    return _conn


def _upsert(provider: str, date: str, cost_usd: float) -> None:
    conn = _get_conn()
    now = int(time.time())
    with _lock:
        conn.execute(
            """
            INSERT INTO cost_snapshots (provider, date, cost_usd, sampled_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(provider, date) DO UPDATE SET
                cost_usd   = excluded.cost_usd,
                sampled_at = excluded.sampled_at
            """,
            (provider, date, cost_usd, now),
        )


def _read_history(days: int = 30) -> dict[str, list[dict]]:
    conn = _get_conn()
    cutoff = (datetime.date.today() - datetime.timedelta(days=days)).isoformat()
    with _lock:
        cur = conn.execute(
            """
            SELECT provider, date, cost_usd
            FROM cost_snapshots
            WHERE date >= ?
            ORDER BY provider, date ASC
            """,
            (cutoff,),
        )
        rows = [dict(r) for r in cur.fetchall()]

    result: dict[str, list[dict]] = {}
    for row in rows:
        pid = row["provider"]
        if pid not in result:
            result[pid] = []
        result[pid].append({"date": row["date"], "cost_usd": row["cost_usd"]})
    return result


def snapshot_costs() -> dict[str, list[dict]]:
    """Fetch current MTD costs, persist today's snapshot, return 30-day history."""
    today = datetime.date.today().isoformat()
    key_data = check_all_keys(force=False)

    for pid, entry in key_data.items():
        cost = entry.get("cost")
        if cost and isinstance(cost, dict) and "usd" in cost and "error" not in cost:
            _upsert(pid, today, float(cost["usd"]))

    return _read_history(30)


def get_cost_history() -> dict[str, list[dict]]:
    """Return 30-day cost history from DB only — no fresh API fetch."""
    return _read_history(30)
