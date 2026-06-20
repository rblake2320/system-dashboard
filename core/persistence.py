"""SQLite persistence layer — metric history, alert log, action log."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_DB_PATH = _ROOT / "data" / "dashboard.db"

_DDL = """
CREATE TABLE IF NOT EXISTS metric_history (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     INTEGER NOT NULL,
    metric TEXT    NOT NULL,
    value  REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mh_metric_ts ON metric_history(metric, ts DESC);

CREATE TABLE IF NOT EXISTS alert_history (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    issue_id TEXT    NOT NULL,
    severity TEXT    NOT NULL,
    title    TEXT    NOT NULL,
    category TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ah_ts ON alert_history(ts DESC);

CREATE TABLE IF NOT EXISTS action_log (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      INTEGER NOT NULL,
    action  TEXT    NOT NULL,
    params  TEXT    NOT NULL,
    ip      TEXT,
    result  TEXT,
    success INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS cost_snapshots (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    provider   TEXT    NOT NULL,
    date       TEXT    NOT NULL,
    cost_usd   REAL    NOT NULL,
    sampled_at INTEGER NOT NULL,
    UNIQUE(provider, date) ON CONFLICT REPLACE
);
CREATE INDEX IF NOT EXISTS idx_cs_provider_date ON cost_snapshots(provider, date DESC);
"""

_VACUUM_INTERVAL = 86_400          # run vacuum check at most once per day
_METRIC_TTL = 7 * 86_400           # keep 7 days of metric data


class DashboardDB:
    """Thread-safe SQLite persistence for dashboard state."""

    def __init__(self, path: Path = _DB_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = path
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None
        self._last_vacuum: float = 0.0
        self._open()

    # ── Internal ──────────────────────────────────────────────────────────────

    def _open(self) -> None:
        self._conn = sqlite3.connect(
            str(self._path),
            check_same_thread=False,
            isolation_level=None,   # autocommit
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        for stmt in _DDL.strip().split(";"):
            s = stmt.strip()
            if s:
                self._conn.execute(s)

    def _execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.execute(sql, params)

    def _fetchall(self, sql: str, params: tuple = ()) -> list[dict]:
        with self._lock:
            cur = self._conn.execute(sql, params)
            return [dict(row) for row in cur.fetchall()]

    # ── Metric history ────────────────────────────────────────────────────────

    def push_metric(self, metric: str, value: float, ts: int | None = None) -> None:
        if ts is None:
            ts = int(time.time())
        self._execute(
            "INSERT INTO metric_history (ts, metric, value) VALUES (?, ?, ?)",
            (ts, metric, float(value)),
        )
        # Opportunistic daily vacuum
        now = time.time()
        if now - self._last_vacuum > _VACUUM_INTERVAL:
            self._last_vacuum = now
            self.vacuum()

    def get_metric_history(self, metric: str, limit: int = 60) -> list[dict]:
        """Return up to *limit* rows newest-first."""
        return self._fetchall(
            "SELECT ts, metric, value FROM metric_history "
            "WHERE metric = ? ORDER BY ts DESC LIMIT ?",
            (metric, limit),
        )

    # ── Alert history ─────────────────────────────────────────────────────────

    def push_alert(self, issue: dict) -> None:
        ts = int(issue.get("detected_at", time.time()))
        self._execute(
            "INSERT INTO alert_history (ts, issue_id, severity, title, category) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                ts,
                issue.get("id", ""),
                issue.get("severity", ""),
                issue.get("title", ""),
                issue.get("category", ""),
            ),
        )

    def get_alerts(self, limit: int = 100) -> list[dict]:
        return self._fetchall(
            "SELECT ts, issue_id, severity, title, category "
            "FROM alert_history ORDER BY ts DESC LIMIT ?",
            (limit,),
        )

    # ── Action log ────────────────────────────────────────────────────────────

    def push_action(
        self,
        action: str,
        params: dict | str,
        ip: str | None,
        result: str | None,
        success: bool,
    ) -> None:
        if not isinstance(params, str):
            params = json.dumps(params)
        self._execute(
            "INSERT INTO action_log (ts, action, params, ip, result, success) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (int(time.time()), action, params, ip, result, int(success)),
        )

    def get_actions(self, limit: int = 100) -> list[dict]:
        return self._fetchall(
            "SELECT ts, action, params, ip, result, success "
            "FROM action_log ORDER BY ts DESC LIMIT ?",
            (limit,),
        )

    # ── Maintenance ───────────────────────────────────────────────────────────

    def vacuum(self) -> None:
        """Delete metric rows older than 7 days."""
        cutoff = int(time.time()) - _METRIC_TTL
        self._execute(
            "DELETE FROM metric_history WHERE ts < ?",
            (cutoff,),
        )


# Global singleton
db = DashboardDB()
