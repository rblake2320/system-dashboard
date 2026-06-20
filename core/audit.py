"""Append-only JSONL audit log for all mutating dashboard actions."""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_LOGS_DIR = Path(__file__).resolve().parent.parent / "logs"
_LOG_FILE = _LOGS_DIR / "actions.jsonl"


class AuditLog:
    """Thread-safe JSONL audit log.

    Each entry written to logs/actions.jsonl:
        {ts, action, params, user_ip, result, pid_validated}
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        _LOGS_DIR.mkdir(parents=True, exist_ok=True)

    def log(
        self,
        action: str,
        params: dict[str, Any],
        user_ip: str,
        result: str,
        pid_validated: bool = False,
    ) -> None:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "params": params,
            "user_ip": user_ip,
            "result": result,
            "pid_validated": pid_validated,
        }
        line = json.dumps(entry, default=str)
        with self._lock:
            with _LOG_FILE.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    def tail(self, n: int = 100) -> list[dict[str, Any]]:
        """Return the last *n* log entries (most-recent-last)."""
        if not _LOG_FILE.exists():
            return []
        with self._lock:
            lines = _LOG_FILE.read_text(encoding="utf-8").splitlines()
        entries: list[dict[str, Any]] = []
        for line in lines[-n:]:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return entries


# Module-level singleton — imported by dashboard.py
audit_log = AuditLog()


def log_action(
    action: str,
    params: dict[str, Any],
    ip: str,
    result: str,
    pid_validated: bool = False,
) -> None:
    """Convenience wrapper around the singleton."""
    audit_log.log(action, params, ip, result, pid_validated)
