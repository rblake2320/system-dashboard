"""PID health tracker for BPC and TSK demo servers.

Tracks PIDs set by the /api/bpc/start and /api/tsk/start routes.
Background thread polls every 5 seconds and marks crashes.
"""
from __future__ import annotations

import threading
import time
from typing import Any

import psutil

_POLL_INTERVAL = 5

_state: dict[str, dict[str, Any]] = {
    "bpc": {"pid": None, "cmd": None, "started_at": None, "status": "unknown", "crashed_at": None},
    "tsk": {"pid": None, "cmd": None, "started_at": None, "status": "unknown", "crashed_at": None},
}
_lock = threading.Lock()
_started = False


def register(name: str, pid: int, cmd: str) -> None:
    """Register a newly started server PID."""
    with _lock:
        _state[name] = {
            "pid": pid,
            "cmd": cmd,
            "started_at": time.strftime("%H:%M:%S"),
            "status": "running",
            "crashed_at": None,
        }


def get_health() -> dict:
    with _lock:
        return {k: dict(v) for k, v in _state.items()}


def _poll() -> None:
    while True:
        time.sleep(_POLL_INTERVAL)
        with _lock:
            for name, info in _state.items():
                pid = info.get("pid")
                if pid is None:
                    continue
                if info["status"] in ("crashed", "stopped"):
                    continue
                try:
                    proc = psutil.Process(pid)
                    status = proc.status()
                    info["status"] = "running" if status not in (
                        psutil.STATUS_ZOMBIE, psutil.STATUS_DEAD
                    ) else "crashed"
                    if info["status"] == "crashed":
                        info["crashed_at"] = time.strftime("%H:%M:%S")
                except psutil.NoSuchProcess:
                    info["status"] = "crashed"
                    info["crashed_at"] = time.strftime("%H:%M:%S")


def start_watcher() -> None:
    global _started
    if _started:
        return
    _started = True
    t = threading.Thread(target=_poll, daemon=True, name="server-health-watcher")
    t.start()
