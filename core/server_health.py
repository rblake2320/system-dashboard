"""PID health tracker for BPC and TSK demo servers.

Tracks the actual port-listener PID, not the PowerShell launcher.
The launcher exits after spawning Node — we find the real process by
checking who owns the port (psutil.net_connections).
"""
from __future__ import annotations

import threading
import time
from typing import Any

import psutil

_POLL_INTERVAL = 5

# Port each service listens on
_PORTS: dict[str, int] = {"bpc": 3100, "tsk": 3200}

_state: dict[str, dict[str, Any]] = {
    "bpc": {"pid": None, "cmd": None, "started_at": None, "status": "unknown", "crashed_at": None, "port": 3100},
    "tsk": {"pid": None, "cmd": None, "started_at": None, "status": "unknown", "crashed_at": None, "port": 3200},
}
_lock = threading.Lock()
_started = False


def _pid_for_port(port: int) -> int | None:
    """Return the PID of the process listening on the given TCP port, or None."""
    try:
        for conn in psutil.net_connections(kind="tcp"):
            if conn.laddr and conn.laddr.port == port and conn.status == "LISTEN":
                return conn.pid
    except (psutil.AccessDenied, OSError):
        pass
    return None


def _resolve_pid(name: str, launcher_pid: int) -> int:
    """Return the port-listener PID if found, otherwise fall back to launcher."""
    port = _PORTS.get(name)
    if port:
        found = _pid_for_port(port)
        if found:
            return found
    return launcher_pid


def register(name: str, pid: int, cmd: str) -> None:
    """Register a newly started server. Resolves the real listener PID after a short wait."""
    with _lock:
        _state[name] = {
            "pid": pid,
            "cmd": cmd,
            "started_at": time.strftime("%H:%M:%S"),
            "status": "starting",
            "crashed_at": None,
            "port": _PORTS.get(name),
        }
    # Resolve actual listener PID in background after server has time to bind
    def _resolve():
        time.sleep(4)
        real_pid = _resolve_pid(name, pid)
        with _lock:
            if _state[name]["pid"] == pid or _state[name]["status"] == "starting":
                _state[name]["pid"] = real_pid
                _state[name]["status"] = "running"
    t = threading.Thread(target=_resolve, daemon=True, name=f"pid-resolve-{name}")
    t.start()


def get_health() -> dict:
    with _lock:
        return {k: dict(v) for k, v in _state.items()}


def _check_process(info: dict) -> None:
    """Update info dict in-place. Caller must hold _lock."""
    pid = info.get("pid")
    port = info.get("port")

    # First try the tracked PID
    alive = False
    if pid is not None:
        try:
            proc = psutil.Process(pid)
            alive = proc.status() not in (psutil.STATUS_ZOMBIE, psutil.STATUS_DEAD)
        except psutil.NoSuchProcess:
            alive = False

    # If tracked PID is gone, check if someone else is on the port
    if not alive and port:
        listener = _pid_for_port(port)
        if listener:
            info["pid"] = listener
            alive = True

    if alive:
        if info["status"] in ("crashed", "starting"):
            info["status"] = "running"
    else:
        if info["status"] not in ("crashed", "unknown"):
            info["status"] = "crashed"
            info["crashed_at"] = time.strftime("%H:%M:%S")


def _poll() -> None:
    while True:
        time.sleep(_POLL_INTERVAL)
        _poll_once()


def _poll_once() -> None:
    """Single health-check pass. Split out so adoption/recovery is testable."""
    with _lock:
        for name, info in _state.items():
            if info["pid"] is None and info["status"] == "unknown":
                # Never started — check port anyway in case it was started externally
                port = _PORTS.get(name)
                if port:
                    pid = _pid_for_port(port)
                    if pid:
                        info["pid"] = pid
                        info["status"] = "running"
                        info["started_at"] = time.strftime("%H:%M:%S")
                        info["cmd"] = f"external process on :{port}"
                continue
            _check_process(info)


def start_watcher() -> None:
    global _started
    if _started:
        return
    _started = True
    t = threading.Thread(target=_poll, daemon=True, name="server-health-watcher")
    t.start()
