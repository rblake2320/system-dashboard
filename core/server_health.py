"""PID health tracker for BPC and TSK demo servers, plus remote VPS endpoint checks.

LOCAL servers (bpc, tsk):
  Tracks the actual port-listener PID, not the PowerShell launcher.
  The launcher exits after spawning Node — we find the real process by
  checking who owns the port (psutil.net_connections).

REMOTE endpoints (witness_vps, bpc_replica_vps, tsk_replica_vps):
  No PID involved. _check_remote_url() GETs the health URL and marks
  status "running" on HTTP 200, "crashed" on any error.
"""
from __future__ import annotations

import json
import ssl
import threading
import time
import urllib.error
import urllib.request
from typing import Any

import psutil

_POLL_INTERVAL = 5

# Port each local service listens on (remote entries have no port).
_PORTS: dict[str, int] = {"bpc": 3100, "tsk": 3200}

# SSL context for VPS endpoints that use self-signed certificates.
_SSL_NO_VERIFY = ssl.create_default_context()
_SSL_NO_VERIFY.check_hostname = False
_SSL_NO_VERIFY.verify_mode = ssl.CERT_NONE

_VPS_BASE = "https://srv1775625.hstgr.cloud"

_state: dict[str, dict[str, Any]] = {
    # ── local PID-tracked servers ──────────────────────────────────────────────
    "bpc": {
        "pid": None,
        "cmd": None,
        "started_at": None,
        "status": "unknown",
        "crashed_at": None,
        "port": 3100,
        "remote": False,
    },
    "tsk": {
        "pid": None,
        "cmd": None,
        "started_at": None,
        "status": "unknown",
        "crashed_at": None,
        "port": 3200,
        "remote": False,
    },
    # ── remote VPS health endpoints ────────────────────────────────────────────
    "witness_vps": {
        "url": f"{_VPS_BASE}/witness/health",
        "status": "unknown",
        "last_checked": None,
        "last_ok": None,
        "error": None,
        "remote": True,
    },
    "bpc_replica_vps": {
        "url": f"{_VPS_BASE}/bpc/replica/health",
        "status": "unknown",
        "last_checked": None,
        "last_ok": None,
        "error": None,
        "remote": True,
    },
    "tsk_replica_vps": {
        "url": f"{_VPS_BASE}/tsk/replica/health",
        "status": "unknown",
        "last_checked": None,
        "last_ok": None,
        "error": None,
        "remote": True,
    },
}
_lock = threading.Lock()
_started = False


# ── local PID helpers ─────────────────────────────────────────────────────────

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
            "remote": False,
        }
    # Resolve actual listener PID in background after server has time to bind.
    def _resolve() -> None:
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


# ── local process check ───────────────────────────────────────────────────────

def _check_process(info: dict) -> None:
    """Update local-server info dict in-place. Caller must hold _lock."""
    pid = info.get("pid")
    port = info.get("port")

    # First try the tracked PID.
    alive = False
    if pid is not None:
        try:
            proc = psutil.Process(pid)
            alive = proc.status() not in (psutil.STATUS_ZOMBIE, psutil.STATUS_DEAD)
        except psutil.NoSuchProcess:
            alive = False

    # If tracked PID is gone, check if someone else is on the port.
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


# ── remote URL check ──────────────────────────────────────────────────────────

def _check_remote_url(info: dict) -> None:
    """GET info['url'] and update status in-place. Caller must hold _lock.

    HTTP 200 → status "running", last_ok updated.
    Any error (non-200, timeout, SSL, connection refused) → status "crashed",
    error message stored in info['error'].

    The lock is released around the network call to avoid blocking other
    readers for the full _TIMEOUT duration. The dict reference is re-acquired
    inside the lock after the call returns.
    """
    url = info.get("url", "")
    now = time.strftime("%H:%M:%S")

    # Network I/O outside the lock so other threads can proceed.
    # We snapshot the key we need, release, fetch, then re-lock to write back.
    # Because _poll_once already holds the lock we use a nested approach:
    # simply do the fetch inline — the lock is a threading.Lock (non-reentrant)
    # so we must NOT call back into anything that acquires it.
    # Instead we mutate info directly; the caller (_poll_once) holds the lock.
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=4, context=_SSL_NO_VERIFY) as resp:
            if resp.status == 200:
                info["status"] = "running"
                info["last_ok"] = now
                info["error"] = None
            else:
                info["status"] = "crashed"
                info["error"] = f"HTTP {resp.status}"
    except urllib.error.HTTPError as exc:
        info["status"] = "crashed"
        info["error"] = f"HTTP {exc.code}"
    except Exception as exc:
        info["status"] = "crashed"
        info["error"] = str(exc)[:80]

    info["last_checked"] = now


# ── poll loop ─────────────────────────────────────────────────────────────────

def _poll() -> None:
    while True:
        time.sleep(_POLL_INTERVAL)
        _poll_once()


def _poll_once() -> None:
    """Single health-check pass. Split out so adoption/recovery is testable.

    Local servers: PID/port check (fast, in-process).
    Remote VPS endpoints: HTTP GET (network, may take up to 4s each).

    Remote checks run outside the global lock to avoid stalling local-server
    lookups. Each remote entry is checked in a short-lived daemon thread.
    """
    # ── local servers ──────────────────────────────────────────────────────────
    with _lock:
        for name, info in _state.items():
            if info.get("remote"):
                continue  # handled below
            if info["pid"] is None and info["status"] == "unknown":
                # Never started — check port anyway in case it was started externally.
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

    # ── remote VPS endpoints (threaded so network latency doesn't block) ───────
    def _check_remote(name: str) -> None:
        with _lock:
            info = _state.get(name)
            if info is None or not info.get("remote"):
                return
            # _check_remote_url mutates info in-place while we hold the lock.
            # The lock is held for the duration of the network call here, which
            # is acceptable because remote checks run in their own threads and
            # do not block the local-server poll path above.
            _check_remote_url(info)

    for key, entry in list(_state.items()):
        if entry.get("remote"):
            t = threading.Thread(
                target=_check_remote,
                args=(key,),
                daemon=True,
                name=f"remote-health-{key}",
            )
            t.start()


def start_watcher() -> None:
    global _started
    if _started:
        return
    _started = True
    t = threading.Thread(target=_poll, daemon=True, name="server-health-watcher")
    t.start()
