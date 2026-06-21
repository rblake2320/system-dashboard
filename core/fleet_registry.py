"""
fleet_registry.py — Thread-safe AI agent fleet registry with background watcher.
"""

import time
import threading
import psutil

_lock = threading.Lock()
_registry: dict[str, dict] = {}
_watcher_thread: threading.Thread | None = None
_started = False


def register_agent(name: str, pid: int, task: str) -> None:
    """Add or replace agent in registry with status='starting'."""
    now = time.time()
    entry = {
        "name": name,
        "pid": pid,
        "task": task,
        "status": "starting",
        "progress": 0,
        "note": "",
        "result": "",
        "started_ts": now,
        "last_heartbeat_ts": now,
        "cpu_samples": [],
        "cpu_pct": None,
        "ram_mb": None,
    }
    with _lock:
        _registry[name] = entry


def heartbeat_agent(name: str, status: str = "working", progress: int = 0, note: str = "") -> None:
    """Update last_heartbeat_ts, status, progress, note.
    If agent was stalled and heartbeat arrives, reset to 'working'."""
    with _lock:
        if name not in _registry:
            return
        agent = _registry[name]
        agent["last_heartbeat_ts"] = time.time()
        agent["progress"] = progress
        agent["note"] = note
        # If previously stalled, a heartbeat wakes it to working
        if agent["status"] == "stalled":
            agent["status"] = "working"
        elif status in ("working", "starting", "done", "stalled", "crashed"):
            agent["status"] = status


def complete_agent(name: str, result: str = "success") -> None:
    """Mark agent as done with the given result."""
    with _lock:
        if name not in _registry:
            return
        agent = _registry[name]
        agent["status"] = "done"
        agent["result"] = result
        agent["progress"] = 100
        agent["last_heartbeat_ts"] = time.time()


def remove_agent(name: str) -> None:
    """Remove agent from registry (called by DELETE /api/fleet/<name>)."""
    with _lock:
        _registry.pop(name, None)


def kill_agent(name: str) -> bool:
    """Kill the agent's process by PID. Returns True if killed, False otherwise."""
    with _lock:
        if name not in _registry:
            return False
        pid = _registry[name]["pid"]

    try:
        proc = psutil.Process(pid)
        proc.kill()
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied, ProcessLookupError):
        return False


def get_fleet() -> list[dict]:
    """Return all agents sorted by started_ts descending.
    Does not include cpu_samples in the output."""
    with _lock:
        snapshot = list(_registry.values())

    now = time.time()
    result = []
    for agent in snapshot:
        result.append({
            "name": agent["name"],
            "pid": agent["pid"],
            "task": agent["task"],
            "status": agent["status"],
            "progress": agent["progress"],
            "note": agent["note"],
            "result": agent["result"],
            "cpu_pct": agent["cpu_pct"],
            "ram_mb": agent["ram_mb"],
            "started_ts": agent["started_ts"],
            "last_heartbeat_ts": agent["last_heartbeat_ts"],
            "runtime_s": int(now - agent["started_ts"]),
        })

    result.sort(key=lambda a: a["started_ts"], reverse=True)
    return result


def _watcher_loop() -> None:
    """Background watcher: polls all agents every 5 seconds."""
    while True:
        try:
            time.sleep(5)
            with _lock:
                names = list(_registry.keys())

            for name in names:
                try:
                    with _lock:
                        if name not in _registry:
                            continue
                        agent = _registry[name]
                        status = agent["status"]
                        pid = agent["pid"]

                    # Skip tombstones
                    if status in ("done", "crashed"):
                        continue

                    try:
                        proc = psutil.Process(pid)
                        cpu = proc.cpu_percent(interval=None)
                        ram = proc.memory_info().rss / 1e6

                        with _lock:
                            if name not in _registry:
                                continue
                            agent = _registry[name]
                            agent["cpu_pct"] = cpu
                            agent["ram_mb"] = ram

                            samples = agent["cpu_samples"]
                            samples.append(cpu)
                            # Keep only last 3
                            if len(samples) > 3:
                                agent["cpu_samples"] = samples[-3:]
                            else:
                                agent["cpu_samples"] = samples

                            current_status = agent["status"]
                            current_samples = agent["cpu_samples"]

                            if (
                                len(current_samples) >= 3
                                and all(s < 0.5 for s in current_samples[-3:])
                                and current_status != "done"
                            ):
                                agent["status"] = "stalled"
                            elif current_status == "stalled" and cpu > 0.5:
                                # Agent woke up
                                agent["status"] = "working"

                    except psutil.NoSuchProcess:
                        with _lock:
                            if name in _registry:
                                current_status = _registry[name]["status"]
                                if current_status not in ("done", "crashed"):
                                    _registry[name]["status"] = "crashed"

                except Exception:
                    # Never crash on a per-agent error
                    pass

        except Exception:
            # Never crash the watcher
            pass


def start_watcher() -> None:
    """Start the background watcher thread. Idempotent — only starts once."""
    global _started, _watcher_thread
    with _lock:
        if _started:
            return
        _started = True

    _watcher_thread = threading.Thread(
        target=_watcher_loop,
        name="fleet-watcher",
        daemon=True,
    )
    _watcher_thread.start()
