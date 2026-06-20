"""Background monitoring daemon — polls system state, maintains history."""
from __future__ import annotations

import collections
import threading
import time
from typing import Any

import psutil

from core import collector, issues as issue_mod, config as cfg
from core.persistence import db


# ── Per-process CPU sampler ───────────────────────────────────────────────────
# psutil needs two samples to compute CPU%; we maintain a persistent sampler.

class _ProcCPUSampler:
    """Tracks running processes across intervals for accurate CPU%."""

    def __init__(self) -> None:
        self._procs: dict[int, psutil.Process] = {}
        self._lock = threading.Lock()

    def sample(self, tracked_names: set[str]) -> dict[int, float]:
        """Return {pid: cpu_pct} for all matching processes."""
        with self._lock:
            # Add new processes
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    if (proc.info["name"] or "").lower() in tracked_names:
                        pid = proc.info["pid"]
                        if pid not in self._procs:
                            self._procs[pid] = proc
                            try:
                                proc.cpu_percent()  # prime
                            except Exception:
                                pass
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            # Collect and clean up dead processes
            result: dict[int, float] = {}
            dead: list[int] = []
            for pid, proc in self._procs.items():
                try:
                    result[pid] = proc.cpu_percent()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    dead.append(pid)
            for pid in dead:
                del self._procs[pid]
            return result


# ── Disk I/O delta tracker ────────────────────────────────────────────────────

class _DiskIOTracker:
    def __init__(self) -> None:
        self._prev: dict[str, Any] = {}
        self._prev_ts: float = 0.0

    def sample(self) -> dict[str, dict]:
        try:
            counters = psutil.disk_io_counters(perdisk=True)
        except Exception:
            return {}
        now = time.time()
        dt = now - self._prev_ts if self._prev_ts else 1.0
        result: dict[str, dict] = {}
        for disk, c in (counters or {}).items():
            prev = self._prev.get(disk)
            if prev and dt > 0:
                read_mbs = round((c.read_bytes - prev.read_bytes) / 1e6 / dt, 2)
                write_mbs = round((c.write_bytes - prev.write_bytes) / 1e6 / dt, 2)
            else:
                read_mbs = write_mbs = 0.0
            result[disk] = {
                "read_mbs": max(0.0, read_mbs),
                "write_mbs": max(0.0, write_mbs),
            }
        self._prev = {d: c for d, c in (counters or {}).items()}
        self._prev_ts = now
        return result


# ── Alert history ─────────────────────────────────────────────────────────────

class AlertHistory:
    MAX = 200

    def __init__(self) -> None:
        self._log: collections.deque = collections.deque(maxlen=self.MAX)
        self._lock = threading.Lock()
        self._seen: set[str] = set()

    def record(self, issue: "issue_mod.Issue") -> None:
        if issue.id not in self._seen:
            self._seen.add(issue.id)
            with self._lock:
                self._log.appendleft({
                    "id": issue.id,
                    "severity": issue.severity,
                    "title": issue.title,
                    "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "ts_epoch": time.time(),
                })

    def get(self, limit: int = 50) -> list[dict]:
        with self._lock:
            return list(self._log)[:limit]


alert_history = AlertHistory()


# ── Rolling history for sparklines ───────────────────────────────────────────

class _RollingHistory:
    """Stores per-metric series for sparkline rendering (last N samples)."""

    def __init__(self, maxlen: int = 60) -> None:
        self._maxlen = maxlen
        self._series: dict[str, collections.deque] = {}
        self._lock = threading.Lock()

    def push(self, key: str, value: float | int) -> None:
        with self._lock:
            if key not in self._series:
                self._series[key] = collections.deque(maxlen=self._maxlen)
            self._series[key].append(value)

    def get_all(self) -> dict[str, list]:
        with self._lock:
            return {k: list(v) for k, v in self._series.items()}


rolling = _RollingHistory(maxlen=60)


# ── Daemon ────────────────────────────────────────────────────────────────────

class MonitorDaemon:
    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._snapshot_lock = threading.Lock()
        self._latest_snapshot: dict = {}
        self._cpu_sampler = _ProcCPUSampler()
        self._disk_io = _DiskIOTracker()
        self._service_first_seen: dict[str, float] = {}  # port → first seen up ts
        self._last_tick_ts: float = 0.0

    @property
    def is_stale(self) -> bool:
        """True if the daemon has not completed a tick in the last 90 seconds."""
        return time.time() - self._last_tick_ts > 90

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="monitor-daemon")
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def latest(self) -> dict:
        with self._snapshot_lock:
            return dict(self._latest_snapshot)

    def _run(self) -> None:
        interval = cfg.daemon().get("interval_seconds", 30)
        # Seed rolling history from DB (last 60 points per metric, oldest first)
        for metric_key in ("cpu_pct", "ram_pct", "gpu0_pct", "gpu0_mem_pct"):
            rows = db.get_metric_history(metric_key, limit=60)
            rows.reverse()  # get_metric_history returns newest-first; push oldest first
            for row in rows:
                rolling.push(metric_key, row["value"])

        # Prime CPU sampler
        tracked_names = {t["name"].lower() for t in cfg.processes()}
        self._cpu_sampler.sample(tracked_names)
        time.sleep(1)

        while not self._stop_event.wait(timeout=interval):
            try:
                self._tick(tracked_names)
            except Exception as exc:
                print(f"[daemon] error: {exc}")

    def _tick(self, tracked_names: set[str]) -> None:
        snap = collector.build_snapshot()

        # Enrich with CPU% per process
        cpu_map = self._cpu_sampler.sample(tracked_names)
        for exe_name, pdata in snap["processes"].items():
            for p in pdata.get("procs", []):
                p["cpu_pct"] = round(cpu_map.get(p["pid"], 0.0), 1)

        # Enrich with disk I/O
        disk_io = self._disk_io.sample()
        snap["disk_io"] = disk_io

        # Track service uptime
        now = time.time()
        for port_str, pdata in snap["ports"].items():
            key = f"port_{port_str}"
            if pdata["up"]:
                if key not in self._service_first_seen:
                    self._service_first_seen[key] = now
                pdata["uptime_s"] = round(now - self._service_first_seen[key], 0)
            else:
                self._service_first_seen.pop(key, None)
                pdata["uptime_s"] = None

        # Rolling history + DB persistence
        sys = snap["system"]
        ts_now = int(now)
        for metric, value in (
            ("cpu_pct", sys["cpu_pct"]),
            ("ram_pct", sys["ram_pct"]),
        ):
            rolling.push(metric, value)
            db.push_metric(metric, value, ts_now)
        for gpu in sys.get("gpus", []):
            for metric, value in (
                (f"gpu{gpu['index']}_pct", gpu["gpu_pct"]),
                (f"gpu{gpu['index']}_mem_pct", gpu["mem_pct"]),
            ):
                rolling.push(metric, value)
                db.push_metric(metric, value, ts_now)

        snap["history"] = rolling.get_all()

        # Detect issues
        detected = issue_mod.detect_issues(snap)
        issue_mod.registry.update(detected)
        for issue in detected:
            alert_history.record(issue)
            db.push_alert(issue.as_dict())
        snap["issues"] = [i.as_dict() for i in issue_mod.registry.get_active()]
        snap["alert_history"] = alert_history.get(50)

        with self._snapshot_lock:
            self._latest_snapshot = snap
        self._last_tick_ts = time.time()


# Singleton
daemon = MonitorDaemon()
