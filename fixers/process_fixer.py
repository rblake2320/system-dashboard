"""Process fixer — kill, list, and manage processes."""
from __future__ import annotations

import time
from collections.abc import Generator

import psutil

from .base import FixerBase


class ProcessFixer(FixerBase):
    fixer_id = "process_fixer"

    def can_fix(self, issue: dict) -> bool:
        return issue.get("fixer_id") == self.fixer_id

    def fix(self, issue: dict) -> Generator[str, None, None]:
        params = issue.get("fix_params", {})
        action = params.get("action", "list_instances")

        if action == "list_instances":
            yield from self._list_instances(params)
        elif action == "kill_by_name":
            yield from self._kill_by_name(params, issue)
        elif action == "kill_by_pid":
            yield from self._kill_by_pid(params)
        elif action == "list_top_cpu":
            yield from self._list_top(sort_by="cpu")
        elif action == "list_top_memory":
            yield from self._list_top(sort_by="memory")
        else:
            yield f"Unknown action: {action}"
            yield "DONE"

    # ── Actions ───────────────────────────────────────────────────────────────

    def _list_instances(self, params: dict) -> Generator[str, None, None]:
        name = params.get("name", "")
        yield f"Listing instances of {name}..."
        procs = self._find_by_name(name)
        if not procs:
            yield f"No running instances of {name} found."
            yield "DONE"
            return
        yield f"Found {len(procs)} instance(s):"
        for p in sorted(procs, key=lambda x: x["mem_mb"], reverse=True):
            yield f"  PID {p['pid']:6d} | {p['mem_mb']:8.1f} MB | up {_fmt_age(p['age_s'])} | status: {p['status']}"
        yield ""
        yield f"Total: {sum(p['mem_mb'] for p in procs):.0f} MB across {len(procs)} processes"
        yield "DONE"

    def _kill_by_name(self, params: dict, issue: dict) -> Generator[str, None, None]:
        name = params.get("name", "")
        yield f"Finding processes matching '{name}'..."
        procs = self._find_by_name(name)
        if not procs:
            yield f"No running instances of {name} found. Nothing to kill."
            yield "DONE"
            return
        yield f"Found {len(procs)} instance(s):"
        killed = 0
        failed = 0
        for p in procs:
            yield f"  Terminating PID {p['pid']} ({p['mem_mb']:.0f}MB)..."
            try:
                proc = psutil.Process(p["pid"])
                proc.terminate()
                time.sleep(0.5)
                if proc.is_running():
                    proc.kill()
                    yield f"  Force-killed PID {p['pid']}"
                else:
                    yield f"  Terminated PID {p['pid']} cleanly"
                killed += 1
            except psutil.NoSuchProcess:
                yield f"  PID {p['pid']} already gone"
                killed += 1
            except psutil.AccessDenied:
                yield f"  FAILED: Access denied for PID {p['pid']}"
                failed += 1
            except Exception as e:
                yield f"  FAILED: {e}"
                failed += 1

        yield ""
        yield f"Result: {killed} killed, {failed} failed"
        if failed:
            yield "FAILED: some processes could not be killed (access denied)"
        else:
            yield "DONE"

    def _kill_by_pid(self, params: dict) -> Generator[str, None, None]:
        pid = params.get("pid")
        if not pid:
            yield "FAILED: no PID specified"
            return
        try:
            pid_int = int(pid)
        except (ValueError, TypeError):
            yield f"FAILED: pid {pid!r} is not an integer"
            return

        # Guard: validate the kill regardless of which code path called us.
        from core.pid_guard import pid_guard
        from daemon.monitor import daemon as _daemon
        snap = _daemon.latest() or {}
        ok, reason = pid_guard.validate_kill(pid_int, snap)
        if not ok:
            yield f"FAILED: Kill blocked by pid_guard — {reason}"
            return

        yield f"Terminating PID {pid_int}..."
        try:
            proc = psutil.Process(pid_int)
            # Capture identity before kill for PID-reuse defence
            _name = proc.name()
            _ctime = proc.create_time()
            proc.terminate()
            time.sleep(0.5)
            try:
                # Re-confirm identity has not changed (PID-reuse race)
                if proc.is_running():
                    if abs(proc.create_time() - _ctime) > 1.0 or proc.name() != _name:
                        yield f"FAILED: PID {pid_int} identity changed mid-kill (PID reuse); aborting"
                        return
                    proc.kill()
                    yield f"Force-killed {_name} (PID {pid_int})"
                else:
                    yield f"Terminated {_name} (PID {pid_int}) cleanly"
            except psutil.NoSuchProcess:
                yield f"Terminated {_name} (PID {pid_int}) cleanly"
            yield "DONE"
        except psutil.NoSuchProcess:
            yield f"PID {pid_int} not found — already exited"
            yield "DONE"
        except psutil.AccessDenied:
            yield f"FAILED: Access denied for PID {pid_int}"
        except Exception as e:
            yield f"FAILED: {e}"

    def _list_top(self, sort_by: str = "memory") -> Generator[str, None, None]:
        yield f"Collecting top processes by {sort_by}..."
        attr = "memory_info" if sort_by == "memory" else "cpu_percent"
        attrs = ["pid", "name", "memory_info", "cpu_percent", "status"]
        procs = []
        if sort_by == "cpu":
            # prime
            for p in psutil.process_iter(["pid"]):
                try:
                    p.cpu_percent()
                except Exception:
                    pass
            time.sleep(0.3)
        for proc in psutil.process_iter(attrs):
            try:
                mi = proc.info["memory_info"]
                mem_mb = round(mi.rss / 1e6, 1) if mi else 0
                cpu = proc.info["cpu_percent"] or 0
                procs.append({
                    "pid": proc.info["pid"],
                    "name": proc.info["name"] or "?",
                    "mem_mb": mem_mb,
                    "cpu_pct": cpu,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        key = "cpu_pct" if sort_by == "cpu" else "mem_mb"
        procs = sorted(procs, key=lambda p: p[key], reverse=True)[:20]
        yield ""
        yield f"{'PID':>7}  {'Name':<30}  {'Mem MB':>10}  {'CPU%':>6}"
        yield "-" * 60
        for p in procs:
            yield f"{p['pid']:>7}  {p['name']:<30}  {p['mem_mb']:>10.1f}  {p['cpu_pct']:>6.1f}"
        yield "DONE"

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _find_by_name(name: str) -> list[dict]:
        result = []
        lname = name.lower()
        for proc in psutil.process_iter(["pid", "name", "memory_info", "status", "create_time"]):
            try:
                if (proc.info["name"] or "").lower() == lname:
                    mi = proc.info["memory_info"]
                    result.append({
                        "pid": proc.info["pid"],
                        "mem_mb": round((mi.rss if mi else 0) / 1e6, 1),
                        "status": proc.info["status"],
                        "age_s": round(time.time() - (proc.info["create_time"] or time.time()), 0),
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return result


def _fmt_age(seconds: float) -> str:
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s//60}m {s%60}s"
    return f"{s//3600}h {(s%3600)//60}m"
