"""Process-kill and fixer-param guard — validates targets before execution."""
from __future__ import annotations

import re
from typing import Any

from core import config as cfg

_ALLOWED_SERVICE_ACTIONS = frozenset({
    "restart", "start", "stop",          # generic sc.exe actions
    "restart_nssm", "diagnose_port", "kill_port",  # ServiceFixer actions
    "find_large_files", "scan_drive",    # StorageFixer actions
})
_DRIVE_RE = re.compile(r"^[A-Za-z]$")


class PIDGuard:
    """Validates PIDs and fixer params before execution.

    Rules
    -----
    validate_kill:
      - If security.allow_kill_any_pid is True (config), allow any PID (still
        logs the validation outcome).
      - Otherwise the PID must appear in the current snapshot's tracked process
        list.  If the process is not tracked but is still running, reject
        unless the allow-any override is set.

    validate_fixer_params:
      - process_fixer / kill_by_name: name must be in tracked process names.
      - process_fixer / kill_by_pid: pid must be a positive integer.
      - service_fixer / *: action must be in the allowed set.
      - storage_fixer / *: drive must be a single letter A-Z.
    """

    def validate_kill(
        self,
        pid: int,
        snapshot: dict[str, Any] | None,
    ) -> tuple[bool, str]:
        """Return (ok, reason). ok=True means the kill is permitted."""
        sec_cfg = cfg.get().get("security", {})
        allow_any = sec_cfg.get("allow_kill_any_pid", False)

        if allow_any:
            return True, f"allow_kill_any_pid=true; pid={pid} permitted (logged)"

        # Build tracked PID set from snapshot
        tracked_pids: set[int] = set()
        if snapshot:
            for proc_group in snapshot.get("processes", {}).values():
                for p in proc_group.get("procs", []):
                    try:
                        tracked_pids.add(int(p["pid"]))
                    except (KeyError, ValueError, TypeError):
                        pass

        if pid in tracked_pids:
            return True, f"pid={pid} found in tracked process list"

        # PID not tracked — check if it's still running
        try:
            import psutil
            proc = psutil.Process(pid)
            proc.status()  # raises NoSuchProcess if gone
            return (
                False,
                f"pid={pid} is running but NOT in tracked process list; "
                "set security.allow_kill_any_pid=true to override",
            )
        except Exception:
            return False, f"pid={pid} is not in tracked list and is not running"

    def validate_fixer_params(
        self,
        fixer_id: str,
        params: dict[str, Any],
    ) -> tuple[bool, str]:
        """Return (ok, reason).  ok=True means the params are safe to execute."""
        action = params.get("action", "")
        tracked_names: set[str] = {
            p["name"].lower() for p in cfg.processes() if "name" in p
        }

        if fixer_id == "process_fixer":
            if action == "kill_by_name":
                name = str(params.get("name", "")).lower()
                if not name:
                    return False, "kill_by_name: 'name' param is missing"
                if name not in tracked_names:
                    return (
                        False,
                        f"kill_by_name: '{name}' is not in the tracked process list",
                    )
                return True, f"kill_by_name: '{name}' is tracked"

            if action == "kill_by_pid":
                try:
                    pid_val = int(params.get("pid", 0))
                except (ValueError, TypeError):
                    return False, "kill_by_pid: 'pid' is not an integer"
                if pid_val <= 0:
                    return False, f"kill_by_pid: pid={pid_val} must be a positive integer"
                return True, f"kill_by_pid: pid={pid_val} is a valid positive integer"

            return True, f"process_fixer action '{action}' not specifically validated; permitted"

        if fixer_id == "service_fixer":
            if action not in _ALLOWED_SERVICE_ACTIONS:
                return (
                    False,
                    f"service_fixer: action '{action}' not in allowed set "
                    f"{sorted(_ALLOWED_SERVICE_ACTIONS)}",
                )
            return True, f"service_fixer: action '{action}' is allowed"

        if fixer_id == "storage_fixer":
            drive = str(params.get("drive", ""))
            if not _DRIVE_RE.match(drive):
                return (
                    False,
                    f"storage_fixer: drive '{drive}' must be a single letter A-Z",
                )
            return True, f"storage_fixer: drive '{drive}' is valid"

        # Unknown fixer — pass through (future fixers are not blocked)
        return True, f"fixer_id '{fixer_id}' has no validation rules; permitted"


# Module-level singleton
pid_guard = PIDGuard()
