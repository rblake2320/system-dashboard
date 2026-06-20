"""Issue detection, registry, and types."""
from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from . import config as cfg

# ── Hysteresis constants ──────────────────────────────────────────────────────
CRITICAL_HYSTERESIS = 3   # must fire 3 consecutive checks before becoming active
RESOLVE_HYSTERESIS = 2    # must be absent 2 consecutive checks before resolving


@dataclass
class Issue:
    id: str                        # deterministic hash — same issue = same id
    severity: str                  # critical | warning | info
    category: str                  # process | storage | network | service | hook
    title: str
    description: str
    fixer_id: str | None = None    # which fixer can handle this
    fix_params: dict = field(default_factory=dict)
    context: dict = field(default_factory=dict)
    detected_at: float = field(default_factory=time.time)
    resolved: bool = False
    state: str = "new"             # new | active | acknowledged | fixing | resolved | suppressed
    suppressed_until: float | None = None  # epoch timestamp; None = not suppressed

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "fixer_id": self.fixer_id,
            "fix_params": self.fix_params,
            "context": self.context,
            "detected_at": self.detected_at,
            "resolved": self.resolved,
            "state": self.state,
        }


def _make_id(*parts: str) -> str:
    raw = "|".join(str(p) for p in parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_issues(snapshot: dict) -> list[Issue]:
    issues: list[Issue] = []
    sys = snapshot.get("system", {})
    procs = snapshot.get("processes", {})
    ports = snapshot.get("ports", {})
    gpus = sys.get("gpus", [])

    # ── CPU ───────────────────────────────────────────────────────────────────
    cpu_pct = sys.get("cpu_pct", 0)
    if cpu_pct > 90:
        issues.append(Issue(
            id=_make_id("cpu_critical"),
            severity="critical", category="system",
            title=f"CPU at {cpu_pct:.0f}%",
            description=f"CPU usage is critically high at {cpu_pct:.1f}%. System may become unresponsive.",
            fixer_id="process_fixer",
            fix_params={"action": "list_top_cpu"},
        ))
    elif cpu_pct > 75:
        issues.append(Issue(
            id=_make_id("cpu_warning"),
            severity="warning", category="system",
            title=f"CPU high at {cpu_pct:.0f}%",
            description=f"CPU is at {cpu_pct:.1f}%. Consider checking resource-heavy processes.",
        ))

    # ── RAM ───────────────────────────────────────────────────────────────────
    ram_pct = sys.get("ram_pct", 0)
    ram_avail = sys.get("ram_avail_gb", 999)
    if ram_pct > 90 or ram_avail < 4:
        issues.append(Issue(
            id=_make_id("ram_critical"),
            severity="critical", category="system",
            title=f"RAM at {ram_pct:.0f}% ({ram_avail:.1f}GB free)",
            description="System RAM nearly exhausted. Risk of OOM kills and instability.",
            fixer_id="process_fixer",
            fix_params={"action": "list_top_memory"},
        ))
    elif ram_pct > 75:
        issues.append(Issue(
            id=_make_id("ram_warning"),
            severity="warning", category="system",
            title=f"RAM at {ram_pct:.0f}% ({ram_avail:.1f}GB free)",
            description="RAM usage is elevated. Monitor for further growth.",
        ))

    # ── GPU ───────────────────────────────────────────────────────────────────
    for gpu in gpus:
        mem_pct = gpu.get("mem_pct", 0)
        gpu_pct = gpu.get("gpu_pct", 0)
        name = gpu.get("name", f"GPU {gpu.get('index', 0)}")
        temp = gpu.get("temp_c")
        if mem_pct > 90:
            issues.append(Issue(
                id=_make_id("gpu_vram", str(gpu.get("index", 0))),
                severity="critical", category="system",
                title=f"{name}: VRAM at {mem_pct:.0f}%",
                description=f"GPU VRAM nearly full: {gpu['mem_used_mb']/1024:.1f}/{gpu['mem_total_mb']/1024:.1f} GB used.",
            ))
        if temp and temp > 85:
            issues.append(Issue(
                id=_make_id("gpu_temp", str(gpu.get("index", 0))),
                severity="critical" if temp > 95 else "warning",
                category="system",
                title=f"{name}: Temp {temp}°C",
                description=f"GPU temperature is {'dangerously high' if temp > 95 else 'elevated'} at {temp}°C.",
            ))

    # ── Storage ───────────────────────────────────────────────────────────────
    for letter, d in sys.get("drives", {}).items():
        if d.get("total_gb", 0) == 0:
            continue  # drive unavailable / unmounted — skip all checks
        if d.get("failing"):
            issues.append(Issue(
                id=_make_id("drive_failing", letter),
                severity="critical", category="storage",
                title=f"Drive {letter}: Hardware Failure",
                description=f"Drive {letter}: is flagged as FAILING. {d.get('free_gb', '?')}GB free. Back up data immediately.",
                fixer_id="storage_fixer",
                fix_params={"action": "scan_drive", "drive": letter},
                context={"drive": letter, "stats": d},
            ))
        elif d.get("warn"):
            issues.append(Issue(
                id=_make_id("drive_low", letter),
                severity="warning", category="storage",
                title=f"Drive {letter}: Low space ({d['free_gb']}GB free)",
                description=f"Drive {letter}: has only {d['free_gb']}GB of {d['total_gb']}GB free ({d['pct']}% used).",
                fixer_id="storage_fixer",
                fix_params={"action": "find_large_files", "drive": letter},
                context={"drive": letter, "stats": d},
            ))

    # ── SMART / NVMe health ───────────────────────────────────────────────────
    smart_health: dict[str, dict] = snapshot.get("smart_health", {})
    for drive_letter, sh in smart_health.items():
        health = sh.get("health", "Unknown")
        temp = sh.get("temp_c")
        wear = sh.get("wear_pct")
        media_err = sh.get("media_errors") or 0
        model = sh.get("model") or f"Drive {drive_letter}:"

        if health == "Unhealthy":
            issues.append(Issue(
                id=_make_id("smart_unhealthy", drive_letter),
                severity="critical", category="storage",
                title=f"Drive {drive_letter}: SMART status Unhealthy — {model}",
                description=(
                    f"Drive {drive_letter}: ({model}) reports SMART health = Unhealthy. "
                    f"Data loss is imminent. Back up immediately."
                ),
                fixer_id="storage_fixer",
                fix_params={"action": "scan_drive", "drive": drive_letter},
                context={"drive": drive_letter, "smart": sh},
            ))

        if wear is not None and wear < 10:
            issues.append(Issue(
                id=_make_id("smart_wear", drive_letter),
                severity="critical", category="storage",
                title=f"Drive {drive_letter}: NVMe wear < 10% remaining ({wear}%)",
                description=(
                    f"Drive {drive_letter}: ({model}) has only {wear}% of rated write "
                    f"endurance remaining. Replace before it fails."
                ),
                fixer_id="storage_fixer",
                fix_params={"action": "scan_drive", "drive": drive_letter},
                context={"drive": drive_letter, "smart": sh},
            ))

        if temp is not None and temp > 70:
            issues.append(Issue(
                id=_make_id("smart_temp", drive_letter),
                severity="warning", category="storage",
                title=f"Drive {drive_letter}: High temp {temp}°C — {model}",
                description=(
                    f"Drive {drive_letter}: ({model}) temperature is {temp}°C, "
                    f"above the 70°C warning threshold. Check airflow."
                ),
                context={"drive": drive_letter, "smart": sh},
            ))

        if media_err > 0:
            issues.append(Issue(
                id=_make_id("smart_media_errors", drive_letter),
                severity="critical", category="storage",
                title=f"Drive {drive_letter}: {media_err} media error(s) — {model}",
                description=(
                    f"Drive {drive_letter}: ({model}) has {media_err} media error(s) "
                    f"logged by the controller. This indicates physical damage to NAND cells."
                ),
                fixer_id="storage_fixer",
                fix_params={"action": "scan_drive", "drive": drive_letter},
                context={"drive": drive_letter, "smart": sh},
            ))

    # ── Processes ─────────────────────────────────────────────────────────────
    proc_cfg = {t["name"].lower(): t for t in cfg.processes()}
    for exe_name, pdata in procs.items():
        lname = exe_name.lower()
        pcfg = proc_cfg.get(lname, {})

        # Autonomy warnings
        if pcfg.get("warn") and pdata.get("count", 0) > 0:
            issues.append(Issue(
                id=_make_id("proc_warn", exe_name),
                severity="warning", category="process",
                title=f"{exe_name}: {pcfg.get('warn_reason', 'Flagged process running')}",
                description=f"{pdata['count']} instance(s) of {exe_name} running. {pcfg.get('warn_reason', '')}",
                fixer_id="process_fixer",
                fix_params={"action": "kill_by_name", "name": exe_name},
                context={"procs": pdata.get("procs", [])},
            ))

        # Count threshold
        warn_count = pcfg.get("warn_if_count_exceeds", 0)
        if warn_count and pdata.get("count", 0) > warn_count:
            issues.append(Issue(
                id=_make_id("proc_count", exe_name),
                severity="warning", category="process",
                title=f"{exe_name}: {pdata['count']} instances (threshold: {warn_count})",
                description=f"{pdata['count']} instances of {exe_name} are running, exceeding the configured threshold of {warn_count}. Total RAM: {pdata.get('total_mb', 0):.0f}MB.",
                fixer_id="process_fixer",
                fix_params={"action": "list_instances", "name": exe_name},
                context={"procs": pdata.get("procs", [])},
            ))

    return issues


# ── Registry ──────────────────────────────────────────────────────────────────

class IssueRegistry:
    """Thread-safe in-memory store for current issues."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._issues: dict[str, Issue] = {}
        self._fire_count: dict[str, int] = {}   # consecutive checks issue was detected
        self._clear_count: dict[str, int] = {}  # consecutive checks issue was absent

    def update(self, new_issues: list[Issue]) -> None:
        new_ids = {i.id for i in new_issues}
        with self._lock:
            # Track absent issues — increment clear counter, resolve after hysteresis
            for iid in list(self._issues):
                issue = self._issues[iid]
                if iid not in new_ids and not issue.resolved and issue.state != "suppressed":
                    self._clear_count[iid] = self._clear_count.get(iid, 0) + 1
                    self._fire_count[iid] = 0  # reset fire counter
                    if self._clear_count[iid] >= RESOLVE_HYSTERESIS:
                        issue.resolved = True
                        issue.state = "resolved"

            # Track detected issues — increment fire counter, add after hysteresis
            for issue in new_issues:
                iid = issue.id
                self._clear_count[iid] = 0  # reset clear counter — issue is present

                if iid not in self._issues:
                    # Pending: not yet in registry — check fire count
                    self._fire_count[iid] = self._fire_count.get(iid, 0) + 1
                    if self._fire_count[iid] >= CRITICAL_HYSTERESIS:
                        self._fire_count[iid] = 0  # reset after crossing threshold
                        self._issues[iid] = issue   # now active
                else:
                    existing = self._issues[iid]
                    if existing.state not in ("acknowledged", "fixing", "suppressed"):
                        existing.resolved = False
                        if existing.state == "resolved":
                            existing.state = "new"
                        elif existing.state == "new":
                            existing.state = "active"
                    existing.title = issue.title
                    existing.description = issue.description

    def get_active(self) -> list[Issue]:
        """Return issues that are not resolved or suppressed."""
        now = time.time()
        with self._lock:
            result = []
            for i in self._issues.values():
                if i.resolved:
                    continue
                if i.state == "suppressed":
                    # Auto-lift suppression if the time window has elapsed
                    if i.suppressed_until is not None and now >= i.suppressed_until:
                        i.state = "active"
                    else:
                        continue
                result.append(i)
            return result

    def get_all(self) -> list[Issue]:
        with self._lock:
            return list(self._issues.values())

    def get(self, issue_id: str) -> Issue | None:
        with self._lock:
            return self._issues.get(issue_id)

    def resolve(self, issue_id: str) -> None:
        with self._lock:
            if issue_id in self._issues:
                self._issues[issue_id].resolved = True
                self._issues[issue_id].state = "resolved"

    def acknowledge(self, issue_id: str) -> None:
        with self._lock:
            if issue_id in self._issues:
                self._issues[issue_id].state = "acknowledged"

    def suppress(self, issue_id: str, until_ts: float | None = None) -> None:
        with self._lock:
            if issue_id in self._issues:
                self._issues[issue_id].state = "suppressed"
                self._issues[issue_id].suppressed_until = until_ts

    def mark_fixing(self, issue_id: str) -> None:
        with self._lock:
            if issue_id in self._issues:
                self._issues[issue_id].state = "fixing"

    def clear_resolved(self) -> None:
        with self._lock:
            self._issues = {k: v for k, v in self._issues.items() if not v.resolved}


# Global registry shared between daemon and Flask routes
registry = IssueRegistry()
