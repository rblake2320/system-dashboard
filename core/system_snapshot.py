"""Canonical, versioned system snapshot shared by Status, Review, and Export."""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable

from core import collector
from core import issues as issue_mod
from core import fleet_guard
from core import fleet_registry
from core.bpc_monitor import get_governance
from core.key_monitor import check_all_keys
from core.memoryweb_monitor import get_status as get_memoryweb_status
from core.mesh_monitor import get_mesh_status
from core.persistence import db

SCHEMA_VERSION = "1.0"
DASHBOARD_VERSION = "2.1.0"
SCORE_VERSION = "1.0"
REQUIRED_SECTIONS = frozenset({
    "snapshot_id",
    "generated_at",
    "system",
    "processes",
    "ports",
    "issues",
    "health_score",
    "fleet",
    "fleet_guard",
    "governance",
    "keys",
    "mesh",
    "memoryweb",
    "daemon",
    "components",
})

_lock = threading.RLock()
_latest: dict[str, Any] | None = None
_latest_ts = 0.0
_CACHE_TTL_SECONDS = 10.0
_repo_root = Path(__file__).resolve().parent.parent


def compute_health_score(issues: list[dict]) -> int:
    """100 minus 20 per critical and 5 per warning."""
    score = 100
    for issue in issues:
        severity = issue.get("severity", "")
        if severity == "critical":
            score -= 20
        elif severity == "warning":
            score -= 5
    return max(0, score)


def _app_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=_repo_root,
            text=True,
            timeout=2,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def _component(
    name: str,
    loader: Callable[[], Any],
    *,
    disabled_when: Callable[[Any], bool] | None = None,
) -> tuple[Any, dict]:
    checked_at = dt.datetime.now(dt.timezone.utc).isoformat()
    try:
        data = loader()
        disabled = bool(disabled_when and disabled_when(data))
        status = "disabled" if disabled else "ok"
        if isinstance(data, dict):
            if data.get("connected") is False or data.get("reachable") is False:
                status = "unavailable"
            if data.get("status") in ("unreachable", "offline"):
                status = "unavailable"
        return data, {
            "name": name,
            "status": status,
            "checked_at": checked_at,
            "error": None,
        }
    except Exception as exc:
        return {}, {
            "name": name,
            "status": "unavailable",
            "checked_at": checked_at,
            "error": str(exc)[:200],
        }


def _load_history(snapshot: dict) -> None:
    if snapshot.get("history"):
        return
    snapshot["history"] = {}
    for metric in ("cpu_pct", "ram_pct", "gpu0_pct", "gpu0_mem_pct"):
        rows = db.get_metric_history(metric, limit=60)
        if rows:
            rows.reverse()
            snapshot["history"][metric] = [row["value"] for row in rows]


def _current_issues(snapshot: dict) -> tuple[list[dict], list[dict]]:
    """Return immediate conditions plus the separate lifecycle-registry view."""
    detected = issue_mod.detect_issues(snapshot)
    issue_mod.registry.update(detected)
    registry_by_id = {
        issue.id: issue.as_dict() for issue in issue_mod.registry.get_active()
    }
    current: list[dict] = []
    for issue in detected:
        item = issue.as_dict()
        lifecycle = registry_by_id.get(issue.id)
        if lifecycle:
            item["state"] = lifecycle.get("state", item.get("state"))
            item["detected_at"] = lifecycle.get("detected_at", item.get("detected_at"))
        current.append(item)
    return current, list(registry_by_id.values())


def validate_snapshot(snapshot: dict) -> dict:
    missing = sorted(REQUIRED_SECTIONS - set(snapshot))
    component_failures = sorted(
        name
        for name, state in snapshot.get("components", {}).items()
        if state.get("status") == "unavailable"
    )
    status = "invalid" if missing else ("partial" if component_failures else "complete")
    return {
        "status": status,
        "schema_valid": not missing,
        "missing_sections": missing,
        "unavailable_components": component_failures,
        "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }


def _hash_snapshot(snapshot: dict) -> str:
    payload = copy.deepcopy(snapshot)
    payload.pop("evidence_hash", None)
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_system_snapshot(
    *,
    freshness: str = "cached",
    reason: str = "status",
) -> dict:
    """Build or reuse the one authoritative dashboard snapshot."""
    global _latest, _latest_ts
    if freshness not in {"cached", "fresh"}:
        raise ValueError("freshness must be 'cached' or 'fresh'")

    with _lock:
        if (
            freshness == "cached"
            and _latest is not None
            and time.time() - _latest_ts < _CACHE_TTL_SECONDS
        ):
            return copy.deepcopy(_latest)

    from daemon.monitor import alert_history, daemon

    if freshness == "fresh":
        snapshot = collector.build_snapshot()
        source = "collector"
    else:
        snapshot = daemon.latest() or collector.build_snapshot()
        source = "daemon" if daemon.latest() else "collector"
    snapshot = copy.deepcopy(snapshot)
    _load_history(snapshot)

    issues, registry_issues = _current_issues(snapshot)
    fleet, fleet_meta = _component("fleet", fleet_registry.get_fleet)
    guard, guard_meta = _component("fleet_guard", fleet_guard.get_guard_state)
    governance, governance_meta = _component(
        "governance",
        lambda: get_governance(force=freshness == "fresh"),
        disabled_when=lambda data: data.get("enabled") is False,
    )
    keys, keys_meta = _component(
        "keys", lambda: check_all_keys(force=freshness == "fresh")
    )
    mesh, mesh_meta = _component(
        "mesh", lambda: get_mesh_status(force=freshness == "fresh")
    )
    memoryweb, memoryweb_meta = _component(
        "memoryweb", lambda: get_memoryweb_status(force=freshness == "fresh")
    )

    generated_at = dt.datetime.now(dt.timezone.utc).isoformat()
    snapshot.update({
        "snapshot_id": str(uuid.uuid4()),
        "schema_version": SCHEMA_VERSION,
        "dashboard_version": DASHBOARD_VERSION,
        "app_commit": _app_commit(),
        "generated_at": generated_at,
        "snapshot_reason": reason,
        "snapshot_source": source,
        "issues": issues,
        "issue_registry": registry_issues,
        "alert_history": alert_history.get(50),
        "health_score": compute_health_score(issues),
        "score_version": SCORE_VERSION,
        "fleet": fleet,
        "fleet_guard": guard,
        "governance": governance,
        "keys": keys,
        "mesh": mesh,
        "memoryweb": memoryweb,
        "daemon": {
            "alive": not daemon.is_stale,
            "last_tick_ts": daemon._last_tick_ts,
        },
        # Legacy flat fields retained for the existing UI.
        "daemon_alive": not daemon.is_stale,
        "last_tick_ts": daemon._last_tick_ts,
        "components": {
            "fleet": fleet_meta,
            "fleet_guard": guard_meta,
            "governance": governance_meta,
            "keys": keys_meta,
            "mesh": mesh_meta,
            "memoryweb": memoryweb_meta,
        },
    })
    snapshot["score_inputs_hash"] = hashlib.sha256(
        json.dumps(issues, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
    snapshot["evidence_integrity"] = validate_snapshot(snapshot)
    snapshot["evidence_hash"] = _hash_snapshot(snapshot)

    with _lock:
        _latest = copy.deepcopy(snapshot)
        _latest_ts = time.time()
    return snapshot


def latest_system_snapshot(*, reason: str = "export") -> dict:
    """Return the exact most-recent canonical snapshot, building one if absent."""
    global _latest
    with _lock:
        if _latest is not None:
            return copy.deepcopy(_latest)
    return build_system_snapshot(freshness="fresh", reason=reason)


def reset_cache() -> None:
    """Test/support hook."""
    global _latest, _latest_ts
    with _lock:
        _latest = None
        _latest_ts = 0.0
