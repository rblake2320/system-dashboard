"""
fleet_evidence.py — Evidence bundle capture for fleet guard hard stops.

On hard_stop, snapshot everything relevant and write it to an evidence directory.
Evidence is forensic — it's for debugging what went wrong and for patent/proof purposes.
This module NEVER raises exceptions; all errors are caught internally.
"""

from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from secrets import token_hex
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EVIDENCE_ROOT = Path(r"C:\Users\techai\system-dashboard\evidence")

GIT_REPOS = [
    Path(r"C:\Users\techai\system-dashboard"),
    Path(r"C:\Users\techai\PKA testing"),
]

MAX_EVENTS_TAIL = 50


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _make_halt_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    rand = token_hex(2)  # 4 hex chars
    return f"{ts}_{rand}"


def _safe_write(path: Path, data: Any, errors: list[str]) -> None:
    """Write *data* as indented JSON to *path*. Append to *errors* on failure."""
    try:
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    except Exception as exc:
        errors.append(f"write {path.name}: {exc}")


def _git_snapshot(errors: list[str]) -> dict[str, str]:
    """Run 'git log --oneline -5' in each known repo dir. Returns {repo: output}."""
    result: dict[str, str] = {}
    for repo_dir in GIT_REPOS:
        key = str(repo_dir)
        try:
            if not repo_dir.is_dir():
                result[key] = "directory not found"
                continue
            proc = subprocess.run(
                ["git", "log", "--oneline", "-5"],
                cwd=repo_dir,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode == 0:
                result[key] = proc.stdout.strip() or "(no commits)"
            else:
                result[key] = f"git error: {proc.stderr.strip()}"
        except Exception as exc:
            result[key] = f"exception: {exc}"
            errors.append(f"git_snapshot {key}: {exc}")
    return result


def _collect_fleet() -> Any:
    try:
        from core.fleet_registry import get_fleet  # type: ignore[import]
        return get_fleet()
    except Exception as exc:
        return {"error": f"unavailable: {exc}"}


def _collect_metrics() -> Any:
    try:
        from core.collector import get_system_metrics  # type: ignore[import]
        return get_system_metrics()
    except Exception as exc:
        return {"error": f"unavailable: {exc}"}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def capture(
    reason: str,
    agent_name: str = "",
    metadata: dict | None = None,
    guard_state: dict | None = None,
    events_tail: list | None = None,
) -> str:
    """
    Create an evidence directory and write all forensic files.

    Parameters
    ----------
    reason : str
        Human-readable description of why the hard stop was triggered.
    agent_name : str
        Name of the agent that triggered (or was targeted by) the hard stop.
    metadata : dict, optional
        Arbitrary key/value pairs the caller wants to attach.
    guard_state : dict, optional
        Full guard state dict from the fleet guard (avoids circular import).
    events_tail : list, optional
        Last N fleet events from the in-memory deque (caller passes in).

    Returns
    -------
    str
        The halt_id string, even if some files failed to write.
    """
    if metadata is None:
        metadata = {}

    halt_id = _make_halt_id()
    ts_utc = datetime.now(timezone.utc).isoformat()
    errors: list[str] = []

    # --- Create evidence directory ---
    halt_dir = EVIDENCE_ROOT / f"halt_{halt_id}"
    try:
        halt_dir.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        # If we can't even create the directory, we still return halt_id.
        # Try a fallback in the temp dir.
        try:
            import tempfile
            halt_dir = Path(tempfile.gettempdir()) / f"fleet_evidence" / f"halt_{halt_id}"
            halt_dir.mkdir(parents=True, exist_ok=True)
            errors.append(f"primary evidence dir failed ({exc}); using fallback {halt_dir}")
        except Exception as exc2:
            # Absolute last resort: return halt_id with no files written.
            return halt_id

    # --- trigger.json ---
    trigger = {
        "halt_id": halt_id,
        "ts": ts_utc,
        "reason": reason,
        "agent_name": agent_name,
        "metadata": metadata,
    }
    _safe_write(halt_dir / "trigger.json", trigger, errors)

    # --- fleet_snapshot.json ---
    fleet = _collect_fleet()
    _safe_write(halt_dir / "fleet_snapshot.json", fleet, errors)

    # --- system_metrics.json ---
    metrics = _collect_metrics()
    _safe_write(halt_dir / "system_metrics.json", metrics, errors)

    # --- guard_state.json ---
    _safe_write(
        halt_dir / "guard_state.json",
        guard_state if guard_state is not None else {"error": "not provided"},
        errors,
    )

    # --- events_tail.json ---
    tail = events_tail[-MAX_EVENTS_TAIL:] if events_tail else []
    _safe_write(halt_dir / "events_tail.json", tail, errors)

    # --- git_snapshot.txt ---
    git_data = _git_snapshot(errors)
    try:
        lines: list[str] = []
        for repo_path, log_output in git_data.items():
            lines.append(f"=== {repo_path} ===")
            lines.append(log_output)
            lines.append("")
        (halt_dir / "git_snapshot.txt").write_text(
            "\n".join(lines), encoding="utf-8"
        )
    except Exception as exc:
        errors.append(f"write git_snapshot.txt: {exc}")

    # --- errors.txt (write last) ---
    if errors:
        try:
            (halt_dir / "errors.txt").write_text(
                "\n".join(errors), encoding="utf-8"
            )
        except Exception:
            pass  # truly nothing more we can do

    return halt_id


def list_halts() -> list[dict]:
    """
    Return a list of all evidence directories, newest first.

    Each entry is:
        {halt_id: str, ts: str, reason: str, path: str}
    """
    result: list[dict] = []

    if not EVIDENCE_ROOT.is_dir():
        return result

    for entry in EVIDENCE_ROOT.iterdir():
        if not entry.is_dir():
            continue
        if not entry.name.startswith("halt_"):
            continue

        halt_id = entry.name[len("halt_"):]
        trigger_file = entry / "trigger.json"
        ts = ""
        reason = ""

        if trigger_file.is_file():
            try:
                data = json.loads(trigger_file.read_text(encoding="utf-8"))
                ts = data.get("ts", "")
                reason = data.get("reason", "")
            except Exception:
                pass

        result.append(
            {
                "halt_id": halt_id,
                "ts": ts,
                "reason": reason,
                "path": str(entry),
            }
        )

    # Sort newest first (halt_id starts with YYYYmmdd_HHMMSS so lexicographic desc works)
    result.sort(key=lambda x: x["halt_id"], reverse=True)
    return result


def get_halt(halt_id: str) -> dict | None:
    """
    Read and return trigger.json plus a file listing for the given halt_id.

    Returns None if the halt directory does not exist.
    """
    halt_dir = EVIDENCE_ROOT / f"halt_{halt_id}"
    if not halt_dir.is_dir():
        return None

    trigger_data: dict = {}
    trigger_file = halt_dir / "trigger.json"
    if trigger_file.is_file():
        try:
            trigger_data = json.loads(trigger_file.read_text(encoding="utf-8"))
        except Exception as exc:
            trigger_data = {"error": f"could not read trigger.json: {exc}"}

    files: list[str] = []
    try:
        files = sorted(f.name for f in halt_dir.iterdir() if f.is_file())
    except Exception:
        pass

    return {
        "halt_id": halt_id,
        "path": str(halt_dir),
        "trigger": trigger_data,
        "files": files,
    }
