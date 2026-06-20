"""Claude Code session context-burn monitor.

Reads JSONL transcripts from ~/.claude/projects/ and computes per-session
context utilization and token burn rate.

Every threshold crossing is written to core/audit.py as a timestamped event —
this is the patent-evidence trail for proactive context-pressure detection.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

# --- constants ----------------------------------------------------------------

_CONTEXT_WINDOW = 200_000          # Sonnet/Opus/Haiku 4.x all use 200K
_SCAN_LOOKBACK_S = 86_400          # only scan sessions active in last 24 h
_TAIL_BYTES = 600_000              # last 600 KB of each JSONL to parse
_BURN_WINDOW = 5                   # number of recent turns to compute burn rate

# Thresholds that trigger audit events (% of context window)
_THRESHOLDS = [70, 85, 95]

# Track which (session_id, threshold) pairs we have already logged this process
# so we don't flood the audit log on every poll cycle.
_LOGGED: set[tuple[str, int]] = set()


def scan_sessions() -> list[dict]:
    """Return a list of session dicts for sessions active in the last 24 hours."""
    claude_dir = Path.home() / ".claude" / "projects"
    if not claude_dir.exists():
        return []

    results = []
    now = time.time()

    for jsonl_path in sorted(claude_dir.rglob("*.jsonl"), key=lambda p: -p.stat().st_mtime):
        try:
            mtime = jsonl_path.stat().st_mtime
        except OSError:
            continue
        if now - mtime > _SCAN_LOOKBACK_S:
            continue

        session = _analyze(jsonl_path, mtime)
        if session:
            results.append(session)

    return results[:20]   # cap at 20 to avoid UI sprawl


def _analyze(path: Path, mtime: float) -> dict | None:
    """Parse a JSONL file and return context-burn metrics."""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            fh.seek(max(0, size - _TAIL_BYTES))
            raw = fh.read().decode("utf-8", errors="replace")
    except OSError:
        return None

    turns: list[dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("type") != "assistant":
            continue
        usage = {}
        msg = obj.get("message")
        if isinstance(msg, dict):
            usage = msg.get("usage", {})
        elif isinstance(obj.get("usage"), dict):
            usage = obj["usage"]
        if not usage:
            continue
        ts = obj.get("timestamp", 0) or mtime
        turns.append({
            "ts": float(ts) if isinstance(ts, (int, float)) else mtime,
            "input":        usage.get("input_tokens", 0),
            "cache_read":   usage.get("cache_read_input_tokens", 0),
            "cache_create": usage.get("cache_creation_input_tokens", 0),
            "output":       usage.get("output_tokens", 0),
        })

    if not turns:
        return None

    last = turns[-1]
    # Context the model "sees": accumulated cache + live input
    context_used = last["cache_read"] + last["cache_create"] + last["input"]
    utilization_pct = min(100.0, context_used / _CONTEXT_WINDOW * 100)

    # Burn rate: tokens/minute over the last _BURN_WINDOW turns
    burn_rate_tpm = 0.0
    if len(turns) >= 2:
        window = turns[-_BURN_WINDOW:]
        elapsed = (window[-1]["ts"] - window[0]["ts"]) / 60.0
        tokens_added = sum(t["cache_create"] + t["output"] for t in window)
        if elapsed > 0:
            burn_rate_tpm = tokens_added / elapsed

    session_id = path.stem
    slug = path.parent.name if path.parent.name != "projects" else session_id

    session = {
        "session_id": session_id,
        "slug": slug,
        "path": str(path),
        "last_activity_ts": last["ts"],
        "context_used_tokens": context_used,
        "context_window_tokens": _CONTEXT_WINDOW,
        "utilization_pct": round(utilization_pct, 1),
        "burn_rate_tpm": round(burn_rate_tpm, 1),
        "output_tokens_total": sum(t["output"] for t in turns),
        "turn_count": len(turns),
    }

    _maybe_log_thresholds(session)
    return session


def _maybe_log_thresholds(session: dict) -> None:
    """Write audit events when context utilization crosses defined thresholds."""
    try:
        from core.audit import log_action
    except ImportError:
        return

    sid = session["session_id"]
    pct = session["utilization_pct"]

    for threshold in _THRESHOLDS:
        key = (sid, threshold)
        if pct >= threshold and key not in _LOGGED:
            _LOGGED.add(key)
            severity = "critical" if threshold >= 95 else ("warning" if threshold >= 85 else "info")
            log_action(
                "session_monitor",
                "context_threshold_crossed",
                {
                    "session_id": sid,
                    "slug": session["slug"],
                    "context_used_tokens": session["context_used_tokens"],
                    "context_window_tokens": session["context_window_tokens"],
                    "utilization_pct": pct,
                    "burn_rate_tpm": session["burn_rate_tpm"],
                    "threshold_pct": threshold,
                    "severity": severity,
                    "compaction_likely": pct >= 95,
                },
            )
        elif pct < threshold and key in _LOGGED:
            # New session (context reset) — clear the logged set so it fires again
            _LOGGED.discard(key)
