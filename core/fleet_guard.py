"""
fleet_guard.py — Alert evaluation engine for the AI agent fleet auto-halt system.

Evaluates alert rules every 5 seconds. Sets a guard state that the orchestrator
polls to decide whether to continue, pause, or hard-stop.

Does NOT kill any processes. Does NOT modify agents. Only sets state and triggers
evidence capture.
"""
from __future__ import annotations

import threading
import time
import uuid
from typing import Any

# ── Thresholds (can be overridden by caller before start_watcher()) ───────────

RAM_HALT_GB: float = 25.0          # free RAM below this → halt_recommended
VRAM_HALT_GB: float = 6.0          # free VRAM below this → halt_recommended (local model only)
HEARTBEAT_TIMEOUT_S: float = 90.0  # seconds without heartbeat = missed ACK
HARD_STOP_BLOCKED_COUNT: int = 2   # number of blocked agents before hard_stop

# ── Guard state constants ─────────────────────────────────────────────────────

STATE_OK = "ok"
STATE_HALT_RECOMMENDED = "halt_recommended"
STATE_DEGRADED = "degraded"
STATE_BLOCKED = "blocked"
STATE_HARD_STOP = "hard_stop"

# Immediate hard-stop event types
_IMMEDIATE_HARD_STOP_EVENTS = frozenset({
    "wrong_window_guard_failure",
    "wrong_nonce",
    "wrong_hash",
    "wrong_sender",
})

# ── Optional evidence module ──────────────────────────────────────────────────

try:
    from core import fleet_evidence as _ev  # type: ignore
except Exception:
    _ev = None  # type: ignore

# ── Internal shared state ─────────────────────────────────────────────────────

_lock = threading.Lock()

# Current guard state
_state: str = STATE_OK
_reason: str = ""
_halt_id: str | None = None
_checked_at: float = time.time()
_local_model_mode: bool = False

# Ordered list of active alert dicts: [{type, agent, ts, detail}]
_active_alerts: list[dict] = []

# Per-agent ACK state
# {agent_name: {missed_acks, narration_violations, degraded, blocked}}
_agent_flags: dict[str, dict] = {}

# Watcher thread control
_watcher_thread: threading.Thread | None = None
_watcher_started: bool = False

# ── Helpers ───────────────────────────────────────────────────────────────────


def _get_or_create_agent_flags(name: str) -> dict:
    """Return (creating if needed) the mutable flags dict for an agent.
    Caller MUST hold _lock.
    """
    if name not in _agent_flags:
        _agent_flags[name] = {
            "missed_acks": 0,
            "narration_violations": 0,
            "degraded": False,
            "blocked": False,
        }
    return _agent_flags[name]


def _add_alert(event_type: str, agent: str, detail: str = "") -> None:
    """Append to _active_alerts. Caller MUST hold _lock."""
    _active_alerts.append({
        "type": event_type,
        "agent": agent,
        "ts": time.time(),
        "detail": detail,
    })


def _trigger_evidence(reason: str, agent_name: str, metadata: dict) -> str | None:
    """Call fleet_evidence.capture() if available. Returns halt_id or None."""
    if _ev is not None:
        try:
            return _ev.capture(reason, agent_name, metadata)
        except Exception:
            pass
    return str(uuid.uuid4())


def _evaluate_state() -> None:
    """Re-evaluate guard state from current flags and alerts.
    Caller MUST hold _lock.
    This is the single authoritative escalation logic — called after every
    mutation so the state is always consistent.

    Escalation order (highest severity wins):
      1. Immediate hard-stop events in active_alerts → hard_stop
      2. Blocked agent count > HARD_STOP_BLOCKED_COUNT → hard_stop
      3. Any blocked agents → blocked
      4. Any degraded agents → degraded
      5. RAM < RAM_HALT_GB while fleet active → halt_recommended
      6. VRAM < VRAM_HALT_GB while local_model_mode → halt_recommended
      7. Otherwise → ok

    Once hard_stop is set it is sticky until resume() is called.
    """
    global _state, _reason, _halt_id

    # Sticky hard_stop — never auto-downgrade
    if _state == STATE_HARD_STOP:
        return

    # Gather resource metrics (non-blocking, best-effort)
    try:
        from core.collector import get_system_metrics  # type: ignore
        metrics = get_system_metrics()
    except Exception:
        metrics = {}

    try:
        from core.fleet_registry import get_fleet  # type: ignore
        fleet = get_fleet()
    except Exception:
        fleet = []

    active_agents = [a for a in fleet if a["status"] not in ("done", "crashed")]
    fleet_active = len(active_agents) > 0

    # ── Step 0.5: Narration violation threshold (≥2 per agent → hard_stop) ──────
    for agent_name, flags in _agent_flags.items():
        if flags.get("narration_violations", 0) >= 2:
            new_reason = (
                f"Security event: local_narration_violation from agent '{agent_name}' "
                f"(count={flags['narration_violations']})"
            )
            if _state != STATE_HARD_STOP:
                halt_id = _trigger_evidence(new_reason, agent_name, {"flags": flags})
                _state = STATE_HARD_STOP
                _reason = new_reason
                _halt_id = halt_id
            return

    # ── Step 1: Immediate hard-stop events ───────────────────────────────────
    for alert in _active_alerts:
        if alert["type"] in _IMMEDIATE_HARD_STOP_EVENTS:
            new_reason = f"Security event: {alert['type']} from agent '{alert['agent']}'"
            if _state != STATE_HARD_STOP:
                halt_id = _trigger_evidence(new_reason, alert["agent"], {"alert": alert})
                _state = STATE_HARD_STOP
                _reason = new_reason
                _halt_id = halt_id
            return

    # ── Step 2 & 3: Blocked agent counts ─────────────────────────────────────
    blocked_agents = [n for n, f in _agent_flags.items() if f["blocked"]]
    degraded_agents = [n for n, f in _agent_flags.items() if f["degraded"] and not f["blocked"]]

    if len(blocked_agents) > HARD_STOP_BLOCKED_COUNT:
        new_reason = (
            f"{len(blocked_agents)} agents blocked (threshold {HARD_STOP_BLOCKED_COUNT}): "
            + ", ".join(blocked_agents)
        )
        if _state != STATE_HARD_STOP:
            halt_id = _trigger_evidence(new_reason, "", {"blocked": blocked_agents})
            _state = STATE_HARD_STOP
            _reason = new_reason
            _halt_id = halt_id
        return

    if blocked_agents:
        _state = STATE_BLOCKED
        _reason = f"Agent(s) blocked (missed heartbeat ≥2): {', '.join(blocked_agents)}"
        return

    # ── Step 4: Degraded ─────────────────────────────────────────────────────
    if degraded_agents:
        _state = STATE_DEGRADED
        _reason = f"Agent(s) missed one heartbeat: {', '.join(degraded_agents)}"
        return

    # ── Step 5 & 6: Resource pressure ────────────────────────────────────────
    if fleet_active:
        ram_avail = metrics.get("ram_avail_gb")
        if ram_avail is None:
            # Fallback key used in get_system_metrics
            ram_avail = metrics.get("ram", {}).get("available_gb")
        if ram_avail is not None and ram_avail < RAM_HALT_GB:
            _state = STATE_HALT_RECOMMENDED
            _reason = f"Free RAM {ram_avail:.1f} GB below threshold {RAM_HALT_GB} GB"
            return

    if _local_model_mode:
        gpus: list[dict] = metrics.get("gpus", [])
        if gpus:
            # Use GPU 0 (primary); sum if multiple local inference GPUs
            vram_free_gb = None
            for gpu in gpus:
                total_mb = gpu.get("mem_total_mb", 0)
                used_mb = gpu.get("mem_used_mb", 0)
                free_mb = (total_mb - used_mb) if (total_mb and used_mb is not None) else None
                if free_mb is not None:
                    free_gb = free_mb / 1024.0
                    if vram_free_gb is None:
                        vram_free_gb = free_gb
                    else:
                        vram_free_gb = min(vram_free_gb, free_gb)  # most constrained GPU
            if vram_free_gb is not None and vram_free_gb < VRAM_HALT_GB:
                _state = STATE_HALT_RECOMMENDED
                _reason = (
                    f"Free VRAM {vram_free_gb:.1f} GB below threshold "
                    f"{VRAM_HALT_GB} GB (local model mode)"
                )
                return

    # ── All clear ─────────────────────────────────────────────────────────────
    _state = STATE_OK
    _reason = ""


# ── Heartbeat timeout detection (called from _eval_loop every 5s) ─────────────


def _check_heartbeats() -> None:
    """Scan active agents for missed heartbeats.  Caller MUST hold _lock."""
    try:
        from core.fleet_registry import get_fleet  # type: ignore
        fleet = get_fleet()
    except Exception:
        return

    now = time.time()
    for agent in fleet:
        if agent["status"] in ("done", "crashed"):
            continue
        name = agent["name"]
        last_hb = agent.get("last_heartbeat_ts", now)
        time_since_hb = now - last_hb

        flags = _get_or_create_agent_flags(name)

        if time_since_hb > HEARTBEAT_TIMEOUT_S:
            flags["missed_acks"] += 1
            if flags["missed_acks"] >= 2:
                if not flags["blocked"]:
                    flags["blocked"] = True
                    _add_alert("missed_ack", name,
                               f"missed_acks={flags['missed_acks']}, blocked")
            elif flags["missed_acks"] == 1:
                if not flags["degraded"]:
                    flags["degraded"] = True
                    _add_alert("missed_ack", name,
                               f"missed_acks={flags['missed_acks']}, degraded")
        else:
            # Heartbeat resumed — clear flags
            if flags["missed_acks"] > 0 or flags["degraded"] or flags["blocked"]:
                flags["missed_acks"] = 0
                flags["degraded"] = False
                flags["blocked"] = False


# ── Background evaluation loop ────────────────────────────────────────────────


def _eval_loop() -> None:
    """Runs every 5 seconds: check heartbeats then re-evaluate state."""
    while True:
        try:
            time.sleep(5)
            with _lock:
                global _checked_at
                _check_heartbeats()
                _evaluate_state()
                _checked_at = time.time()
        except Exception:
            # Never let the background thread die
            pass


# ── Public API ────────────────────────────────────────────────────────────────


def start_watcher() -> None:
    """Start the background evaluation thread. Idempotent — safe to call multiple times."""
    global _watcher_thread, _watcher_started
    with _lock:
        if _watcher_started:
            return
        _watcher_started = True

    _watcher_thread = threading.Thread(
        target=_eval_loop,
        name="fleet-guard-watcher",
        daemon=True,
    )
    _watcher_thread.start()


def record_event(
    event_type: str,
    agent_name: str = "",
    metadata: dict | None = None,
) -> None:
    """Record a security / protocol event and immediately re-evaluate guard state.

    Called by /api/fleet/event endpoint.

    Args:
        event_type: One of the recognised security event type strings.
        agent_name: The agent that triggered the event (may be empty).
        metadata:   Arbitrary detail dict stored with the alert.
    """
    if metadata is None:
        metadata = {}

    with _lock:
        global _checked_at

        if event_type == "missed_ack":
            # Explicit missed_ack event (separate from heartbeat polling)
            flags = _get_or_create_agent_flags(agent_name)
            flags["missed_acks"] += 1
            if flags["missed_acks"] >= 2:
                flags["blocked"] = True
                _add_alert(event_type, agent_name,
                           f"missed_acks={flags['missed_acks']}, blocked")
            else:
                flags["degraded"] = True
                _add_alert(event_type, agent_name,
                           f"missed_acks={flags['missed_acks']}, degraded")

        elif event_type == "local_narration_violation":
            flags = _get_or_create_agent_flags(agent_name)
            flags["narration_violations"] += 1
            detail = f"narration_violations={flags['narration_violations']}"
            _add_alert(event_type, agent_name, detail)
            if flags["narration_violations"] >= 2:
                # Escalate to hard_stop immediately without waiting for _evaluate_state
                # (will be confirmed by _evaluate_state via active_alerts path below)
                pass  # handled by _evaluate_state via immediate path

        else:
            # All other event types are stored as alerts; immediate ones trigger hard_stop
            _add_alert(event_type, agent_name, str(metadata))

        _evaluate_state()
        _checked_at = time.time()


def get_guard_state() -> dict[str, Any]:
    """Return the current guard state snapshot.

    Returns:
        {
          "state": str,
          "reason": str,
          "halt_id": str | None,
          "active_alerts": list[dict],
          "agent_flags": dict,
          "local_model_mode": bool,
          "checked_at": float,
        }
    """
    with _lock:
        return {
            "state": _state,
            "reason": _reason,
            "halt_id": _halt_id,
            "active_alerts": list(_active_alerts),  # shallow copy for safety
            "agent_flags": {
                name: dict(flags) for name, flags in _agent_flags.items()
            },
            "local_model_mode": _local_model_mode,
            "checked_at": _checked_at,
        }


def resume(operator_note: str = "") -> None:
    """Reset guard state to 'ok'. Clears all flags, alerts, and halt_id.

    This is the only way to exit STATE_HARD_STOP.
    Logs the resume event to the audit log if available.

    Args:
        operator_note: Optional human-readable explanation for the resume.
    """
    global _state, _reason, _halt_id, _active_alerts, _agent_flags, _checked_at

    with _lock:
        prev_state = _state
        prev_halt_id = _halt_id

        _state = STATE_OK
        _reason = ""
        _halt_id = None
        _active_alerts = []
        _agent_flags = {}
        _checked_at = time.time()

    # Log outside the lock (audit_log is thread-safe internally)
    try:
        from core.audit import log_action  # type: ignore
        log_action(
            action="fleet_guard_resume",
            params={
                "prev_state": prev_state,
                "prev_halt_id": prev_halt_id,
                "operator_note": operator_note,
            },
            ip="system",
            result="ok",
        )
    except Exception:
        pass


def set_local_model_mode(active: bool) -> None:
    """Enable or disable VRAM threshold checking.

    Call with active=True when Ollama / local inference is running so that
    fleet_guard will also monitor VRAM headroom.

    Args:
        active: True = local model is running; False = cloud-only mode.
    """
    global _local_model_mode
    with _lock:
        _local_model_mode = active
        # Re-evaluate immediately so VRAM state is reflected without waiting 5s
        _evaluate_state()
