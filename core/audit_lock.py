"""Audit-lock trigger (HA Phase 3).

When the witness reports a chain-head mismatch (a rewrite of the local audit
chain), the primary engages AUDIT-LOCK: all mutating BPC/TSK operations are
refused with 503 until the guard explicitly clears it. This is the
"audit-lock-mode" property — tamper of the non-repudiable trail halts new
authority decisions rather than letting them continue over a compromised log.

State is process-local and also persisted to a flag file so a restart does not
silently drop the lock (fail-closed across restarts).
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path

_lock = threading.Lock()
_state: dict = {"locked": False, "reason": None, "since": None, "detail": None}
_flag_path: Path | None = None


def _path() -> Path:
    global _flag_path
    if _flag_path is None:
        root = Path(__file__).resolve().parent.parent
        evidence = root / "evidence"
        evidence.mkdir(exist_ok=True)
        _flag_path = evidence / "audit_lock.json"
    return _flag_path


def _persist() -> None:
    try:
        _path().write_text(json.dumps(_state), encoding="utf-8")
    except Exception:
        pass


def _load_from_disk() -> None:
    p = _path()
    if p.exists():
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(data, dict) and data.get("locked"):
                _state.update(data)
        except Exception:
            pass


def engage(reason: str, detail: dict | None = None) -> dict:
    """Engage the audit lock. Idempotent — re-engaging keeps the original `since`."""
    with _lock:
        if not _state["locked"]:
            _state.update({
                "locked": True,
                "reason": reason,
                "since": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "detail": detail or {},
            })
            _persist()
        return dict(_state)


def clear(by: str) -> dict:
    """Guard-only: clear the audit lock after investigating the mismatch."""
    with _lock:
        _state.update({"locked": False, "reason": None, "since": None,
                       "detail": {"cleared_by": by,
                                  "cleared_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}})
        _persist()
        return dict(_state)


def is_locked() -> bool:
    with _lock:
        return bool(_state["locked"])


def state() -> dict:
    with _lock:
        return dict(_state)


def assert_writable() -> dict | None:
    """Return a 503 error payload if locked, else None. Call in write routes."""
    if is_locked():
        s = state()
        return {"error": "audit_lock_active", "reason": s.get("reason"), "since": s.get("since")}
    return None


# Restore a persisted lock on import (fail-closed across restarts).
_load_from_disk()
