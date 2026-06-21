"""Hash-chained BPC audit log.

Each entry is SHA-256 chained to the previous one over a canonical payload:
  entry_hash = SHA-256(json({prev_hash, ts, action, pair_id, operator, meta}))

Stored as NDJSON at evidence/bpc_audit_chain.ndjson (relative to _ROOT).
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Any

_GENESIS_HASH = "0" * 64
_lock = threading.Lock()
_chain_path: Path | None = None


def _path() -> Path:
    global _chain_path
    if _chain_path is None:
        from pathlib import Path as _P
        root = _P(__file__).resolve().parent.parent
        evidence = root / "evidence"
        evidence.mkdir(exist_ok=True)
        _chain_path = evidence / "bpc_audit_chain.ndjson"
    return _chain_path


def _last_hash() -> str:
    p = _path()
    if not p.exists():
        return _GENESIS_HASH
    try:
        raw = p.read_bytes()
        last_line = raw.rstrip(b"\n").rsplit(b"\n", 1)[-1].strip()
        if not last_line:
            return _GENESIS_HASH
        entry = json.loads(last_line)
        return entry.get("entry_hash", _GENESIS_HASH)
    except Exception:
        return _GENESIS_HASH


def _compute_hash(
    prev_hash: str,
    ts: str,
    action: str,
    pair_id: str,
    operator: str,
    metadata: dict[str, Any] | None = None,
) -> str:
    payload = {
        "prev_hash": prev_hash,
        "ts": ts,
        "action": action,
        "pair_id": pair_id,
        "operator": operator,
        "meta": metadata or {},
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def append(action: str, pair_id: str, operator: str = "dashboard",
           metadata: dict | None = None) -> dict:
    """Append a chained entry. Returns the entry written."""
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with _lock:
        prev = _last_hash()
        entry = {
            "ts": ts,
            "action": action,
            "pair_id": pair_id,
            "operator": operator,
            "prev_hash": prev,
        }
        if metadata:
            entry["meta"] = metadata
        entry["entry_hash"] = _compute_hash(
            prev,
            ts,
            action,
            pair_id,
            operator,
            metadata,
        )
        with open(_path(), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


def tail(n: int = 20) -> list[dict]:
    """Return the last n entries from the chain."""
    p = _path()
    if not p.exists():
        return []
    try:
        size = p.stat().st_size
        with open(p, "rb") as fh:
            fh.seek(max(0, size - 32_000))
            raw = fh.read().decode("utf-8", errors="replace")
        entries = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return entries[-n:]
    except Exception:
        return []


def verify_chain(max_entries: int | None = None) -> dict:
    """Walk the full chain and report tampering.

    ``max_entries`` is accepted for backward compatibility but verification
    always starts at genesis. Verifying only a tail window would hide deleted or
    reordered earlier entries and can create false failures when the tail's
    first entry does not point at genesis.
    """
    p = _path()
    if not p.exists():
        return {"ok": True, "checked": 0}
    prev_hash = _GENESIS_HASH
    checked = 0
    with open(p, encoding="utf-8") as fh:
        lines = list(fh)
    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return {"ok": False, "broken_at": i, "checked": checked + 1, "reason": "invalid_json"}
        expected = _compute_hash(
            entry.get("prev_hash", ""),
            entry.get("ts", ""),
            entry.get("action", ""),
            entry.get("pair_id", ""),
            entry.get("operator", ""),
            entry.get("meta") or {},
        )
        if entry.get("entry_hash") != expected:
            return {
                "ok": False,
                "broken_at": i,
                "checked": checked + 1,
                "reason": "entry_hash_mismatch",
                "entry": entry,
            }
        if entry.get("prev_hash") != prev_hash:
            return {
                "ok": False,
                "broken_at": i,
                "checked": checked + 1,
                "reason": "prev_hash_mismatch",
            }
        prev_hash = entry["entry_hash"]
        checked += 1
    return {"ok": True, "checked": checked}
