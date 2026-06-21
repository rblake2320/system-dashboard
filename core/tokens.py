"""Dashboard API token management — SQLite-backed, scoped, trackable.

Tokens are generated here and can be used by any external caller
(AI Army nodes, scripts, agent harnesses) to call dashboard API endpoints
via the X-Dashboard-Token header. Each call is logged with timestamp.

The raw token is shown ONCE at creation. Only the SHA-256 hash is stored.
"""
from __future__ import annotations

import hashlib
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any

_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "tokens.db"

_SCOPES = {
    "read":  "Read-only: /api/status, /api/sessions, /api/memoryweb, /api/keys",
    "write": "Read + acknowledge issues, kill PIDs, set keys",
    "admin": "Full access including token management",
}


def _conn() -> sqlite3.Connection:
    _DB_PATH.parent.mkdir(exist_ok=True)
    db = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("""
        CREATE TABLE IF NOT EXISTS tokens (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            hash        TEXT NOT NULL,
            scope       TEXT NOT NULL DEFAULT 'read',
            created_at  REAL NOT NULL,
            last_used_at REAL,
            use_count   INTEGER NOT NULL DEFAULT 0,
            revoked     INTEGER NOT NULL DEFAULT 0
        )
    """)
    db.commit()
    return db


def create_token(name: str, scope: str = "read") -> dict[str, Any]:
    """Generate a new token. Returns dict including the raw value (shown ONCE)."""
    if scope not in _SCOPES:
        scope = "read"
    raw = "dtok_" + secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    token_id = "tid_" + secrets.token_hex(8)
    now = time.time()
    db = _conn()
    db.execute(
        "INSERT INTO tokens (id, name, hash, scope, created_at) VALUES (?,?,?,?,?)",
        (token_id, name.strip()[:80], token_hash, scope, now),
    )
    db.commit()
    db.close()
    return {
        "id": token_id,
        "name": name,
        "scope": scope,
        "scope_description": _SCOPES[scope],
        "created_at": now,
        "raw": raw,  # shown once — not stored
    }


def list_tokens() -> list[dict[str, Any]]:
    """Return all tokens (without hash or raw value)."""
    db = _conn()
    rows = db.execute(
        "SELECT id, name, scope, created_at, last_used_at, use_count, revoked FROM tokens ORDER BY created_at DESC"
    ).fetchall()
    db.close()
    return [dict(r) for r in rows]


def validate_token(raw: str) -> dict[str, Any] | None:
    """Check a raw token. Returns token row if valid and not revoked, else None."""
    if not raw or not raw.startswith("dtok_"):
        return None
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    db = _conn()
    row = db.execute(
        "SELECT id, name, scope, revoked FROM tokens WHERE hash=?", (token_hash,)
    ).fetchone()
    if row and not row["revoked"]:
        db.execute(
            "UPDATE tokens SET last_used_at=?, use_count=use_count+1 WHERE id=?",
            (time.time(), row["id"]),
        )
        db.commit()
        db.close()
        return dict(row)
    db.close()
    return None


def revoke_token(token_id: str) -> bool:
    """Mark a token as revoked. Returns True if found."""
    db = _conn()
    cur = db.execute("UPDATE tokens SET revoked=1 WHERE id=?", (token_id,))
    db.commit()
    db.close()
    return cur.rowcount > 0


def delete_token(token_id: str) -> bool:
    """Permanently delete a token record."""
    db = _conn()
    cur = db.execute("DELETE FROM tokens WHERE id=?", (token_id,))
    db.commit()
    db.close()
    return cur.rowcount > 0


SCOPES = _SCOPES
