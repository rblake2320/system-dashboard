"""Local ownership map for BPC pair IDs.

The BPC server owns cryptographic pair state. This module adds local dashboard
context: who/what a pair was generated for, which mode it belongs to, and which
agent birth ID it maps to when applicable.
"""
from __future__ import annotations

import platform
import sqlite3
import time
from pathlib import Path
from typing import Any

_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "bpc_owners.db"


def _conn() -> sqlite3.Connection:
    _DB_PATH.parent.mkdir(exist_ok=True)
    db = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
    db.row_factory = sqlite3.Row
    db.execute("""
        CREATE TABLE IF NOT EXISTS bpc_pair_owners (
            pair_id     TEXT PRIMARY KEY,
            name        TEXT NOT NULL DEFAULT '',
            role        TEXT NOT NULL DEFAULT '',
            machine     TEXT NOT NULL DEFAULT '',
            profile     TEXT NOT NULL DEFAULT '',
            created_by  TEXT NOT NULL DEFAULT '',
            birth_id    TEXT NOT NULL DEFAULT '',
            created_at  REAL NOT NULL
        )
    """)
    db.commit()
    return db


def record_owner(
    pair_id: str,
    *,
    name: str = "",
    role: str = "",
    machine: str = "",
    profile: str = "",
    created_by: str = "dashboard",
    birth_id: str = "",
) -> dict[str, Any]:
    pair_id = str(pair_id or "").strip()
    if not pair_id:
        raise ValueError("pair_id is required")
    now = time.time()
    owner = {
        "pair_id": pair_id,
        "name": str(name or "")[:100],
        "role": str(role or "")[:80],
        "machine": str(machine or platform.node() or "")[:120],
        "profile": str(profile or "")[:32],
        "created_by": str(created_by or "dashboard")[:80],
        "birth_id": str(birth_id or "")[:80],
        "created_at": now,
    }
    db = _conn()
    db.execute(
        """
        INSERT INTO bpc_pair_owners
            (pair_id, name, role, machine, profile, created_by, birth_id, created_at)
        VALUES
            (:pair_id, :name, :role, :machine, :profile, :created_by, :birth_id, :created_at)
        ON CONFLICT(pair_id) DO UPDATE SET
            name=excluded.name,
            role=excluded.role,
            machine=excluded.machine,
            profile=excluded.profile,
            created_by=excluded.created_by,
            birth_id=excluded.birth_id
        """,
        owner,
    )
    db.commit()
    db.close()
    return owner


def get_owner(pair_id: str) -> dict[str, Any] | None:
    db = _conn()
    row = db.execute(
        "SELECT * FROM bpc_pair_owners WHERE pair_id=?",
        (str(pair_id or "").strip(),),
    ).fetchone()
    db.close()
    return dict(row) if row else None


def list_owners() -> dict[str, dict[str, Any]]:
    db = _conn()
    rows = db.execute("SELECT * FROM bpc_pair_owners ORDER BY created_at DESC").fetchall()
    db.close()
    return {row["pair_id"]: dict(row) for row in rows}


def annotate_pairs(pairs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    owners = list_owners()
    annotated = []
    for pair in pairs:
        item = dict(pair)
        owner = owners.get(str(pair.get("id") or pair.get("pairId") or ""))
        if owner:
            item["owner"] = owner
        annotated.append(item)
    return annotated
