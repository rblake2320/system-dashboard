"""Tests for the BPC hash-chained audit log."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import bpc_audit_chain as chain


def _use_tmp_chain(monkeypatch, tmp_path: Path) -> Path:
    path = tmp_path / "bpc_audit_chain.ndjson"
    monkeypatch.setattr(chain, "_chain_path", path)
    return path


def _read_entries(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _write_entries(path: Path, entries: list[dict]) -> None:
    path.write_text(
        "\n".join(json.dumps(entry, sort_keys=True) for entry in entries) + "\n",
        encoding="utf-8",
    )


def test_verify_chain_accepts_valid_entries(monkeypatch, tmp_path):
    _use_tmp_chain(monkeypatch, tmp_path)

    chain.append("generate", "pair-1", metadata={"scope": "read"})
    chain.append("revoke", "pair-1")

    result = chain.verify_chain()

    assert result == {"ok": True, "checked": 2}


def test_verify_chain_detects_metadata_tamper(monkeypatch, tmp_path):
    path = _use_tmp_chain(monkeypatch, tmp_path)
    chain.append("generate", "pair-1", metadata={"scope": "read"})

    entries = _read_entries(path)
    entries[0]["meta"]["scope"] = "admin"
    _write_entries(path, entries)

    result = chain.verify_chain()

    assert result["ok"] is False
    assert result["reason"] == "entry_hash_mismatch"


def test_verify_chain_detects_deleted_entry(monkeypatch, tmp_path):
    path = _use_tmp_chain(monkeypatch, tmp_path)
    chain.append("generate", "pair-1")
    chain.append("rotate", "pair-1", metadata={"new_pair_id": "pair-2"})
    chain.append("revoke", "pair-2")

    entries = _read_entries(path)
    _write_entries(path, [entries[0], entries[2]])

    result = chain.verify_chain()

    assert result["ok"] is False
    assert result["reason"] == "prev_hash_mismatch"


def test_verify_chain_detects_reordered_entries(monkeypatch, tmp_path):
    path = _use_tmp_chain(monkeypatch, tmp_path)
    chain.append("generate", "pair-1")
    chain.append("rotate", "pair-1", metadata={"new_pair_id": "pair-2"})

    entries = _read_entries(path)
    _write_entries(path, [entries[1], entries[0]])

    result = chain.verify_chain()

    assert result["ok"] is False
    assert result["reason"] == "prev_hash_mismatch"


def test_tail_returns_recent_entries(monkeypatch, tmp_path):
    _use_tmp_chain(monkeypatch, tmp_path)
    for i in range(5):
        chain.append("generate", f"pair-{i}")

    assert [entry["pair_id"] for entry in chain.tail(2)] == ["pair-3", "pair-4"]
