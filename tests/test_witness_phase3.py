"""Phase 3 witness — REAL loopback integration test.

No mocks: starts the actual witness Flask server on a real localhost socket,
pushes real signed checkpoints derived from a real hash-chained audit log, then
corrupts the local chain and verifies the mismatch engages the real audit lock.
"""
import threading

import pytest
from werkzeug.serving import make_server

from core import bpc_audit_chain as chain
from core import audit_lock
from core import witness_client
from core.witness_sig import sign_checkpoint
from witness_server import create_witness_app

WKEY = "witness-preshared-test-key"
PRINCIPAL = "bpc-primary"


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    # Real files, just isolated to tmp so we exercise the real code paths.
    monkeypatch.setattr(chain, "_chain_path", tmp_path / "chain.ndjson")
    monkeypatch.setattr(audit_lock, "_flag_path", tmp_path / "lock.json")
    audit_lock._state.update({"locked": False, "reason": None, "since": None, "detail": None})
    yield tmp_path


@pytest.fixture
def witness(tmp_path):
    app = create_witness_app(WKEY, tmp_path / "witness_log.ndjson")
    srv = make_server("127.0.0.1", 0, app)          # ephemeral real port
    port = srv.server_port
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


def test_health(witness):
    import urllib.request, json
    with urllib.request.urlopen(f"{witness}/witness/health") as r:
        body = json.loads(r.read())
    assert body["ok"] is True


def test_checkpoint_push_and_identical_verify(isolated, witness):
    chain.append("generate", "pair_a")
    chain.append("rotate", "pair_a")
    resp = witness_client.push_checkpoint(witness, WKEY, PRINCIPAL)
    assert resp["ok"] is True
    assert resp["witnessed"]["entry_count"] == 2

    v = witness_client.verify_against_witness(witness, PRINCIPAL)
    assert v["match"] is True
    assert v["reason"] == "identical"


def test_local_ahead_is_not_a_mismatch(isolated, witness):
    chain.append("generate", "pair_a")
    witness_client.push_checkpoint(witness, WKEY, PRINCIPAL)   # witness at count 1
    chain.append("rotate", "pair_a")                          # local advances to 2
    v = witness_client.verify_against_witness(witness, PRINCIPAL)
    assert v["match"] is True
    assert v["reason"] == "local_ahead"


def test_forged_checkpoint_rejected(witness):
    import urllib.request, urllib.error, json
    bad = {
        "principal_id": PRINCIPAL, "chain_head_hash": "deadbeef",
        "entry_count": 1, "timestamp": "2026-01-01T00:00:00Z",
        "sig": sign_checkpoint("WRONG-KEY", PRINCIPAL, "deadbeef", 1, "2026-01-01T00:00:00Z"),
    }
    req = urllib.request.Request(f"{witness}/witness/checkpoint",
                                 data=json.dumps(bad).encode(),
                                 headers={"Content-Type": "application/json"})
    with pytest.raises(urllib.error.HTTPError) as ei:
        urllib.request.urlopen(req)
    assert ei.value.code == 401          # witness refuses a checkpoint it can't verify


def test_chain_rewrite_triggers_audit_lock(isolated, witness):
    # Build a real chain and witness it at count 3.
    chain.append("generate", "pair_a")
    chain.append("rotate", "pair_a")
    chain.append("revoke", "pair_a")
    witness_client.push_checkpoint(witness, WKEY, PRINCIPAL)
    head_before = chain.head()
    assert head_before["entry_count"] == 3

    # Simulate a full chain REWRITE: same length, different content → different head.
    chain._chain_path.unlink()
    chain.append("generate", "pair_EVIL")
    chain.append("rotate", "pair_EVIL")
    chain.append("revoke", "pair_EVIL")
    head_after = chain.head()
    assert head_after["entry_count"] == 3
    assert head_after["head_hash"] != head_before["head_hash"]   # rewrite happened

    # The witness still holds the original head → mismatch detected.
    v = witness_client.verify_against_witness(witness, PRINCIPAL)
    assert v["match"] is False
    assert v["reason"] == "head_mismatch"

    # Engage the real audit lock from the mismatch.
    assert audit_lock.is_locked() is False
    audit_lock.engage("witness_mismatch", v)
    assert audit_lock.is_locked() is True
    blocked = audit_lock.assert_writable()
    assert blocked is not None and blocked["error"] == "audit_lock_active"

    # Guard clears it.
    audit_lock.clear(by="fleet-guard")
    assert audit_lock.is_locked() is False
    assert audit_lock.assert_writable() is None


def test_witness_unreachable_is_not_tamper(isolated):
    chain.append("generate", "pair_a")
    # Point at a dead port — must NOT be treated as a mismatch/lock.
    v = witness_client.verify_against_witness("http://127.0.0.1:1", PRINCIPAL)
    assert v["match"] is True
    assert v["reason"].startswith("witness_unreachable")
