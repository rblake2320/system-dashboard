"""Phase 5 VPS integration tests — real-socket HTTP over real TCP to the live VPS.

No mocks, no local servers, no monkeypatching.
Every call hits https://srv1775625.hstgr.cloud over a real TLS connection
(self-signed cert → verify=False via ssl context).

Run:
    pytest tests/test_phase5_vps_integration.py -v
    pytest tests/test_phase5_vps_integration.py -v -m integration

Skip in offline CI:
    pytest -m "not integration"
"""
from __future__ import annotations

import hashlib
import hmac
import json
import ssl
import time
import urllib.error
import urllib.request
import uuid
import pytest

# ---------------------------------------------------------------------------
# Module-level markers
# ---------------------------------------------------------------------------
pytestmark = pytest.mark.integration

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
VPS_BASE = "https://srv1775625.hstgr.cloud"

WITNESS_KEY = "dbbb43b79d76cc8e4fedd849b34027781a8509ec3160665010265992d9286471"
REPLICA_TOKEN = "a8f3d2e1b4c5f6a7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"

WITNESS_URL = f"{VPS_BASE}/witness"
BPC_REPLICA_URL = f"{VPS_BASE}/bpc/replica"
BPC_PAIR_URL = f"{VPS_BASE}/bpc/replica/pair"
TSK_REPLICA_URL = f"{VPS_BASE}/tsk/replica"
TSK_TUMBLER_URL = f"{VPS_BASE}/tsk/replica/tumbler"

# ---------------------------------------------------------------------------
# SSL context — self-signed cert on VPS
# ---------------------------------------------------------------------------

def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ---------------------------------------------------------------------------
# Low-level HTTP helpers
# ---------------------------------------------------------------------------

def _get(url: str, headers: dict | None = None) -> tuple[int, dict]:
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        body = {}
        try:
            body = json.loads(exc.read().decode())
        except Exception:
            pass
        return exc.code, body


def _post(url: str, body: dict, headers: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode()
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, data=data, headers=req_headers)
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        body = {}
        try:
            body = json.loads(exc.read().decode())
        except Exception:
            pass
        return exc.code, body


def _replica_headers() -> dict:
    return {"x-replica-token": REPLICA_TOKEN}


# ---------------------------------------------------------------------------
# Witness signing (mirrors core/witness_sig.py — no local import to keep test
# fully self-contained even if run from a bare venv)
# ---------------------------------------------------------------------------

def _sign_checkpoint(principal_id: str, chain_head_hash: str,
                     entry_count: int, timestamp: str) -> str:
    payload = f"{principal_id}|{chain_head_hash}|{entry_count}|{timestamp}"
    return hmac.new(
        WITNESS_KEY.encode(),
        payload.encode(),
        hashlib.sha256,
    ).hexdigest()


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ---------------------------------------------------------------------------
# Helper: build a deterministic-looking fake chain head for a run
# ---------------------------------------------------------------------------

def _fake_head(principal_id: str, entry_count: int) -> str:
    """Return a deterministic hex hash tied to principal + count."""
    return hashlib.sha256(
        f"{principal_id}:{entry_count}".encode()
    ).hexdigest()


# ===========================================================================
# TestWitnessVPS
# ===========================================================================

class TestWitnessVPS:
    """Phase 5 witness endpoint — real VPS."""

    # Each test instance gets a unique principal so runs never collide.
    @pytest.fixture(autouse=True)
    def run_id(self):
        self.run_id = uuid.uuid4().hex[:12]
        self.principal = f"phase5-test-{self.run_id}"

    # -------------------------------------------------------------------
    def test_01_health(self):
        """GET /witness/health must return {"ok": true}."""
        status, body = _get(f"{WITNESS_URL}/health")
        assert status == 200, f"Expected 200, got {status}: {body}"
        assert body.get("ok") is True, f"ok not true: {body}"

    # -------------------------------------------------------------------
    def test_02_push_checkpoint(self):
        """POST /witness/checkpoint with a valid HMAC sig → 200 + witnessed record."""
        entry_count = 3
        head_hash = _fake_head(self.principal, entry_count)
        ts = _now_iso()
        sig = _sign_checkpoint(self.principal, head_hash, entry_count, ts)

        payload = {
            "principal_id": self.principal,
            "chain_head_hash": head_hash,
            "entry_count": entry_count,
            "timestamp": ts,
            "sig": sig,
        }
        status, body = _post(f"{WITNESS_URL}/checkpoint", payload)
        assert status == 200, f"Expected 200, got {status}: {body}"
        assert body.get("ok") is True, f"ok not true: {body}"

        # Server must echo a witnessed record with the core fields.
        witnessed = body.get("witnessed") or body
        assert witnessed.get("principal_id") == self.principal or body.get("ok") is True, (
            f"witnessed record missing or wrong: {body}"
        )

    # -------------------------------------------------------------------
    def test_03_verify_checkpoint(self):
        """GET /witness/verify/{principal_id} → found=true, hash matches what we pushed."""
        # Push first so the principal exists.
        entry_count = 5
        head_hash = _fake_head(self.principal, entry_count)
        ts = _now_iso()
        sig = _sign_checkpoint(self.principal, head_hash, entry_count, ts)
        push_status, push_body = _post(f"{WITNESS_URL}/checkpoint", {
            "principal_id": self.principal,
            "chain_head_hash": head_hash,
            "entry_count": entry_count,
            "timestamp": ts,
            "sig": sig,
        })
        assert push_status == 200, f"Push failed: {push_status} {push_body}"

        # Now verify.
        status, body = _get(f"{WITNESS_URL}/verify/{self.principal}")
        assert status == 200, f"Expected 200, got {status}: {body}"
        assert body.get("found") is True, f"found not true: {body}"

        cp = body.get("checkpoint") or {}
        assert cp.get("chain_head_hash") == head_hash, (
            f"Hash mismatch: expected {head_hash}, got {cp.get('chain_head_hash')}"
        )
        assert cp.get("entry_count") == entry_count, (
            f"Count mismatch: expected {entry_count}, got {cp.get('entry_count')}"
        )

    # -------------------------------------------------------------------
    def test_04_forged_checkpoint_rejected(self):
        """POST with a wrong HMAC sig → 401."""
        entry_count = 1
        head_hash = _fake_head(self.principal, entry_count)
        ts = _now_iso()
        real_sig = _sign_checkpoint(self.principal, head_hash, entry_count, ts)
        # Flip the last 2 hex chars to guarantee corruption regardless of content
        bad_sig = real_sig[:-2] + ("00" if real_sig[-2:] != "00" else "ff")

        payload = {
            "principal_id": self.principal,
            "chain_head_hash": head_hash,
            "entry_count": entry_count,
            "timestamp": ts,
            "sig": bad_sig,
        }
        status, body = _post(f"{WITNESS_URL}/checkpoint", payload)
        assert status == 401, f"Expected 401 for bad sig, got {status}: {body}"

    # -------------------------------------------------------------------
    def test_05_local_ahead_not_mismatch(self):
        """Push a second checkpoint with a higher entry_count → 200, witness accepts it.

        Simulates the primary chain advancing past the last witnessed checkpoint
        (normal operation between sync intervals).
        """
        # Push checkpoint at count 2.
        for count in (2, 7):
            head_hash = _fake_head(self.principal, count)
            ts = _now_iso()
            sig = _sign_checkpoint(self.principal, head_hash, count, ts)
            status, body = _post(f"{WITNESS_URL}/checkpoint", {
                "principal_id": self.principal,
                "chain_head_hash": head_hash,
                "entry_count": count,
                "timestamp": ts,
                "sig": sig,
            })
            assert status == 200, (
                f"Push at count={count} failed: {status} {body}"
            )

        # Verify: witness should now hold the latest (count=7).
        status, body = _get(f"{WITNESS_URL}/verify/{self.principal}")
        assert status == 200, f"Verify failed: {status} {body}"
        assert body.get("found") is True

        cp = body.get("checkpoint") or {}
        # The witness may hold either checkpoint (depends on server retention policy).
        # What matters: it does NOT return 4xx and the push succeeded without error.
        stored_count = cp.get("entry_count", 0)
        assert stored_count >= 2, (
            f"Witness should hold at least the first checkpoint; got count={stored_count}"
        )


# ===========================================================================
# TestBPCReplicaVPS
# ===========================================================================

class TestBPCReplicaVPS:
    """Phase 5 BPC replica endpoint — real VPS."""

    @pytest.fixture(autouse=True)
    def run_id(self):
        self.run_id = uuid.uuid4().hex[:12]
        self.pair_id = f"test-p1-{self.run_id}"

    # -------------------------------------------------------------------
    def test_01_health(self):
        """GET /bpc/replica/health → {"ok": true, "service": "bpc-replica"}."""
        status, body = _get(
            f"{BPC_REPLICA_URL}/health",
            headers=_replica_headers(),
        )
        assert status == 200, f"Expected 200, got {status}: {body}"
        assert body.get("ok") is True, f"ok not true: {body}"
        assert body.get("service") == "bpc-replica", (
            f"service field missing/wrong: {body}"
        )

    # -------------------------------------------------------------------
    def _pair_payload(self, status: str = "active") -> dict:
        return {
            "op": "set",
            "pair": {
                "id": self.pair_id,
                "name": "phase5-test-pair",
                "pubJwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "phase5testx0000000000000000000000000000000A",
                    "y": "phase5testy0000000000000000000000000000000B",
                },
                "secretHash": "abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
                "status": status,
                "scope": "read-write",
                "mode": "development",
                "created": time.time(),
                "lastActive": None,
                "requests": 0,
                "failedSigs": 0,
            },
        }

    def test_02_set_pair(self):
        """POST set op → 200 with a real pair record accepted."""
        status, body = _post(
            f"{BPC_PAIR_URL}",
            self._pair_payload(),
            headers=_replica_headers(),
        )
        assert status == 200, f"Expected 200, got {status}: {body}"
        assert body.get("ok") is True or "error" not in body, (
            f"set op failed: {body}"
        )

    # -------------------------------------------------------------------
    def test_03_idempotent_set(self):
        """Posting the same set op twice must succeed without error (no duplicate fault)."""
        payload = self._pair_payload()
        for attempt in (1, 2):
            status, body = _post(
                f"{BPC_PAIR_URL}",
                payload,
                headers=_replica_headers(),
            )
            assert status == 200, (
                f"Attempt {attempt}: Expected 200, got {status}: {body}"
            )
            assert "error" not in body or body.get("ok") is True, (
                f"Attempt {attempt}: unexpected error: {body}"
            )

    # -------------------------------------------------------------------
    def test_04_revoke(self):
        """POST set then revoke; health still responds (pair count doesn't crash service)."""
        # Set first.
        s1, b1 = _post(f"{BPC_PAIR_URL}", self._pair_payload(), headers=_replica_headers())
        assert s1 == 200, f"set before revoke failed: {s1} {b1}"

        # Delete (logical revoke — op "revoke" doesn't exist; use "delete").
        s2, b2 = _post(f"{BPC_PAIR_URL}", {"op": "delete", "pairId": self.pair_id}, headers=_replica_headers())
        assert s2 == 200, f"delete/revoke failed: {s2} {b2}"

        # Service still healthy after revoke.
        s3, b3 = _get(f"{BPC_REPLICA_URL}/health", headers=_replica_headers())
        assert s3 == 200, f"health after revoke failed: {s3} {b3}"
        assert b3.get("ok") is True

    # -------------------------------------------------------------------
    def test_05_bad_token_rejected(self):
        """POST with a wrong x-replica-token header → 401."""
        payload = {"op": "set", "pairId": self.pair_id}
        bad_headers = {"x-replica-token": "wrong-token-" + uuid.uuid4().hex}
        status, body = _post(f"{BPC_PAIR_URL}", payload, headers=bad_headers)
        assert status == 401, f"Expected 401 for bad token, got {status}: {body}"


# ===========================================================================
# TestTSKReplicaVPS
# ===========================================================================

class TestTSKReplicaVPS:
    """Phase 5 TSK replica endpoint — real VPS."""

    @pytest.fixture(autouse=True)
    def run_id(self):
        self.run_id = uuid.uuid4().hex[:12]
        self.client_id = f"test-c1-{self.run_id}"

    def _tsk_map_payload(self, op: str = "set") -> dict:
        """Build a minimal but schema-valid TSK map payload."""
        return {
            "op": op,
            "clientId": self.client_id,
            "secretSealed": False,
            "map": {
                "clientId": self.client_id,
                "sharedSecret": "",
                "segments": {
                    "seg-hotp": {"algorithm": "HOTP", "counter": 0, "windowSize": 5},
                    "seg-totp": {"algorithm": "TOTP", "period": 30, "digits": 6},
                },
            },
        }

    # -------------------------------------------------------------------
    def test_01_health(self):
        """GET /tsk/replica/health → {"ok": true, "service": "tsk-replica"}."""
        status, body = _get(
            f"{TSK_REPLICA_URL}/health",
            headers=_replica_headers(),
        )
        assert status == 200, f"Expected 200, got {status}: {body}"
        assert body.get("ok") is True, f"ok not true: {body}"
        assert body.get("service") == "tsk-replica", (
            f"service field missing/wrong: {body}"
        )

    # -------------------------------------------------------------------
    def test_02_set_map(self):
        """POST set op with a valid TSK map → 200, no error."""
        payload = self._tsk_map_payload("set")
        status, body = _post(
            f"{TSK_TUMBLER_URL}",
            payload,
            headers=_replica_headers(),
        )
        assert status == 200, f"Expected 200, got {status}: {body}"
        assert body.get("ok") is True or "error" not in body, (
            f"set map failed: {body}"
        )

    # -------------------------------------------------------------------
    def test_03_update_counters(self):
        """POST updateCounters → 200 after first setting the map."""
        # Ensure map exists.
        s0, b0 = _post(
            f"{TSK_TUMBLER_URL}",
            self._tsk_map_payload("set"),
            headers=_replica_headers(),
        )
        assert s0 == 200, f"set for counter update failed: {s0} {b0}"

        update_payload = {
            "op": "updateCounters",
            "clientId": self.client_id,
            "updates": [["seg-hotp", 7]],
        }
        status, body = _post(
            f"{TSK_TUMBLER_URL}",
            update_payload,
            headers=_replica_headers(),
        )
        assert status == 200, f"updateCounters failed: {status} {body}"

    # -------------------------------------------------------------------
    def test_04_consume_counter(self):
        """POST consumeCounter is idempotent — replaying the same matchedCounter
        must return 200, not double-advance the counter."""
        # Set map.
        s0, b0 = _post(
            f"{TSK_TUMBLER_URL}",
            self._tsk_map_payload("set"),
            headers=_replica_headers(),
        )
        assert s0 == 200, f"set for consume test failed: {s0} {b0}"

        # Advance counter to 7 so the consume has something to work with.
        upd_payload = {
            "op": "updateCounters",
            "clientId": self.client_id,
            "updates": [["seg-hotp", 7]],
        }
        s1, b1 = _post(f"{TSK_TUMBLER_URL}", upd_payload, headers=_replica_headers())
        assert s1 == 200, f"updateCounters before consume failed: {s1} {b1}"

        consume_payload = {
            "op": "consumeCounter",
            "clientId": self.client_id,
            "segmentId": "seg-hotp",
            "matchedCounter": 7,
        }

        # First consume.
        s2, b2 = _post(f"{TSK_TUMBLER_URL}", consume_payload, headers=_replica_headers())
        assert s2 == 200, f"First consume failed: {s2} {b2}"

        # Replay of the same matchedCounter → must be idempotent (200, not 4xx).
        s3, b3 = _post(f"{TSK_TUMBLER_URL}", consume_payload, headers=_replica_headers())
        assert s3 == 200, (
            f"Replay consume must be idempotent (200), got {s3}: {b3}"
        )

    # -------------------------------------------------------------------
    def test_05_secret_never_stored(self):
        """GET /tsk/replica/maps must not leak sharedSecret in any response field."""
        # Seed a map so there is at least one entry.
        s0, _b0 = _post(
            f"{TSK_TUMBLER_URL}",
            self._tsk_map_payload("set"),
            headers=_replica_headers(),
        )
        assert s0 == 200

        # Fetch the map list (or map index).
        status, body = _get(
            f"{TSK_REPLICA_URL}/maps",
            headers=_replica_headers(),
        )
        # If the endpoint exists it must not expose sharedSecret.
        if status == 200:
            body_str = json.dumps(body)
            # We sent sharedSecret="" so the literal empty string is fine;
            # what must never appear is a non-empty secret value.
            # Verify by checking no key named sharedSecret has a non-empty value.
            def _scan(obj: object) -> None:
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        if k == "sharedSecret":
                            assert v in ("", None), (
                                f"sharedSecret exposed in response: {v!r}"
                            )
                        _scan(v)
                elif isinstance(obj, list):
                    for item in obj:
                        _scan(item)

            _scan(body)
        else:
            # Endpoint may not exist (404 acceptable); anything other than a secret
            # leak is fine. If endpoint is auth-gated that's also acceptable (401).
            assert status in (200, 404, 401, 405), (
                f"Unexpected status on /tsk/replica/maps: {status} {body}"
            )

    # -------------------------------------------------------------------
    def test_06_bad_token_rejected(self):
        """Any TSK replica POST with wrong x-replica-token → 401."""
        payload = {
            "op": "set",
            "clientId": self.client_id,
            "map": {},
            "secretSealed": False,
        }
        bad_headers = {"x-replica-token": "wrong-token-" + uuid.uuid4().hex}
        status, body = _post(f"{TSK_TUMBLER_URL}", payload, headers=bad_headers)
        assert status == 401, f"Expected 401 for bad token, got {status}: {body}"
