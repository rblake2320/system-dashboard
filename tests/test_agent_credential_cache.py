"""Conformance tests for the DPAPI-sealed fail-closed agent credential cache.

Implements the 10 required vectors from docs/AGENT_CACHE_CONTRACT.md (the shared
TS/Python contract) plus the real-DPAPI smoke requirement. Windows-only (DPAPI);
skipped elsewhere with an explicit reason (never silently passes).
"""
import sys
import time

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="DPAPI is Windows-only")

from core.agent_credential_cache import (  # noqa: E402
    AgentCredentialCache, CacheEntry, make_entry,
    CacheMissError, CacheExpiredError, CacheTamperedError, CacheInvalidScopeError,
    dpapi_protect, _canonical, _inner_digest, _SCOPE_CURRENT_USER,
)

POLICY = "sha256:policy-v1"
PERMS = "sha256:perms-v1"
BINDING = "sha256:binding-abc"
CHECKPOINT = "sha256:checkpoint-1"
CRED_VER = 1


def _cache(tmp_path, entropy=None):
    return AgentCredentialCache(tmp_path / "agent.cache", entropy=entropy)


def _entry(now=None):
    return make_entry(
        "principal-1", BINDING, POLICY, PERMS, ttl_seconds=300,
        credential_version=CRED_VER, checkpoint_hash=CHECKPOINT,
        provider="claude", provider_session_id="sess-1", agent_instance_id="agent-1",
        now=now,
    )


def _seal_raw(cache, entry_fields, *, scope=_SCOPE_CURRENT_USER, recompute_digest=True, digest=None):
    """Seal an arbitrary envelope (valid DPAPI) so individual contract vectors can
    be constructed without going through the normal seal() path."""
    env = {
        "scope": scope,
        "entry": entry_fields,
        "_digest": _inner_digest(entry_fields) if recompute_digest else digest,
    }
    cache.path.write_bytes(dpapi_protect(_canonical(env).encode(), cache.entropy))


# ── Vector 1: valid_current_user_cache ────────────────────────────────────────

def test_v1_valid_current_user_cache(tmp_path):
    c = _cache(tmp_path)
    c.seal(_entry())
    loaded = c.load(
        expected_binding_hash=BINDING, expected_policy_digest=POLICY,
        expected_permissions_hash=PERMS, expected_checkpoint_hash=CHECKPOINT,
        expected_credential_version=CRED_VER,
    )
    assert loaded.principal_id == "principal-1"
    assert loaded.credential_version == CRED_VER


# ── Vector 2: expired_cache ───────────────────────────────────────────────────

def test_v2_expired_cache(tmp_path):
    c = _cache(tmp_path)
    past = time.time() - 1000
    c.seal(_entry(now=past))   # ttl 300s, issued 1000s ago → expired
    with pytest.raises(CacheExpiredError):
        c.load()


# ── Vector 3: blob_tamper ─────────────────────────────────────────────────────

def test_v3_blob_tamper(tmp_path):
    c = _cache(tmp_path)
    c.seal(_entry())
    raw = bytearray(c.path.read_bytes())
    raw[len(raw) // 2] ^= 0xFF
    c.path.write_bytes(bytes(raw))
    with pytest.raises(CacheTamperedError):
        c.load()


# ── Vector 4: binding_hash_tamper ─────────────────────────────────────────────

def test_v4_binding_hash_tamper(tmp_path):
    c = _cache(tmp_path)
    fields = _entry()._fields()
    fields["binding_hash"] = "sha256:DIFFERENT"     # altered, but keep old digest
    _seal_raw(c, fields, recompute_digest=False, digest=_inner_digest(_entry()._fields()))
    with pytest.raises(CacheTamperedError):
        c.load()


# ── Vector 5: stale_policy_digest ─────────────────────────────────────────────

def test_v5_stale_policy_digest(tmp_path):
    c = _cache(tmp_path)
    c.seal(_entry())
    with pytest.raises(CacheTamperedError):
        c.load(expected_policy_digest="sha256:policy-v2-rotated")


# ── Vector 6: stale_permissions_hash ──────────────────────────────────────────

def test_v6_stale_permissions_hash(tmp_path):
    c = _cache(tmp_path)
    c.seal(_entry())
    with pytest.raises(CacheTamperedError):
        c.load(expected_permissions_hash="sha256:perms-v2-changed")


# ── Vector 7: checkpoint_mismatch ─────────────────────────────────────────────

def test_v7_checkpoint_mismatch(tmp_path):
    c = _cache(tmp_path)
    c.seal(_entry())
    with pytest.raises(CacheTamperedError):
        c.load(expected_checkpoint_hash="sha256:checkpoint-2-advanced")


# ── Vector 8: credential_version_mismatch ─────────────────────────────────────

def test_v8_credential_version_mismatch(tmp_path):
    c = _cache(tmp_path)
    c.seal(_entry())
    with pytest.raises(CacheTamperedError):
        c.load(expected_credential_version=2)   # credential rotated


# ── Vector 9: missing_required_field ──────────────────────────────────────────

def test_v9_missing_required_field(tmp_path):
    c = _cache(tmp_path)
    fields = _entry()._fields()
    del fields["checkpoint_hash"]            # remove a required field before sealing
    _seal_raw(c, fields)                     # digest recomputed over the reduced set
    with pytest.raises(CacheTamperedError):
        c.load()


# ── Vector 10: unsupported_scope ──────────────────────────────────────────────

def test_v10_unsupported_scope(tmp_path):
    c = _cache(tmp_path)
    fields = _entry()._fields()
    _seal_raw(c, fields, scope="LocalMachine")   # envelope claims machine scope
    with pytest.raises(CacheInvalidScopeError):
        c.load()
    # And it is catchable as a tamper error (subclass) for generic callers.
    _seal_raw(c, fields, scope="LocalMachine")
    with pytest.raises(CacheTamperedError):
        c.load()


# ── Contract: miss is a named error ───────────────────────────────────────────

def test_missing_cache_raises_named_not_falsy(tmp_path):
    c = _cache(tmp_path)
    with pytest.raises(CacheMissError):
        c.load()


# ── Real-DPAPI smoke (contract §Real Platform Smoke Tests, no mock) ───────────

def test_real_dpapi_smoke_currentuser(tmp_path):
    """Round-trips through the real Windows DPAPI provider, then a one-byte flip
    in the real ciphertext must fail closed. No mock/fake provider."""
    c = _cache(tmp_path)
    c.seal(_entry())
    assert c.load().principal_id == "principal-1"     # real unseal
    raw = bytearray(c.path.read_bytes())
    # Flip a byte in the ciphertext+MAC region (latter half). The leading bytes
    # are an unauthenticated DPAPI provider/version header, so corrupting them is
    # not reliably detected; the encrypted body + HMAC is.
    raw[len(raw) // 2] ^= 0x01
    c.path.write_bytes(bytes(raw))
    with pytest.raises(CacheTamperedError):
        c.load()


def test_wrong_entropy_fails_closed(tmp_path):
    cw = _cache(tmp_path, entropy=b"agent-1|machine-A")
    cw.seal(_entry())
    cr = AgentCredentialCache(cw.path, entropy=b"agent-1|machine-B")
    with pytest.raises(CacheTamperedError):
        cr.load()
