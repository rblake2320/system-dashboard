"""Fail-closed agent credential cache.

This module implements the behavioral contract in
docs/AGENT_CACHE_CONTRACT.md (authored in the bpc-protocol / tsk-protocol repos,
Codex lane). Any change to cache payload fields, DPAPI scope, or fail-closed
error semantics must keep the TypeScript (`agent-cache.ts`) and Python
implementations conformant with that shared contract.

This is the SSSD-style offline-operation layer of the BPC/TSK HA design: when an
agent cannot reach the primary BPC/TSK authority, it falls back to a LOCAL sealed
cache of its principal binding so it can keep operating in a bounded, authorized
window — never an unbounded or unauthenticated one. It is an offline
authorization source for a PREVIOUSLY validated principal, not a fallback
password and not a trust bypass.

Distinct from ``bpc_secret_vault`` (secret DELIVERY via Credential Manager).
This module is about safe OFFLINE OPERATION, not secret custody.

Contract guarantees (docs/AGENT_CACHE_CONTRACT.md):

  C4-01  Policy/permissions/binding/version/checkpoint are sealed WITH the
    credential, and the verifier authorizes only while ALL of them — plus TTL —
    match the caller's current expectations. A stale value (after rotation /
    permission change / checkpoint advance) fails closed.

  C4-02  Fail-closed = a NAMED raised error (CacheMissError / CacheExpiredError /
    CacheTamperedError / CacheInvalidScopeError). Never null/false/silent-degrade.

  C4-03  DPAPI CurrentUser scope — NEVER LocalMachine. Only the identity that
    performed the binding can decrypt. The envelope records its scope and a
    machine/global-scope envelope is rejected with a named error.

NIST SP 800-53 Rev 5: SC-28, IA-5, AC-3, SI-7, CP-10.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import sys
import time
from ctypes import wintypes
from dataclasses import dataclass, asdict, field
from pathlib import Path

# ── Errors (C4-02) ────────────────────────────────────────────────────────────

class CacheError(Exception):
    """Base for all credential-cache failures. Always fail closed on these."""


class CacheMissError(CacheError):
    """No cache entry exists for this principal."""


class CacheExpiredError(CacheError):
    """The cache entry's TTL has elapsed. Re-validate against the primary."""


class CacheTamperedError(CacheError):
    """The cache could not be decrypted, failed integrity, is missing a required
    field, or no longer matches current policy/permissions/binding/version/
    checkpoint (stale-authorization attack). Treat as hostile."""


class CacheInvalidScopeError(CacheTamperedError):
    """The sealed envelope claims a non-user (machine/global) protection scope.
    Subclass of CacheTamperedError so callers catching tamper also catch this."""


# ── DPAPI (CurrentUser scope) via ctypes — no third-party dependency ──────────

CRYPTPROTECT_UI_FORBIDDEN = 0x1
# NOTE: CRYPTPROTECT_LOCAL_MACHINE (0x4) is intentionally NEVER set → CurrentUser.

_SCOPE_CURRENT_USER = "CurrentUser"

# Fields that must be present in every sealed entry (contract §Required Payload).
REQUIRED_FIELDS = (
    "version", "principal_id", "binding_hash", "policy_digest",
    "permissions_hash", "credential_version", "checkpoint_hash",
    "issued_at", "expires_at",
)


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(data: bytes) -> _DATA_BLOB:
    buf = ctypes.create_string_buffer(data, len(data))
    return _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))


def _blob_bytes(blob: _DATA_BLOB) -> bytes:
    try:
        return ctypes.string_at(blob.pbData, blob.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob.pbData)


def _require_windows() -> None:
    if sys.platform != "win32":
        raise CacheError("DPAPI credential cache requires Windows (win32)")


def dpapi_protect(data: bytes, entropy: bytes | None = None) -> bytes:
    """Seal bytes with DPAPI at CurrentUser scope (C4-03)."""
    _require_windows()
    blob_in = _blob(data)
    ent = _blob(entropy) if entropy else None
    blob_out = _DATA_BLOB()
    ok = ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(blob_in), None,
        ctypes.byref(ent) if ent else None,
        None, None, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(blob_out),
    )
    if not ok:
        raise CacheError("CryptProtectData failed")
    return _blob_bytes(blob_out)


def dpapi_unprotect(data: bytes, entropy: bytes | None = None) -> bytes:
    """Unseal DPAPI bytes. A failure (foreign user / corrupt / wrong entropy)
    raises CacheTamperedError — never returns garbage."""
    _require_windows()
    blob_in = _blob(data)
    ent = _blob(entropy) if entropy else None
    blob_out = _DATA_BLOB()
    ok = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blob_in), None,
        ctypes.byref(ent) if ent else None,
        None, None, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(blob_out),
    )
    if not ok:
        raise CacheTamperedError("CryptUnprotectData failed (foreign/corrupt/entropy-mismatch)")
    return _blob_bytes(blob_out)


# ── Cache entry (contract §Required Payload Fields) ───────────────────────────

@dataclass(frozen=True)
class CacheEntry:
    principal_id: str
    binding_hash: str          # sha256 of the principal↔device binding
    policy_digest: str         # digest of the authorization policy in force
    permissions_hash: str      # hash of the granted permission set
    credential_version: int    # monotonically advances on rotation
    checkpoint_hash: str       # audit/witness checkpoint this binding is valid under
    expires_at: float          # epoch — hard TTL
    issued_at: float           # epoch — when sealed
    version: str = "1"         # cache schema version
    provider: str = ""         # e.g. 'codex' / 'claude'
    provider_session_id: str = ""
    agent_instance_id: str = ""
    credential_material: dict = field(default_factory=dict)

    def _fields(self) -> dict:
        return asdict(self)


def _canonical(d: dict) -> str:
    return json.dumps(d, sort_keys=True, separators=(",", ":"))


def _inner_digest(fields: dict) -> str:
    """Integrity digest over the entry fields — independent of DPAPI's own MAC.
    Catches in-blob field tampering even after a successful decrypt."""
    return hashlib.sha256(_canonical(fields).encode()).hexdigest()


# ── Cache ─────────────────────────────────────────────────────────────────────

class AgentCredentialCache:
    """File-backed, DPAPI-sealed, fail-closed principal cache for one agent."""

    def __init__(self, path: str | Path, entropy: bytes | None = None):
        self.path = Path(path)
        # Optional secondary entropy further binds the blob (e.g. agent id + machine
        # GUID). A wrong/absent entropy makes DPAPI unseal fail → CacheTamperedError.
        self.entropy = entropy

    # ── seal ──
    def seal(self, entry: CacheEntry) -> None:
        fields = entry._fields()
        envelope = {
            "scope": _SCOPE_CURRENT_USER,
            "entry": fields,
            "_digest": _inner_digest(fields),
        }
        sealed = dpapi_protect(_canonical(envelope).encode(), self.entropy)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_bytes(sealed)
        tmp.replace(self.path)   # atomic — never leave a half-written cache

    # ── load (fail-closed) ──
    def load(
        self,
        *,
        expected_binding_hash: str | None = None,
        expected_policy_digest: str | None = None,
        expected_permissions_hash: str | None = None,
        expected_checkpoint_hash: str | None = None,
        expected_credential_version: int | None = None,
        now: float | None = None,
    ) -> CacheEntry:
        """Return the entry, or raise. NEVER returns a falsy 'denied' value (C4-02).

        Pass the caller's CURRENT expectations (from restored BPC/TSK state) to
        detect a stale authorization (C4-01); any mismatch fails closed.
        """
        if not self.path.exists():
            raise CacheMissError(f"no cache at {self.path}")

        sealed = self.path.read_bytes()
        plaintext = dpapi_unprotect(sealed, self.entropy)  # → CacheTamperedError on failure

        try:
            envelope = json.loads(plaintext.decode())
        except (ValueError, UnicodeDecodeError) as exc:
            raise CacheTamperedError(f"corrupt cache payload: {exc}") from exc

        # C4-03: reject any non-user protection scope.
        if envelope.get("scope") != _SCOPE_CURRENT_USER:
            raise CacheInvalidScopeError(
                f"unsupported cache scope {envelope.get('scope')!r}; expected CurrentUser"
            )

        fields = envelope.get("entry")
        stored_digest = envelope.get("_digest")
        if not isinstance(fields, dict) or stored_digest is None:
            raise CacheTamperedError("cache missing entry/integrity digest")

        # Required-field presence (contract: missing field → tampered).
        missing = [f for f in REQUIRED_FIELDS if f not in fields or fields[f] is None]
        if missing:
            raise CacheTamperedError(f"cache missing required field(s): {missing}")

        # Field integrity (catches binding_hash and any field altered after sealing).
        if _inner_digest(fields) != stored_digest:
            raise CacheTamperedError("cache field integrity digest mismatch")

        try:
            entry = CacheEntry(**fields)
        except TypeError as exc:
            raise CacheTamperedError(f"cache schema mismatch: {exc}") from exc

        # C4-01: stale-authorization detection against the caller's current state.
        if expected_binding_hash is not None and entry.binding_hash != expected_binding_hash:
            raise CacheTamperedError("binding hash does not match current binding")
        if expected_policy_digest is not None and entry.policy_digest != expected_policy_digest:
            raise CacheTamperedError("policy digest does not match current policy (stale authorization)")
        if expected_permissions_hash is not None and entry.permissions_hash != expected_permissions_hash:
            raise CacheTamperedError("permissions hash does not match current grant (stale authorization)")
        if expected_checkpoint_hash is not None and entry.checkpoint_hash != expected_checkpoint_hash:
            raise CacheTamperedError("checkpoint hash does not match current checkpoint")
        if expected_credential_version is not None and entry.credential_version != expected_credential_version:
            raise CacheTamperedError("credential version does not match current version (stale credential)")

        # TTL (checked last so integrity/stale faults are reported first).
        if (now if now is not None else time.time()) > entry.expires_at:
            raise CacheExpiredError(f"cache expired at {entry.expires_at}")

        return entry

    def clear(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


def make_entry(
    principal_id: str,
    binding_hash: str,
    policy_digest: str,
    permissions_hash: str,
    ttl_seconds: float,
    *,
    credential_version: int = 1,
    checkpoint_hash: str = "sha256:genesis",
    provider: str = "",
    provider_session_id: str = "",
    agent_instance_id: str = "",
    credential_material: dict | None = None,
    now: float | None = None,
) -> CacheEntry:
    """Convenience constructor that stamps issued_at/expires_at from a TTL."""
    t = now if now is not None else time.time()
    return CacheEntry(
        principal_id=principal_id,
        binding_hash=binding_hash,
        policy_digest=policy_digest,
        permissions_hash=permissions_hash,
        credential_version=credential_version,
        checkpoint_hash=checkpoint_hash,
        expires_at=t + ttl_seconds,
        issued_at=t,
        provider=provider,
        provider_session_id=provider_session_id,
        agent_instance_id=agent_instance_id,
        credential_material=credential_material or {},
    )
