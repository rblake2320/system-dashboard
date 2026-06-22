"""Shared witness checkpoint signing — used by both witness_server and the
witness client so the signed payload can never drift between the two sides.

HMAC-SHA256 over a fixed-order, compact payload with the witness pre-shared key.
"""
from __future__ import annotations

import hashlib
import hmac


def canonical_payload(principal_id: str, chain_head_hash: str,
                      entry_count: int, timestamp: str) -> bytes:
    return f"{principal_id}|{chain_head_hash}|{entry_count}|{timestamp}".encode()


def sign_checkpoint(witness_key: str, principal_id: str, chain_head_hash: str,
                    entry_count: int, timestamp: str) -> str:
    return hmac.new(
        witness_key.encode(),
        canonical_payload(principal_id, chain_head_hash, entry_count, timestamp),
        hashlib.sha256,
    ).hexdigest()


def verify_checkpoint(witness_key: str, principal_id: str, chain_head_hash: str,
                      entry_count: int, timestamp: str, sig: str) -> bool:
    expected = sign_checkpoint(witness_key, principal_id, chain_head_hash, entry_count, timestamp)
    return hmac.compare_digest(expected, sig)
