"""Witness client + audit-lock trigger (HA Phase 3, primary side).

After each audit-chain append the primary calls `push_checkpoint()` to publish
its current chain head to the external witness. `verify_against_witness()`
compares the witness's last known head to the local chain head; a mismatch means
the local chain was rewritten (or the witness was fed a divergent head) and the
primary engages AUDIT-LOCK: writes are refused until the guard clears it.

The witness pre-shared key is separate from BPC/TSK keys. In production it lives
in the Windows credential store; here it is read from config/env.

Default VPS witness: https://srv1775625.hstgr.cloud (self-signed cert, ssl_verify=False).
"""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request

from core import bpc_audit_chain as _chain
from core.witness_sig import sign_checkpoint


_TIMEOUT = 5

# Default witness endpoint — Hostinger VPS, self-signed cert in use until CA cert issued.
VPS_WITNESS_URL = "https://srv1775625.hstgr.cloud"


def _now_iso() -> str:
    import time
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _ssl_ctx(verify: bool) -> ssl.SSLContext | None:
    """Return an SSL context. When verify=False, disable cert validation (self-signed)."""
    if not verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return None  # urllib default: full verification


def _post(url: str, body: dict, timeout: int = _TIMEOUT,
          ssl_verify: bool = True) -> dict:
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    ctx = _ssl_ctx(ssl_verify)
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return json.loads(resp.read().decode())


def _get(url: str, timeout: int = _TIMEOUT, ssl_verify: bool = True) -> dict:
    ctx = _ssl_ctx(ssl_verify)
    with urllib.request.urlopen(url, timeout=timeout, context=ctx) as resp:
        return json.loads(resp.read().decode())


def push_checkpoint(witness_key: str, principal_id: str,
                    witness_url: str = VPS_WITNESS_URL,
                    timestamp: str | None = None,
                    ssl_verify: bool = False) -> dict:
    """Publish the current local chain head to the witness. Returns the witness reply.

    Args:
        witness_key:  HMAC pre-shared key (hex string).
        principal_id: Identifier for this primary node.
        witness_url:  Base URL of the witness server. Defaults to VPS_WITNESS_URL.
        timestamp:    ISO-8601 timestamp; auto-generated if omitted.
        ssl_verify:   Set False for self-signed certs (VPS default). Set True in prod
                      once a CA-signed cert is installed.
    """
    h = _chain.head()
    ts = timestamp or _now_iso()
    sig = sign_checkpoint(witness_key, principal_id, h["head_hash"], h["entry_count"], ts)
    body = {
        "principal_id": principal_id,
        "chain_head_hash": h["head_hash"],
        "entry_count": h["entry_count"],
        "timestamp": ts,
        "sig": sig,
    }
    return _post(f"{witness_url}/witness/checkpoint", body, ssl_verify=ssl_verify)


def verify_against_witness(principal_id: str,
                           witness_url: str = VPS_WITNESS_URL,
                           ssl_verify: bool = False) -> dict:
    """Compare the witness's last checkpoint to the local chain head.

    Returns {match, reason, local_head, witness_head}. `match=False` means the
    caller should engage audit-lock. A witness with no prior checkpoint for this
    principal is treated as match=True (nothing to contradict yet).

    Args:
        principal_id: Identifier for this primary node.
        witness_url:  Base URL of the witness server. Defaults to VPS_WITNESS_URL.
        ssl_verify:   Set False for self-signed certs (VPS default).
    """
    local = _chain.head()
    try:
        resp = _get(f"{witness_url}/witness/verify/{principal_id}", ssl_verify=ssl_verify)
    except (urllib.error.URLError, OSError) as exc:
        # Witness unreachable is NOT a tamper signal — report it, don't lock.
        return {"match": True, "reason": f"witness_unreachable:{exc}", "local_head": local, "witness_head": None}

    cp = resp.get("checkpoint")
    if not resp.get("found") or cp is None:
        return {"match": True, "reason": "no_prior_checkpoint", "local_head": local, "witness_head": None}

    witness_head = {"head_hash": cp.get("chain_head_hash"), "entry_count": cp.get("entry_count")}

    # The local chain must be consistent with the witnessed head: either identical,
    # or strictly AHEAD (more entries, same prefix is enforced by hash chaining).
    if local["head_hash"] == witness_head["head_hash"]:
        return {"match": True, "reason": "identical", "local_head": local, "witness_head": witness_head}
    if local["entry_count"] > witness_head["entry_count"]:
        # Local advanced past the last checkpoint — expected between checkpoints.
        return {"match": True, "reason": "local_ahead", "local_head": local, "witness_head": witness_head}

    # Same/older count but different head hash → the chain was rewritten. TAMPER.
    return {"match": False, "reason": "head_mismatch", "local_head": local, "witness_head": witness_head}
