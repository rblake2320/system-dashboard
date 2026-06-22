"""Standalone smoke-test: push a checkpoint to the VPS witness and verify it.

Usage (from repo root):
    python scripts/push_witness_test.py [--principal <id>]

Loads credentials from .witness.env in the repo root. Exits 0 on success, 1
on any failure so it can be wired into CI or called by the HA health-check loop.

No third-party libraries — urllib only, consistent with bpc_monitor.py style.
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


# ---------------------------------------------------------------------------
# Env loader
# ---------------------------------------------------------------------------

def _load_env(env_path: Path) -> dict[str, str]:
    """Parse a KEY=VALUE env file; skip blank lines and comments."""
    result: dict[str, str] = {}
    if not env_path.exists():
        raise FileNotFoundError(f".witness.env not found at {env_path}")
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        result[key.strip()] = value.strip()
    return result


# ---------------------------------------------------------------------------
# Low-level HTTP helpers (no requests, no cert verification for self-signed)
# ---------------------------------------------------------------------------

_TIMEOUT = 8


def _ssl_ctx_no_verify() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _post(url: str, body: dict) -> dict:
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=_TIMEOUT, context=_ssl_ctx_no_verify()) as resp:
        return json.loads(resp.read().decode())


def _get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=_TIMEOUT, context=_ssl_ctx_no_verify()) as resp:
        return json.loads(resp.read().decode())


# ---------------------------------------------------------------------------
# Inline push / verify (avoids sys.path surgery for core imports)
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _hmac_sign(key: str, principal_id: str, chain_head_hash: str,
               entry_count: int, timestamp: str) -> str:
    import hashlib
    import hmac as _hmac
    payload = f"{principal_id}|{chain_head_hash}|{entry_count}|{timestamp}".encode()
    return _hmac.new(key.encode(), payload, hashlib.sha256).hexdigest()


def push_checkpoint(witness_url: str, witness_key: str, principal_id: str,
                    chain_head_hash: str, entry_count: int) -> dict:
    ts = _now_iso()
    sig = _hmac_sign(witness_key, principal_id, chain_head_hash, entry_count, ts)
    body = {
        "principal_id": principal_id,
        "chain_head_hash": chain_head_hash,
        "entry_count": entry_count,
        "timestamp": ts,
        "sig": sig,
    }
    return _post(f"{witness_url}/witness/checkpoint", body)


def verify_against_witness(witness_url: str, principal_id: str,
                           local_head_hash: str, local_entry_count: int) -> dict:
    try:
        resp = _get(f"{witness_url}/witness/verify/{principal_id}")
    except (urllib.error.URLError, OSError) as exc:
        return {"match": False, "reason": f"witness_unreachable:{exc}"}

    cp = resp.get("checkpoint")
    if not resp.get("found") or cp is None:
        # No prior checkpoint — nothing to contradict.
        return {"match": True, "reason": "no_prior_checkpoint"}

    w_hash = cp.get("chain_head_hash")
    w_count = cp.get("entry_count")

    if local_head_hash == w_hash:
        return {"match": True, "reason": "identical",
                "witness_head": w_hash, "witness_count": w_count}
    if local_entry_count > w_count:
        return {"match": True, "reason": "local_ahead",
                "witness_head": w_hash, "witness_count": w_count}

    return {"match": False, "reason": "head_mismatch",
            "local_head": local_head_hash, "local_count": local_entry_count,
            "witness_head": w_hash, "witness_count": w_count}


# ---------------------------------------------------------------------------
# Chain head reader (reads local evidence file directly)
# ---------------------------------------------------------------------------

def _local_chain_head(repo_root: Path) -> dict:
    """Read head_hash and entry_count from the local audit chain NDJSON."""
    genesis = "0" * 64
    chain_path = repo_root / "evidence" / "bpc_audit_chain.ndjson"
    if not chain_path.exists():
        print(f"  [info] No audit chain at {chain_path} — using genesis head")
        return {"head_hash": genesis, "entry_count": 0}

    last_hash = genesis
    count = 0
    with open(chain_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                last_hash = entry.get("entry_hash", last_hash)
                count += 1
            except json.JSONDecodeError:
                pass
    return {"head_hash": last_hash, "entry_count": count}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Push a BPC audit checkpoint to the VPS witness.")
    parser.add_argument("--principal", default="bpc-primary-win32",
                        help="Principal ID to register under (default: bpc-primary-win32)")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    env_path = repo_root / ".witness.env"

    # 1. Load credentials
    print(f"[1/4] Loading credentials from {env_path}")
    try:
        env = _load_env(env_path)
    except FileNotFoundError as exc:
        print(f"  ERROR: {exc}", file=sys.stderr)
        return 1

    witness_url = env.get("WITNESS_URL", "").rstrip("/")
    witness_key = env.get("WITNESS_KEY", "")
    if not witness_url or not witness_key:
        print("  ERROR: WITNESS_URL or WITNESS_KEY missing from .witness.env", file=sys.stderr)
        return 1
    print(f"  WITNESS_URL = {witness_url}")
    print(f"  WITNESS_KEY = {witness_key[:8]}...{witness_key[-8:]}")

    # 2. Read local chain head
    print(f"\n[2/4] Reading local audit chain head")
    head = _local_chain_head(repo_root)
    print(f"  head_hash   = {head['head_hash'][:16]}...")
    print(f"  entry_count = {head['entry_count']}")

    # 3. Push checkpoint
    print(f"\n[3/4] Pushing checkpoint to {witness_url}/witness/checkpoint")
    try:
        push_reply = push_checkpoint(
            witness_url=witness_url,
            witness_key=witness_key,
            principal_id=args.principal,
            chain_head_hash=head["head_hash"],
            entry_count=head["entry_count"],
        )
    except Exception as exc:
        print(f"  ERROR pushing checkpoint: {exc}", file=sys.stderr)
        return 1
    print(f"  Witness reply: {json.dumps(push_reply, indent=2)}")

    ok_statuses = {"ok", "accepted", "stored", "success"}
    reply_status = str(push_reply.get("status", "")).lower()
    if reply_status not in ok_statuses and not push_reply.get("ok"):
        print(f"  ERROR: unexpected reply status '{reply_status}'", file=sys.stderr)
        return 1

    # 4. Verify
    print(f"\n[4/4] Verifying against witness: {witness_url}/witness/verify/{args.principal}")
    try:
        v = verify_against_witness(
            witness_url=witness_url,
            principal_id=args.principal,
            local_head_hash=head["head_hash"],
            local_entry_count=head["entry_count"],
        )
    except Exception as exc:
        print(f"  ERROR during verify: {exc}", file=sys.stderr)
        return 1
    print(f"  Verify result: {json.dumps(v, indent=2)}")

    if not v.get("match"):
        print(f"\n  AUDIT-LOCK TRIGGER: head mismatch — {v.get('reason')}", file=sys.stderr)
        return 1

    print(f"\n  OK — checkpoint accepted and verified ({v['reason']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
