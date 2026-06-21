"""BPC/TSK governance monitor — HTTP-based, no PostgreSQL required.

BPC demo server: http://localhost:3100  (cd bpc-protocol/demo && npx tsx server.ts)
TSK demo server: http://localhost:3200  (cd tsk-protocol   && npx tsx demo/server.ts)

Configure via config.yaml under the `governance:` key:
  governance:
    bpc_url:         "http://localhost:3100"
    bpc_admin_token: "demo-admin-token"
    bpc_root:        ""          # optional path to bpc-protocol/demo
    tsk_url:         "http://localhost:3200"
    tsk_root:        ""          # optional path to tsk-protocol
    tsk_ndjson:      ""          # optional path to analytics.ndjson
"""
from __future__ import annotations

import base64
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

_TIMEOUT = 4
_CACHE_TTL = 30
_MAX_EVENTS = 20

_cache: dict = {}
_cache_ts: float = 0.0


# ── helpers ───────────────────────────────────────────────────────────────────

def _get(url: str, token: str | None = None, timeout: int = _TIMEOUT) -> dict | list:
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode(errors="replace"))


def _post(url: str, body: dict, token: str | None = None, timeout: int = _TIMEOUT) -> dict:
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode(errors="replace"))


# ── BPC ───────────────────────────────────────────────────────────────────────

def _fetch_bpc(bpc_url: str, admin_token: str) -> dict:
    """Fetch pair list and anomaly state from the BPC HTTP server."""
    try:
        pairs_raw = _get(f"{bpc_url}/bpc/pairs", token=admin_token)
        pairs = pairs_raw.get("pairs", []) if isinstance(pairs_raw, dict) else []
    except urllib.error.HTTPError as e:
        return {"connected": False, "error": f"HTTP {e.code} on /bpc/pairs", "pairs": []}
    except Exception as exc:
        offline = "10061" in str(exc) or "refused" in str(exc) or "10060" in str(exc)
        return {
            "connected": False,
            "offline": offline,
            "error": str(exc)[:100],
            "pairs": [],
        }

    try:
        anomaly_raw = _get(f"{bpc_url}/bpc/anomaly", token=admin_token)
    except Exception:
        anomaly_raw = {}

    active = sum(1 for p in pairs if p.get("status") == "active")
    revoked = sum(1 for p in pairs if p.get("status") == "revoked")

    return {
        "connected": True,
        "pairs": pairs,
        "total": len(pairs),
        "active": active,
        "revoked": revoked,
        "anomaly": anomaly_raw,
    }


# ── TSK ───────────────────────────────────────────────────────────────────────

def _fetch_tsk(tsk_url: str) -> dict:
    try:
        body = _get(f"{tsk_url}/tsk/anomaly")
        return {"connected": True, **body}
    except urllib.error.HTTPError as e:
        return {"connected": False, "error": f"HTTP {e.code}"}
    except Exception as exc:
        offline = "10061" in str(exc) or "refused" in str(exc) or "10060" in str(exc)
        return {"connected": False, "offline": offline, "error": str(exc)[:80]}


def _parse_tsk_ndjson(ndjson_path: str) -> list[dict]:
    p = Path(ndjson_path) if ndjson_path else None
    if not p or not p.exists():
        # Try default location
        default = Path.home() / "tsk-protocol" / "demo" / "analytics.ndjson"
        if not default.exists():
            return []
        p = default
    try:
        size = p.stat().st_size
        with open(p, "rb") as fh:
            fh.seek(max(0, size - 40_000))
            tail = fh.read().decode("utf-8", errors="replace")
        events = []
        for line in tail.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return events[-_MAX_EVENTS:]
    except Exception:
        return []


def _resolve_default_tsk_ndjson(gov: dict) -> str:
    configured = str(gov.get("tsk_ndjson", "")).strip()
    if configured:
        return configured
    candidates: list[Path] = []
    root = str(gov.get("tsk_root", "")).strip()
    if root:
        candidates.append(Path(root).expanduser() / "demo" / "analytics.ndjson")
    repo_root = Path(__file__).resolve().parent.parent
    candidates.append(repo_root.parent / "tsk-protocol" / "demo" / "analytics.ndjson")
    candidates.append(Path.home() / "tsk-protocol" / "demo" / "analytics.ndjson")
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return str(candidates[0])


# ── Keypair generation ────────────────────────────────────────────────────────

def generate_bpc_pair(bpc_url: str, name: str, scope: str = "read-write",
                      mode: str = "development") -> dict:
    """Generate a new BPC keypair in Python, register it with the BPC server.

    Returns dict with: pairId, privJwk (copy & store securely), pubJwk, rawSecret.
    """
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend

    # Generate P-256 ECDSA keypair
    priv_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pub_key = priv_key.public_key()
    pub_nums = pub_key.public_numbers()
    priv_nums = priv_key.private_numbers()

    def _b64u(n: int, length: int = 32) -> str:
        return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

    x = _b64u(pub_nums.x)
    y = _b64u(pub_nums.y)
    d = _b64u(priv_nums.private_value)

    pub_jwk: dict = {"kty": "EC", "crv": "P-256", "x": x, "y": y}
    priv_jwk: dict = {"kty": "EC", "crv": "P-256", "x": x, "y": y, "d": d}

    # Generate random secret and derive secretHash using BPC HKDF spec
    raw_sec = os.urandom(32)
    raw_sec_b64 = base64.urlsafe_b64encode(raw_sec).rstrip(b"=").decode()

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"bpc-protocol-hmac-salt-v1",
        info=b"bpc-v1-hmac-key",
        backend=default_backend(),
    )
    secret_hash = base64.urlsafe_b64encode(hkdf.derive(raw_sec)).rstrip(b"=").decode()

    # Register with BPC server
    result = _post(f"{bpc_url}/bpc/register", {
        "name": name,
        "scope": scope,
        "mode": mode,
        "secretHash": secret_hash,
        "pubJwk": pub_jwk,
    })

    return {
        "pairId": result.get("pairId"),
        "status": result.get("status", "unknown"),
        "privJwk": priv_jwk,
        "pubJwk": pub_jwk,
        "rawSecret": raw_sec_b64,
        "name": name,
        "scope": scope,
        "mode": mode,
    }


def revoke_bpc_pair(bpc_url: str, pair_id: str) -> dict:
    """Revoke a BPC pair by ID."""
    try:
        return _post(f"{bpc_url}/bpc/revoke", {"pairId": pair_id})
    except Exception as exc:
        return {"revoked": False, "error": str(exc)[:100]}


# ── Combined ──────────────────────────────────────────────────────────────────

def get_governance(force: bool = False) -> dict:
    """Return merged BPC + TSK state. Uses 30s cache."""
    global _cache, _cache_ts

    if not force and _cache and (time.time() - _cache_ts) < _CACHE_TTL:
        return _cache

    from core import config as cfg
    gov = cfg.get().get("governance", {})

    bpc_url = gov.get("bpc_url", "http://localhost:3100")
    admin_token = gov.get("bpc_admin_token", "demo-admin-token")
    tsk_url = gov.get("tsk_url", "http://localhost:3200")
    tsk_ndjson = _resolve_default_tsk_ndjson(gov)

    bpc = _fetch_bpc(bpc_url, admin_token)
    tsk_anomaly = _fetch_tsk(tsk_url)
    tsk_events = _parse_tsk_ndjson(tsk_ndjson)

    result = {
        "checked_at": time.strftime("%H:%M:%S"),
        "bpc_url": bpc_url,
        "tsk_url": tsk_url,
        "bpc": bpc,
        "tsk": {
            "anomaly": tsk_anomaly,
            "recent_events": tsk_events,
        },
    }

    _cache = result
    _cache_ts = time.time()
    return result
