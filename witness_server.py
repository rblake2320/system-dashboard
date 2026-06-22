"""External audit-chain witness server (HA Phase 3).

A minimal, standalone append-only witness for BPC/TSK audit-chain heads. The
primary pushes a signed checkpoint after each audit append; the witness verifies
the HMAC signature and appends it to an append-only NDJSON log. If the primary's
local chain head ever disagrees with the last witnessed head, the primary can
detect a chain rewrite (tamper) it could not detect from its own state alone.

Security posture:
  - Holds ONLY chain head HASHES + counts + timestamps. No private keys, no raw
    secrets, no BPC/TSK binding material. A full compromise of this server yields
    a list of hashes — nothing forgeable.
  - Every checkpoint is HMAC-SHA256 signed with a witness PRE-SHARED key
    (separate from BPC/TSK keys). The witness rejects unsigned/forged checkpoints,
    so a compromised primary cannot poison the witness with false heads without
    the shared key.
  - Append-only: checkpoints are never overwritten; the full history is retained.

Run locally:   WITNESS_KEY=... python witness_server.py  (default port 3300)
Deploy:        same file on the Hostinger VPS behind HTTPS (Phase 5).
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

from flask import Flask, jsonify, request

try:
    from core.witness_sig import verify_checkpoint
except ImportError:  # allow running as a standalone file on the VPS
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from core.witness_sig import verify_checkpoint

_LOG_LOCK = threading.Lock()


def create_witness_app(witness_key: str, log_path: str | Path) -> Flask:
    """Build the witness Flask app. `witness_key` is the pre-shared HMAC key."""
    app = Flask(__name__)
    log_path = Path(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    def _last_checkpoint(principal_id: str) -> dict | None:
        if not log_path.exists():
            return None
        last = None
        with open(log_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("principal_id") == principal_id:
                    last = rec
        return last

    @app.post("/witness/checkpoint")
    def checkpoint():
        body = request.get_json(silent=True) or {}
        principal_id = body.get("principal_id")
        chain_head_hash = body.get("chain_head_hash")
        entry_count = body.get("entry_count")
        timestamp = body.get("timestamp")
        sig = body.get("sig")

        if not all(isinstance(x, str) and x for x in (principal_id, chain_head_hash, timestamp, sig)):
            return jsonify({"ok": False, "error": "missing_fields"}), 400
        if not isinstance(entry_count, int):
            return jsonify({"ok": False, "error": "bad_entry_count"}), 400

        # Constant-time HMAC verify — a compromised primary without the key can't forge.
        if not verify_checkpoint(witness_key, principal_id, chain_head_hash, entry_count, timestamp, sig):
            return jsonify({"ok": False, "error": "bad_signature"}), 401

        record = {
            "principal_id": principal_id,
            "chain_head_hash": chain_head_hash,
            "entry_count": entry_count,
            "timestamp": timestamp,
            "sig": sig,
            "witnessed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        with _LOG_LOCK:
            with open(log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        return jsonify({"ok": True, "witnessed": record})

    @app.get("/witness/verify/<principal_id>")
    def verify(principal_id: str):
        last = _last_checkpoint(principal_id)
        if last is None:
            return jsonify({"ok": True, "found": False, "checkpoint": None})
        return jsonify({"ok": True, "found": True, "checkpoint": last})

    @app.get("/witness/health")
    def health():
        return jsonify({"ok": True, "service": "witness", "ts": time.time()})

    return app


def main() -> None:
    key = os.environ.get("WITNESS_KEY", "")
    if not key:
        raise SystemExit("WITNESS_KEY env var is required (witness pre-shared key)")
    port = int(os.environ.get("WITNESS_PORT", "3300"))
    log = os.environ.get("WITNESS_LOG", str(Path(__file__).resolve().parent / "evidence" / "witness_log.ndjson"))
    app = create_witness_app(key, log)
    print(f"Witness server -> http://127.0.0.1:{port}  (log: {log})")
    app.run(host=os.environ.get("WITNESS_HOST", "127.0.0.1"), port=port, threaded=True)


if __name__ == "__main__":
    main()
