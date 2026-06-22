"""Webhook notifier — fires on governance anomaly state changes.

Triggers:
  - VPS replica goes offline (any of witness / bpc_replica / tsk_replica)
  - BPC failed signature count exceeds threshold
  - TSK anomaly state changes (connected → anomaly detected)
  - Fleet guard halts an agent (external call from fleet guard)

Config via .witness.env or environment variables:
  WEBHOOK_URL      — Slack incoming webhook URL (or any HTTP POST endpoint)
  WEBHOOK_ENABLED  — "1" to enable (default off)
  WEBHOOK_FAILED_SIG_THRESHOLD — int, default 3

State is held in module-level dicts so repeated polls don't re-fire on
the same condition. Call notify_governance(data) on every governance poll;
it compares against prior state and fires only on transitions.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

# ── config ────────────────────────────────────────────────────────────────────

def _load_env() -> None:
    env_file = Path(__file__).resolve().parent.parent / ".witness.env"
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip())


_load_env()

WEBHOOK_URL: str = os.environ.get("WEBHOOK_URL", "")
WEBHOOK_ENABLED: bool = os.environ.get("WEBHOOK_ENABLED", "0") == "1"
FAILED_SIG_THRESHOLD: int = int(os.environ.get("WEBHOOK_FAILED_SIG_THRESHOLD", "3"))

# ── prior-state tracking ──────────────────────────────────────────────────────

_prior: dict = {
    "vps_witness": None,     # True/False/None
    "vps_bpc": None,
    "vps_tsk": None,
    "bpc_failed_sigs": 0,
    "tsk_anomaly": None,     # True/False/None
}

# ── HTTP dispatch ─────────────────────────────────────────────────────────────

def _post_webhook(payload: dict) -> bool:
    if not WEBHOOK_URL:
        return False
    try:
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            WEBHOOK_URL,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status < 300
    except Exception:
        return False


def _slack(text: str, color: str = "#ff0000") -> dict:
    return {"attachments": [{"color": color, "text": text, "ts": int(time.time())}]}


# ── public API ────────────────────────────────────────────────────────────────

def notify_governance(data: dict) -> list[str]:
    """Compare governance poll data against prior state; fire webhooks on
    transitions. Returns list of event strings fired (empty if none)."""
    if not WEBHOOK_ENABLED or not WEBHOOK_URL:
        return []

    fired: list[str] = []
    vps = data.get("vps", {})
    bpc = data.get("bpc", {})
    tsk = data.get("tsk", {})

    # ── VPS replica offline transition ────────────────────────────────────────
    for key, subkey, label in [
        ("vps_witness", "witness", "Witness"),
        ("vps_bpc",     "bpc_replica", "BPC Replica"),
        ("vps_tsk",     "tsk_replica", "TSK Replica"),
    ]:
        cur = vps.get(subkey, {}).get("connected")
        prev = _prior[key]
        if prev is True and cur is False:
            msg = f"⚠️ *{label}* VPS endpoint went OFFLINE"
            _post_webhook(_slack(msg, "#ff0000"))
            fired.append(f"vps_offline:{subkey}")
        elif prev is False and cur is True:
            msg = f"✅ *{label}* VPS endpoint back ONLINE"
            _post_webhook(_slack(msg, "#36a64f"))
            fired.append(f"vps_online:{subkey}")
        _prior[key] = cur

    # ── BPC failed signature threshold ───────────────────────────────────────
    total_failed = sum(
        p.get("failedSigs", 0) for p in bpc.get("pairs", [])
    )
    if total_failed >= FAILED_SIG_THRESHOLD and _prior["bpc_failed_sigs"] < FAILED_SIG_THRESHOLD:
        msg = (
            f"🔴 *BPC Failed Signatures* crossed threshold "
            f"({total_failed} ≥ {FAILED_SIG_THRESHOLD}). "
            f"Check audit chain for possible replay/forgery."
        )
        _post_webhook(_slack(msg, "#ff0000"))
        fired.append(f"bpc_failed_sigs:{total_failed}")
    _prior["bpc_failed_sigs"] = total_failed

    # ── TSK anomaly state change ───────────────────────────────────────────────
    tsk_anomaly = tsk.get("anomaly", {})
    cur_anomaly = tsk_anomaly.get("active", False) if tsk_anomaly.get("connected") else None
    prev_anomaly = _prior["tsk_anomaly"]
    if prev_anomaly is False and cur_anomaly is True:
        details = tsk_anomaly.get("details", "")
        msg = f"🔴 *TSK Anomaly Detected*{': ' + details if details else ''}. Review TSK event log."
        _post_webhook(_slack(msg, "#ff0000"))
        fired.append("tsk_anomaly_active")
    elif prev_anomaly is True and cur_anomaly is False:
        _post_webhook(_slack("✅ *TSK Anomaly* cleared.", "#36a64f"))
        fired.append("tsk_anomaly_cleared")
    _prior["tsk_anomaly"] = cur_anomaly

    return fired


def notify_fleet_halt(agent_name: str, reason: str) -> bool:
    """Call from fleet guard when an agent is halted. Always fires regardless
    of WEBHOOK_ENABLED — fleet halts are high-severity events."""
    if not WEBHOOK_URL:
        return False
    msg = (
        f"🛑 *Fleet Guard HALT* — agent `{agent_name}` stopped.\n"
        f"Reason: {reason}\nEvidence written to disk."
    )
    return _post_webhook(_slack(msg, "#ff0000"))
