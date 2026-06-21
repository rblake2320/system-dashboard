"""System Dashboard — main Flask app with SSE fix streaming."""
from __future__ import annotations

import json
import logging
import logging.handlers
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request
from pathlib import Path

# Ensure stdout handles unicode on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Add project root to path
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# ── Error log (separate from Flask access log) ────────────────────────────────
_LOG_DIR = _ROOT / "logs"
_LOG_DIR.mkdir(exist_ok=True)
_error_log = logging.getLogger("dashboard.errors")
_error_log.setLevel(logging.ERROR)
_err_handler = logging.handlers.RotatingFileHandler(
    _LOG_DIR / "error.log", maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8"
)
_err_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
_error_log.addHandler(_err_handler)
_error_log.addHandler(logging.StreamHandler(sys.stderr))

import datetime

from flask import Flask, Response, jsonify, request, stream_with_context

from core import config as cfg, collector, issues as issue_mod
from core.persistence import db
from core.auth import require_token, generate_token, print_startup_token, issue_sse_ticket, require_sse_ticket
from core.audit import log_action
from core.pid_guard import pid_guard
from core.key_monitor import check_all_keys, refresh_provider, set_provider_key, clear_provider_key, _PROVIDERS as _KEY_PROVIDERS
from core.session_monitor import scan_sessions
from core.memoryweb_monitor import get_status as mw_status
from core.bpc_monitor import get_governance, generate_bpc_pair, revoke_bpc_pair
from core import fleet_registry as _fleet
from core import fleet_guard as _guard
from core import fleet_evidence as _evidence
from core import bpc_audit_chain as _bpc_audit
from core import server_health as _svc_health
from core.tokens import create_token, list_tokens, validate_token, revoke_token, delete_token, SCOPES as TOKEN_SCOPES
from daemon.monitor import daemon, alert_history
from agents.ollama import get_agent
from fixers.process_fixer import ProcessFixer
from fixers.service_fixer import ServiceFixer, StorageFixer

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


@app.errorhandler(Exception)
def _handle_unhandled(exc: Exception):
    tb = traceback.format_exc()
    _error_log.error("Unhandled exception on %s %s\n%s", request.method, request.path, tb)
    return jsonify({"error": "internal error", "detail": str(exc)}), 500

FIXERS = {f.fixer_id: f for f in [ProcessFixer(), ServiceFixer(), StorageFixer()]}

# ── Bootstrap ──────────────────────────────────────────────────────────────────

def _start_daemon() -> None:
    import threading as _th
    dcfg = cfg.daemon()
    if not dcfg.get("enabled", True):
        return
    daemon.start()
    print("[dashboard] Background monitor started")

    # Watchdog: check every 60s if the daemon thread is still alive; restart if not
    def _watchdog() -> None:
        import time as _time
        while True:
            _time.sleep(60)
            if not (daemon._thread and daemon._thread.is_alive()):
                print("[watchdog] Daemon thread died — restarting")
                try:
                    daemon.start()
                except Exception as exc:
                    print(f"[watchdog] restart failed: {exc}")
    _th.Thread(target=_watchdog, daemon=True, name="daemon-watchdog").start()


# ── Token auth middleware (optional — records usage when header present) ───────

@app.before_request
def _record_token_use():
    """If X-Dashboard-Token header is present, validate and record the call."""
    raw = request.headers.get("X-Dashboard-Token", "").strip()
    if raw:
        result = validate_token(raw)
        if not result:
            return jsonify({"error": "Invalid or revoked token"}), 401
        # Attach scope to request context for downstream use
        request.token_scope = result.get("scope", "read")
    else:
        request.token_scope = None  # unauthenticated (localhost-only anyway)


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return _HTML, 200, {"Content-Type": "text/html; charset=utf-8"}


@app.route("/api/status")
def api_status():
    snap = daemon.latest()
    if not snap:
        snap = collector.build_snapshot()
        detected = issue_mod.detect_issues(snap)
        issue_mod.registry.update(detected)
        snap["issues"] = [i.as_dict() for i in issue_mod.registry.get_active()]
        snap["alert_history"] = alert_history.get(50)
        snap["disk_io"] = {}
        # Load sparkline history from DB when in-memory rolling is empty
        snap["history"] = {}
        for metric in ("cpu_pct", "ram_pct", "gpu0_pct", "gpu0_mem_pct"):
            rows = db.get_metric_history(metric, limit=60)
            if rows:
                rows.reverse()  # oldest first for sparklines
                snap["history"][metric] = [r["value"] for r in rows]
    elif not snap.get("history"):
        # Daemon is live but history dict is somehow empty — fill from DB
        snap["history"] = {}
        for metric in ("cpu_pct", "ram_pct", "gpu0_pct", "gpu0_mem_pct"):
            rows = db.get_metric_history(metric, limit=60)
            if rows:
                rows.reverse()
                snap["history"][metric] = [r["value"] for r in rows]
    snap["daemon_alive"] = not daemon.is_stale
    snap["last_tick_ts"] = daemon._last_tick_ts
    snap["fleet"] = _fleet.get_fleet()
    snap["fleet_guard"] = _guard.get_guard_state()
    return jsonify(snap)


@app.route("/api/issues")
def api_issues():
    return jsonify([i.as_dict() for i in issue_mod.registry.get_active()])


@app.route("/api/issues/<issue_id>/acknowledge", methods=["POST"])
def api_acknowledge(issue_id: str):
    issue = issue_mod.registry.get(issue_id)
    if not issue:
        return jsonify({"error": "Issue not found"}), 404
    issue_mod.registry.acknowledge(issue_id)
    return jsonify({"ok": True, "state": "acknowledged"})


@app.route("/api/issues/<issue_id>/suppress", methods=["POST"])
def api_suppress(issue_id: str):
    issue = issue_mod.registry.get(issue_id)
    if not issue:
        return jsonify({"error": "Issue not found"}), 404
    data = request.get_json(force=True) or {}
    minutes = data.get("until_minutes", 60)
    until_ts = time.time() + float(minutes) * 60
    issue_mod.registry.suppress(issue_id, until_ts=until_ts)
    return jsonify({"ok": True, "state": "suppressed", "until_ts": until_ts})


@app.route("/api/alert_history")
def api_alert_history():
    # Merge in-memory (newest events, may include current session) with DB (survives restarts)
    mem_alerts = alert_history.get(100)
    mem_ids = {a["id"] for a in mem_alerts}
    db_alerts = db.get_alerts(limit=100)
    # Convert DB rows to the same shape as in-memory alerts
    for row in db_alerts:
        if row["issue_id"] not in mem_ids:
            mem_alerts.append({
                "id": row["issue_id"],
                "severity": row["severity"],
                "title": row["title"],
                "ts": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row["ts"])),
                "ts_epoch": row["ts"],
            })
    # Sort combined list newest-first and cap at 100
    mem_alerts.sort(key=lambda x: x.get("ts_epoch", 0), reverse=True)
    return jsonify(mem_alerts[:100])


@app.route("/api/actions")
def api_actions():
    return jsonify(db.get_actions(limit=100))


@app.route("/api/keys")
def api_keys():
    """Return masked API key health status for all configured providers."""
    force = request.args.get("refresh") == "1"
    return jsonify(check_all_keys(force=force))


@app.route("/api/keys/<provider_id>/refresh", methods=["POST"])
def api_key_refresh(provider_id: str):
    """Force-refresh a single provider's key status."""
    result = refresh_provider(provider_id)
    if result is None:
        return jsonify({"error": f"Unknown provider: {provider_id}"}), 404
    return jsonify(result)


@app.route("/api/keys/<provider_id>/set", methods=["POST"])
def api_key_set(provider_id: str):
    """Set an API key for a provider. Persists to .env.local."""
    pdef = _KEY_PROVIDERS.get(provider_id)
    if not pdef:
        return jsonify({"error": f"Unknown provider: {provider_id}"}), 404
    body = request.get_json(silent=True) or {}
    key_value = (body.get("key") or "").strip()
    env_var = (body.get("env_var") or (pdef.get("env_vars") or [""])[0]).strip()
    model_value = (body.get("model") or "").strip()
    model_env_var = pdef.get("model_env_var", "")
    if not env_var:
        return jsonify({"error": "No env_var for this provider"}), 400
    if not key_value:
        clear_provider_key(provider_id, env_var)
        return jsonify({"ok": True, "action": "cleared", "env_var": env_var})
    set_provider_key(provider_id, env_var, key_value)
    if model_value and model_env_var:
        set_provider_key(provider_id, model_env_var, model_value)
    result = refresh_provider(provider_id)
    return jsonify({"ok": True, "action": "set", "env_var": env_var, "model": model_value or None, "status": result})


@app.route("/api/sessions")
def api_sessions():
    """Claude Code context-burn metrics for active sessions."""
    return jsonify(scan_sessions())


@app.route("/api/sessions/<session_id>/resume", methods=["POST"])
def api_session_resume(session_id: str):
    """Launch a new terminal window with claude --resume <session_id>."""
    sessions = scan_sessions()
    session = next((s for s in sessions if s["session_id"] == session_id), None)
    if not session:
        return jsonify({"error": "Session not found (may have expired from 24h window)"}), 404

    # Decode slug to project directory: C--Users-techai → C:\Users\techai
    slug = session.get("slug", "")
    project_dir = str(Path.home())
    if "--" in slug:
        parts = slug.split("--", 1)
        drive = parts[0]
        rest = parts[1].replace("-", "\\")
        candidate = Path(f"{drive}:\\{rest}")
        if candidate.exists():
            project_dir = str(candidate)

    cmd = f"claude --resume {session_id}"
    try:
        # CREATE_NEW_CONSOLE opens a visible window (incompatible with DETACHED_PROCESS on Windows)
        creationflags = subprocess.CREATE_NEW_CONSOLE | subprocess.CREATE_NEW_PROCESS_GROUP
        subprocess.Popen(
            ["powershell.exe", "-NoProfile", "-NoExit", "-Command",
             f"Set-Location '{project_dir}'; {cmd}"],
            creationflags=creationflags,
        )
        return jsonify({"ok": True, "cmd": cmd, "dir": project_dir})
    except Exception as e:
        _error_log.error("session resume %s failed\n%s", session_id, traceback.format_exc())
        return jsonify({"error": str(e)}), 500


@app.route("/api/memoryweb")
def api_memoryweb():
    """MemoryWeb health status."""
    force = request.args.get("refresh") == "1"
    return jsonify(mw_status(force=force))


@app.route("/api/smart_debug")
def api_smart_debug():
    """Debug endpoint — call get_smart_health() live and return result + timing."""
    import time as _t
    t0 = _t.time()
    result = collector.get_smart_health()
    elapsed = round(_t.time() - t0, 2)
    return jsonify({"smart": result, "elapsed_s": elapsed, "count": len(result)})


@app.route("/api/fleet")
def api_fleet():
    return jsonify({"agents": _fleet.get_fleet()})


@app.route("/api/fleet/register", methods=["POST"])
def api_fleet_register():
    data = request.get_json(force=True) or {}
    _fleet.register_agent(
        name=str(data.get("name", "unknown")),
        pid=int(data.get("pid", 0)),
        task=str(data.get("task", "")),
    )
    return jsonify({"ok": True})


@app.route("/api/fleet/heartbeat", methods=["POST"])
def api_fleet_heartbeat():
    data = request.get_json(force=True) or {}
    _fleet.heartbeat_agent(
        name=str(data.get("name", "")),
        status=str(data.get("status", "working")),
        progress=int(data.get("progress", 0)),
        note=str(data.get("note", "")),
    )
    return jsonify({"ok": True})


@app.route("/api/fleet/done", methods=["POST"])
def api_fleet_done():
    data = request.get_json(force=True) or {}
    _fleet.complete_agent(
        name=str(data.get("name", "")),
        result=str(data.get("result", "success")),
    )
    return jsonify({"ok": True})


@app.route("/api/fleet/<name>", methods=["DELETE"])
def api_fleet_remove(name):
    _fleet.remove_agent(name)
    return jsonify({"ok": True})


@app.route("/api/fleet/<name>/kill", methods=["POST"])
def api_fleet_kill(name):
    ok = _fleet.kill_agent(name)
    return jsonify({"ok": ok})


@app.route("/api/fleet/event", methods=["POST"])
def api_fleet_event():
    data = request.get_json(force=True) or {}
    _guard.record_event(
        event_type=str(data.get("event_type", "")),
        agent_name=str(data.get("agent_name", "")),
        metadata=data.get("metadata", {}),
    )
    return jsonify({"ok": True, "guard_state": _guard.get_guard_state()["state"]})


@app.route("/api/fleet/guard")
def api_fleet_guard():
    return jsonify(_guard.get_guard_state())


@app.route("/api/fleet/guard/resume", methods=["POST"])
def api_fleet_guard_resume():
    data = request.get_json(force=True) or {}
    _guard.resume(operator_note=str(data.get("note", "")))
    return jsonify({"ok": True})


@app.route("/api/fleet/evidence")
def api_fleet_evidence_list():
    return jsonify({"halts": _evidence.list_halts()})


@app.route("/api/fleet/evidence/<halt_id>")
def api_fleet_evidence_get(halt_id):
    data = _evidence.get_halt(halt_id)
    if data is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(data)


@app.route("/api/governance")
def api_governance():
    """BPC/TSK governance events and anomaly state."""
    force = request.args.get("refresh") == "1"
    return jsonify(get_governance(force=force))


@app.route("/api/bpc/generate", methods=["POST"])
def api_bpc_generate():
    """Generate a new BPC keypair, register it, and write a chained audit entry."""
    from core import config as cfg
    gov = cfg.get().get("governance", {})
    bpc_url = gov.get("bpc_url", "http://localhost:3100")
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "dashboard-pair").strip()[:64] or "dashboard-pair"
    scope = body.get("scope", "read-write")
    mode = body.get("mode", "development")
    if scope not in ("read", "read-write", "admin"):
        scope = "read-write"
    if mode not in ("development", "production"):
        mode = "development"
    try:
        result = generate_bpc_pair(bpc_url, name, scope, mode)
        _bpc_audit.append("generate", result.get("pairId", "unknown"),
                          metadata={"name": name, "scope": scope, "mode": mode})
        return jsonify(result)
    except Exception as exc:
        _error_log.error("BPC generate failed: %s", exc)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/bpc/revoke/<pair_id>", methods=["POST"])
def api_bpc_revoke(pair_id: str):
    """Revoke a BPC pair and write a chained audit entry."""
    from core import config as cfg
    gov = cfg.get().get("governance", {})
    bpc_url = gov.get("bpc_url", "http://localhost:3100")
    result = revoke_bpc_pair(bpc_url, pair_id)
    if result.get("revoked"):
        _bpc_audit.append("revoke", pair_id)
    return jsonify(result)


@app.route("/api/bpc/rotate/<old_pair_id>", methods=["POST"])
def api_bpc_rotate(old_pair_id: str):
    """Proxy a signed BPC rotation request to the BPC server.

    The browser builds and signs the RotationRequest using Web Crypto (old privJwk
    never leaves the client). This route validates shape then proxies to BPC.
    """
    from core import config as cfg
    gov = cfg.get().get("governance", {})
    bpc_url = gov.get("bpc_url", "http://localhost:3100")
    body = request.get_json(silent=True) or {}
    required = {"oldPairId", "newPubJwk", "signature", "signedData", "timestamp"}
    missing = required - body.keys()
    if missing:
        return jsonify({"error": f"missing fields: {sorted(missing)}"}), 400
    if body.get("oldPairId") != old_pair_id:
        return jsonify({"error": "oldPairId mismatch"}), 400
    try:
        data = json.dumps(body).encode()
        req = urllib.request.Request(
            f"{bpc_url}/bpc/rotate", data=data,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            result = json.loads(resp.read().decode())
        if result.get("newPairId"):
            _bpc_audit.append("rotate", old_pair_id,
                              metadata={"new_pair_id": result["newPairId"]})
        return jsonify(result)
    except urllib.error.HTTPError as e:
        body_err = e.read().decode(errors="replace")
        return jsonify({"error": body_err}), e.code
    except Exception as exc:
        _error_log.error("BPC rotate proxy failed: %s", exc)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/bpc/audit")
def api_bpc_audit():
    """Return recent hash-chained audit entries and chain integrity check."""
    n = int(request.args.get("n", 30))
    entries = _bpc_audit.tail(n)
    integrity = _bpc_audit.verify_chain()
    return jsonify({"entries": entries, "integrity": integrity})


@app.route("/api/gov/health")
def api_gov_health():
    """Return PID health for BPC and TSK servers."""
    return jsonify(_svc_health.get_health())


def _governance_repo_path(config_key: str, *default_parts: str) -> Path:
    """Resolve a governance repo path from config, sibling checkout, then home."""
    from core import config as cfg
    gov = cfg.get().get("governance", {})
    configured = str(gov.get(config_key, "")).strip()
    candidates: list[Path] = []
    if configured:
        candidates.append(Path(configured).expanduser())
    candidates.append(_ROOT.parent.joinpath(*default_parts))
    candidates.append(Path.home().joinpath(*default_parts))
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


@app.route("/api/bpc/start", methods=["POST"])
def api_bpc_start():
    """Start the BPC demo server and track its PID."""
    bpc_dir = str(_governance_repo_path("bpc_root", "bpc-protocol", "demo"))
    try:
        proc = subprocess.Popen(
            ["powershell.exe", "-NoProfile", "-NoExit", "-Command",
             f"Set-Location '{bpc_dir}'; npx tsx server.ts"],
            creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.CREATE_NEW_PROCESS_GROUP,
        )
        _svc_health.register("bpc", proc.pid, f"npx tsx server.ts in {bpc_dir}")
        return jsonify({"started": True, "pid": proc.pid, "dir": bpc_dir})
    except Exception as exc:
        return jsonify({"started": False, "error": str(exc)}), 500


@app.route("/api/tsk/start", methods=["POST"])
def api_tsk_start():
    """Start the TSK demo server and track its PID."""
    tsk_dir = str(_governance_repo_path("tsk_root", "tsk-protocol"))
    try:
        proc = subprocess.Popen(
            ["powershell.exe", "-NoProfile", "-NoExit", "-Command",
             f"Set-Location '{tsk_dir}'; npx tsx demo/server.ts"],
            creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.CREATE_NEW_PROCESS_GROUP,
        )
        _svc_health.register("tsk", proc.pid, f"npx tsx demo/server.ts in {tsk_dir}")
        return jsonify({"started": True, "pid": proc.pid, "dir": tsk_dir})
    except Exception as exc:
        return jsonify({"started": False, "error": str(exc)}), 500


# ── Dashboard API Token Management ────────────────────────────────────────────

@app.route("/api/tokens")
def api_tokens_list():
    """List all dashboard API tokens (id, name, scope, usage — never raw value)."""
    return jsonify({"tokens": list_tokens(), "scopes": TOKEN_SCOPES})


@app.route("/api/tokens", methods=["POST"])
def api_tokens_create():
    """Create a new scoped dashboard API token. Raw value returned ONCE."""
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    scope = (body.get("scope") or "read").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400
    token = create_token(name, scope)
    return jsonify({"ok": True, "token": token})


@app.route("/api/tokens/<token_id>/revoke", methods=["POST"])
def api_tokens_revoke(token_id: str):
    ok = revoke_token(token_id)
    return jsonify({"ok": ok})


@app.route("/api/tokens/<token_id>", methods=["DELETE"])
def api_tokens_delete(token_id: str):
    ok = delete_token(token_id)
    return jsonify({"ok": ok})


@app.route("/api/chat", methods=["POST"])
def api_chat():
    """Free-form chat with the configured LLM, with live system snapshot as context."""
    data = request.get_json(force=True)
    message = (data.get("message") or "").strip()
    history = data.get("history", [])   # [{role, content}, ...]
    if not message:
        return jsonify({"error": "Empty message"}), 400

    agent = get_agent()
    if not agent.available():
        return jsonify({"reply": "LLM not available. Set llm.provider in config.yaml (ollama / openai / anthropic)."})

    # Build compact snapshot for system context
    snap = daemon.latest() or {}
    sys_info = snap.get("system", {})
    gpus = sys_info.get("gpus", [])
    raw_issues = snap.get("issues", [])
    active_issues = raw_issues if isinstance(raw_issues, list) else raw_issues.get("active", [])
    issues = [i.get("title", "") for i in active_issues if isinstance(i, dict)]
    system_ctx = {
        "cpu_pct": sys_info.get("cpu_pct"),
        "ram_pct": sys_info.get("ram_pct"),
        "gpus": [{"gpu_pct": g.get("gpu_pct"), "mem_pct": g.get("mem_pct"), "temp_c": g.get("temp_c")} for g in gpus],
        "active_issues": issues[:5],
        "storage": {k: {"free_gb": v.get("free_gb"), "pct": v.get("pct"), "failing": v.get("failing"), "failing_reason": v.get("failing_reason")}
                    for k, v in sys_info.get("drives", {}).items()},
    }

    try:
        reply = agent.chat(message, history=history, system_context=system_ctx)
        return jsonify({"reply": reply})
    except Exception as exc:
        return jsonify({"reply": f"LLM error: {exc}"})


@app.route("/api/cost-history")
def api_cost_history():
    """Return 30-day daily cost snapshots per provider. Pass ?refresh=1 to force a fresh MTD fetch."""
    from core.cost_tracker import snapshot_costs, get_cost_history
    force = request.args.get("refresh") == "1"
    data = snapshot_costs() if force else get_cost_history()
    return jsonify(data)


@app.route("/api/mesh")
def api_mesh():
    """Agent Mesh status — Army OS, Hub, and local agent-status daemon."""
    from core.mesh_monitor import get_mesh_status
    force = request.args.get("refresh") == "1"
    return jsonify(get_mesh_status(force=force))


@app.route("/api/diagnose", methods=["POST"])
def api_diagnose():
    if not require_token(request):
        log_action("diagnose", {}, request.remote_addr or "", "rejected: missing token")
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(force=True)
    issue_id = data.get("issue_id", "")
    issue = issue_mod.registry.get(issue_id)
    if not issue:
        log_action("diagnose", {"issue_id": issue_id}, request.remote_addr or "", "issue not found")
        return jsonify({"error": "Issue not found"}), 404
    agent = get_agent()
    if not agent.available():
        return jsonify({
            "summary": "LLM not available",
            "root_cause": "Configure an LLM provider in config.yaml",
            "suggested_fix": "Set llm.provider to 'ollama', 'openai', or 'anthropic'",
            "confidence": "low",
        })
    snap = daemon.latest() or {}
    context = _build_filtered_context(snap, issue)
    try:
        result = agent.diagnose(issue.as_dict(), context)
        log_action("diagnose", {"issue_id": issue_id}, request.remote_addr or "", "ok")
        return jsonify({
            "summary": result.summary,
            "root_cause": result.root_cause,
            "suggested_fix": result.suggested_fix,
            "fixer_id": result.fixer_id,
            "fix_params": result.fix_params,
            "confidence": result.confidence,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/fix/ticket", methods=["POST"])
def api_fix_ticket():
    """Exchange the main session token (header) for a single-use 30-second SSE ticket.

    EventSource cannot send custom headers, so the UI must POST here first,
    then open the EventSource with ?ticket=<ticket>.  This keeps the main token
    out of the server access log entirely.
    """
    if not require_token(request):
        log_action("fix_ticket", {}, request.remote_addr or "", "rejected: missing token")
        return jsonify({"error": "Unauthorized"}), 401
    ticket = issue_sse_ticket()
    log_action("fix_ticket", {}, request.remote_addr or "", "issued")
    return jsonify({"ticket": ticket})


@app.route("/api/fix/stream")
def api_fix_stream():
    # Validate via single-use SSE ticket (avoids main token in query-string / access log)
    ticket = request.args.get("ticket")
    if not require_sse_ticket(ticket):
        log_action("fix_stream", {}, request.remote_addr or "", "rejected: invalid or missing ticket")
        def _unauth():
            yield "data: Unauthorized\n\n"
            yield "data: FAILED\n\n"
        return Response(stream_with_context(_unauth()), mimetype="text/event-stream", status=401)
    issue_id = request.args.get("issue_id", "")
    issue = issue_mod.registry.get(issue_id)
    if not issue:
        def _err():
            yield "data: Issue not found\n\n"
            yield "data: FAILED\n\n"
        return Response(stream_with_context(_err()), mimetype="text/event-stream")

    fixer_id = issue.fixer_id or request.args.get("fixer_id", "")
    fixer = FIXERS.get(fixer_id)
    if not fixer:
        def _no_fixer():
            yield f"data: No fixer registered for fixer_id '{fixer_id}'\n\n"
            yield "data: DONE\n\n"
        return Response(stream_with_context(_no_fixer()), mimetype="text/event-stream")

    issue_dict = issue.as_dict()

    def _stream():
        try:
            for line in fixer.fix(issue_dict):
                yield f"data: {line}\n\n"
                time.sleep(0.02)
            issue_mod.registry.resolve(issue_id)
        except Exception as exc:
            yield f"data: ERROR: {exc}\n\n"
            yield "data: FAILED\n\n"

    return Response(
        stream_with_context(_stream()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def _build_filtered_context(snap: dict, issue: "issue_mod.Issue") -> dict:
    """Build a compact LLM context dict — max 2000 chars to avoid token exhaustion."""
    sys = snap.get("system", {})
    gpus = sys.get("gpus", [])

    # System: only key percentages
    context: dict = {
        "system": {
            "cpu_pct": sys.get("cpu_pct"),
            "ram_pct": sys.get("ram_pct"),
            "gpus": [{"index": g.get("index"), "gpu_pct": g.get("gpu_pct"), "mem_pct": g.get("mem_pct")} for g in gpus],
        },
    }

    # Processes: the specific process matching the issue + top 5 by memory
    raw_procs = snap.get("processes", {})
    issue_name = (issue.context or {}).get("name", "")
    top5 = sorted(
        [{"name": k, "count": v["count"], "total_mb": v["total_mb"]} for k, v in raw_procs.items()],
        key=lambda x: x["total_mb"], reverse=True,
    )[:5]
    matched = None
    if issue_name:
        matched_data = raw_procs.get(issue_name)
        if matched_data:
            matched = {"name": issue_name, "count": matched_data["count"], "total_mb": matched_data["total_mb"]}
    context["processes"] = {"top5_by_memory": top5}
    if matched:
        context["processes"]["issue_process"] = matched

    # Ports: only downed services
    raw_ports = snap.get("ports", {})
    context["ports_down"] = {k: v.get("label", k) for k, v in raw_ports.items() if not v.get("up")}

    # Issue's own context (already specific)
    if issue.context:
        context["issue_context"] = issue.context

    # Truncate to 2000 chars
    serialized = json.dumps(context, default=str)
    if len(serialized) > 2000:
        serialized = serialized[:1997] + "..."
        # Return a truncated string wrapped so the agent can still decode context
        context = {"_truncated": True, "raw": serialized}

    return context


def _compute_health_score(issues: list) -> int:
    """100 minus 20 per critical, 5 per warning."""
    score = 100
    for iss in issues:
        sev = iss.get("severity") if isinstance(iss, dict) else getattr(iss, "severity", "")
        if sev == "critical":
            score -= 20
        elif sev == "warning":
            score -= 5
    return max(0, score)


@app.route("/api/review")
def api_review():
    """Full system review — fresh snapshot + AI diagnoses on every active issue."""
    with_ai = request.args.get("with_ai", "true").lower() not in ("false", "0", "no")

    # 1. Force fresh snapshot (bypass daemon cache)
    snap = collector.build_snapshot()
    detected = issue_mod.detect_issues(snap)
    issue_mod.registry.update(detected)

    sys = snap.get("system", {})
    gpus = sys.get("gpus", [])
    raw_ports = snap.get("ports", {})
    ports_up = sum(1 for v in raw_ports.values() if v.get("up"))

    drives = sys.get("drives", {})
    drives_summary = {
        lt: {"free_gb": d.get("free_gb"), "pct": d.get("pct"), "failing": d.get("failing", False)}
        for lt, d in drives.items()
    }

    snapshot_summary = {
        "cpu_pct": sys.get("cpu_pct"),
        "ram_pct": sys.get("ram_pct"),
        "gpu_pct": gpus[0].get("gpu_pct") if gpus else None,
        "drives_summary": drives_summary,
        "ports_up_count": ports_up,
    }

    # 2. Build issues list — optionally run AI diagnoses
    active_issues = issue_mod.registry.get_active()
    agent = get_agent() if with_ai else None
    issues_out = []
    for iss in active_issues:
        iss_dict = iss.as_dict()
        if with_ai and agent and agent.available():
            try:
                context = _build_filtered_context(snap, iss)
                result = agent.diagnose(iss_dict, context)
                iss_dict["diagnosis"] = {
                    "summary": result.summary,
                    "root_cause": result.root_cause,
                    "suggested_fix": result.suggested_fix,
                    "fixer_id": result.fixer_id,
                    "fix_params": result.fix_params,
                    "confidence": result.confidence,
                }
            except Exception as exc:
                iss_dict["diagnosis"] = {"error": str(exc)}
            time.sleep(2)  # throttle — max 1 LLM call per 2s to avoid overloading Ollama
        issues_out.append(iss_dict)

    # 3. Top processes by memory and CPU
    raw_procs = snap.get("processes", {})
    all_procs_flat: list[dict] = []
    for name, pdata in raw_procs.items():
        for p in pdata.get("procs", []):
            all_procs_flat.append({
                "name": name,
                "pid": p.get("pid"),
                "mem_mb": p.get("mem_mb", 0),
                "cpu_pct": p.get("cpu_pct", 0),
                "status": p.get("status"),
            })

    top_by_mem = sorted(all_procs_flat, key=lambda x: x["mem_mb"], reverse=True)[:5]
    top_by_cpu = sorted(all_procs_flat, key=lambda x: x["cpu_pct"], reverse=True)[:5]

    return jsonify({
        "ts": snap.get("ts"),
        "snapshot_summary": snapshot_summary,
        "issues": issues_out,
        "top_processes_by_memory": top_by_mem,
        "top_processes_by_cpu": top_by_cpu,
        "health_score": _compute_health_score(issues_out),
    })


@app.route("/api/export")
def api_export():
    """Download a JSON bundle of the current system state and issue history."""
    snap = daemon.latest() or collector.build_snapshot()
    active_issues = issue_mod.registry.get_active()
    issues_list = [i.as_dict() for i in active_issues]

    bundle = {
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "dashboard_version": "2.0.0",
        "system": snap,
        "issues": issues_list,
        "alert_history": alert_history.get(50),
        "health_score": _compute_health_score(issues_list),
    }

    date_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    filename = f"system-review-{date_str}.json"

    return Response(
        json.dumps(bundle, indent=2, default=str),
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.route("/api/kill_pid", methods=["POST"])
def api_kill_pid():
    if not require_token(request):
        log_action("kill_pid", {}, request.remote_addr or "", "rejected: missing token")
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(force=True)
    pid = data.get("pid")
    if not pid:
        return jsonify({"error": "pid required"}), 400
    try:
        pid = int(pid)
    except (ValueError, TypeError):
        return jsonify({"error": "pid must be an integer"}), 400
    snap = daemon.latest() or {}

    # Capture process identity at validation time to defend against PID-reuse races.
    # We record (name, create_time) now and re-verify them immediately before killing.
    try:
        import psutil as _psutil
        _proc_snapshot = _psutil.Process(pid)
        _snap_name = _proc_snapshot.name()
        _snap_ctime = _proc_snapshot.create_time()
    except Exception:
        _snap_name = None
        _snap_ctime = None

    ok, reason = pid_guard.validate_kill(pid, snap)
    log_action(
        "kill_pid",
        {"pid": pid},
        request.remote_addr or "",
        f"{"allowed" if ok else "blocked"}: {reason}",
        pid_validated=ok,
    )
    if not ok:
        return jsonify({"error": f"Kill blocked: {reason}"}), 403

    # Re-verify identity before executing kill to prevent PID-reuse race.
    if _snap_name is not None and _snap_ctime is not None:
        try:
            import psutil as _psutil2
            _proc_now = _psutil2.Process(pid)
            if _proc_now.name() != _snap_name or abs(_proc_now.create_time() - _snap_ctime) > 1.0:
                log_action("kill_pid", {"pid": pid}, request.remote_addr or "", "blocked: PID reuse detected")
                return jsonify({"error": "Kill blocked: process identity changed (PID reuse detected)"}), 409
        except Exception:
            pass  # process already gone — fixer will handle it

    fixer = ProcessFixer()
    lines = list(fixer.fix({"fixer_id": "process_fixer", "fix_params": {"action": "kill_by_pid", "pid": pid}}))
    success = any("DONE" in line for line in lines)
    return jsonify({"output": lines, "success": success})




# ── Security utility routes ────────────────────────────────────────────────────

@app.route("/api/token")
def api_token():
    """Return the session token — only accessible from localhost."""
    remote = request.remote_addr or ""
    if not (remote.startswith("127.") or remote == "::1"):
        return jsonify({"error": "Forbidden: localhost only"}), 403
    return jsonify({"token": generate_token()})


@app.route("/api/audit")
def api_audit():
    """Return the last 100 audit log entries."""
    from core.audit import audit_log
    return jsonify(audit_log.tail(100))


# ── HTML ────────────────────────────────────────────────────────────────────────

_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>System Dashboard</title>
<style>
:root{
  --bg:#0d0d0f;--surface:#16181e;--surface2:#1e2028;--border:#2a2d38;
  --text:#e2e4ec;--muted:#6b7280;--accent:#6366f1;--accent2:#8b5cf6;
  --green:#22c55e;--yellow:#eab308;--red:#ef4444;--orange:#f97316;
  --blue:#3b82f6;--cyan:#06b6d4;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;line-height:1.5}
a{color:inherit;text-decoration:none}

.topbar{display:flex;align-items:center;justify-content:space-between;padding:12px 20px;background:var(--surface);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:100}
.topbar h1{font-size:17px;font-weight:600;letter-spacing:.3px}
.topbar .meta{display:flex;gap:16px;align-items:center;font-size:12px;color:var(--muted)}
.dot-live{width:8px;height:8px;border-radius:50%;background:var(--green);animation:pulse 2s infinite}
.dot-stale{width:8px;height:8px;border-radius:50%;background:var(--red);animation:pulse 2s infinite}
.stale-banner{display:none;background:rgba(239,68,68,.15);border:1px solid var(--red);border-radius:6px;padding:4px 12px;font-size:12px;font-weight:600;color:var(--red);animation:pulse 1.5s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.main{padding:16px 20px;display:flex;flex-direction:column;gap:16px}

.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px 16px}
.card-title{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.8px;color:var(--muted);margin-bottom:12px}

.grid-3{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
.grid-2{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}
.grid-auto{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:10px}
@media(max-width:900px){.grid-3,.grid-2{grid-template-columns:1fr}}

.metric-big{font-size:26px;font-weight:700;line-height:1}
.metric-sub{font-size:11px;color:var(--muted);margin-top:3px}
.bar-track{height:6px;background:var(--border);border-radius:4px;margin-top:8px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;transition:width .5s ease}
.bar-green{background:var(--green)}
.bar-yellow{background:var(--yellow)}
.bar-red{background:var(--red)}

svg.spark{width:100%;height:36px;display:block;margin-top:8px}

.issue-card{background:var(--surface2);border-radius:8px;padding:12px 14px;border-left:3px solid transparent;margin-bottom:8px}
.issue-card.critical{border-left-color:var(--red);background:rgba(239,68,68,.06)}
.issue-card.warning{border-left-color:var(--yellow);background:rgba(234,179,8,.04)}
.issue-card.info{border-left-color:var(--blue)}
.issue-title{font-size:13px;font-weight:600;margin-bottom:4px}
.issue-desc{font-size:12px;color:var(--muted)}
.issue-actions{display:flex;gap:8px;margin-top:10px}
.btn{display:inline-flex;align-items:center;gap:5px;padding:5px 12px;border-radius:6px;font-size:12px;font-weight:500;cursor:pointer;border:none;transition:opacity .15s}
.btn:hover{opacity:.85}
.btn-diagnose{background:var(--accent);color:#fff}
.btn-fix{background:var(--green);color:#000}
.btn-danger{background:var(--red);color:#fff}
.btn-neutral{background:var(--surface2);color:var(--text);border:1px solid var(--border)}
.btn-ack{background:rgba(234,179,8,.2);color:var(--yellow);border:1px solid var(--yellow)}
.btn-suppress{background:rgba(107,114,128,.15);color:var(--muted);border:1px solid var(--border)}
.state-badge{display:inline-block;padding:2px 7px;border-radius:10px;font-size:10px;font-weight:600;margin-left:4px}
.state-new{background:rgba(59,130,246,.15);color:var(--blue)}
.state-active{background:rgba(239,68,68,.15);color:var(--red)}
.state-acknowledged{background:rgba(234,179,8,.15);color:var(--yellow)}
.state-fixing{background:rgba(6,182,212,.15);color:var(--cyan)}
.state-suppressed{background:rgba(107,114,128,.15);color:var(--muted)}
.badge{display:inline-block;padding:2px 7px;border-radius:10px;font-size:10px;font-weight:600}
.badge-critical{background:rgba(239,68,68,.2);color:var(--red)}
.badge-warning{background:rgba(234,179,8,.2);color:var(--yellow)}
.badge-info{background:rgba(59,130,246,.2);color:var(--blue)}

.proc-tile{background:var(--surface2);border-radius:8px;padding:10px 12px}
.proc-tile .count{font-size:22px;font-weight:700}
.proc-tile .pname{font-size:11px;color:var(--muted)}
.proc-tile .pmem{font-size:11px;color:var(--accent)}
.proc-table{width:100%;border-collapse:collapse;font-size:12px}
.proc-table th{text-align:left;color:var(--muted);font-weight:500;padding:4px 6px;border-bottom:1px solid var(--border)}
.proc-table td{padding:4px 6px;border-bottom:1px solid rgba(255,255,255,.04)}
.proc-table tr:last-child td{border-bottom:none}
.cpu-mini{display:inline-block;height:10px;background:var(--accent2);border-radius:3px;margin-right:4px;vertical-align:middle;min-width:2px}

.port-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:8px}
.port-item{background:var(--surface2);border-radius:7px;padding:8px 10px;display:flex;align-items:flex-start;gap:8px;border:1px solid transparent}
.port-item.is-up{border-color:rgba(74,222,128,.25)}
.port-item.is-dn{opacity:.55}
.port-item:hover{background:var(--border)}
.dot{width:8px;height:8px;border-radius:50%;flex-shrink:0;margin-top:4px}
.dot-up{background:var(--green)}
.dot-dn{background:#555}
.port-name{font-size:12px;font-weight:500}
.port-name-up{color:var(--fg)}
.port-name-dn{color:var(--muted)}
.port-num{font-size:10px;color:var(--muted)}
.port-up{font-size:10px;color:var(--green)}

.net-section-title{font-size:11px;font-weight:600;color:var(--muted);margin:10px 0 6px;text-transform:uppercase;letter-spacing:.6px}
.net-item{display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid rgba(255,255,255,.04);font-size:12px}
.net-item:last-child{border-bottom:none}
.net-proc{font-weight:600;min-width:110px}
.net-remote{color:var(--muted);flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tag-ext{font-size:10px;padding:1px 5px;border-radius:4px;background:rgba(239,68,68,.15);color:var(--red);flex-shrink:0}
.tag-lan{font-size:10px;padding:1px 5px;border-radius:4px;background:rgba(99,102,241,.2);color:var(--accent);flex-shrink:0}
.tag-st{font-size:10px;padding:1px 5px;border-radius:4px;background:rgba(107,114,128,.15);color:var(--muted);flex-shrink:0}

.modal-backdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:200;align-items:flex-end;justify-content:center}
.modal-backdrop.open{display:flex}
.modal{width:100%;max-width:760px;background:var(--surface);border:1px solid var(--border);border-radius:12px 12px 0 0;max-height:72vh;display:flex;flex-direction:column}
.modal-header{display:flex;align-items:center;justify-content:space-between;padding:12px 16px;border-bottom:1px solid var(--border);flex-shrink:0}
.modal-title{font-size:14px;font-weight:600}
.modal-close{cursor:pointer;font-size:18px;background:none;border:none;color:var(--text);line-height:1}
.diag-box{background:var(--surface2);border-radius:8px;padding:14px;margin:12px 16px 0;display:none;flex-shrink:0}
.diag-row{margin-bottom:8px}
.diag-row:last-child{margin-bottom:0}
.diag-label{font-size:10px;font-weight:600;text-transform:uppercase;color:var(--muted);margin-bottom:2px}
.diag-val{font-size:13px}
.conf-high{color:var(--green)}
.conf-medium{color:var(--yellow)}
.conf-low{color:var(--muted)}
.terminal{flex:1;overflow-y:auto;background:#0a0a0c;padding:12px 14px;font-family:'Cascadia Code','Consolas',monospace;font-size:12px;white-space:pre-wrap;line-height:1.6;margin:12px 0 0}
.t-done{color:var(--green)}
.t-fail{color:var(--red)}
.modal-footer{padding:10px 16px;border-top:1px solid var(--border);display:flex;gap:8px;justify-content:flex-end;flex-shrink:0}

.hist-item{display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid rgba(255,255,255,.04);font-size:12px}
.hist-item:last-child{border-bottom:none}
.hist-ts{color:var(--muted);font-size:11px;min-width:130px;flex-shrink:0}

.table-std{width:100%;border-collapse:collapse;font-size:12px}
.table-std th{text-align:left;color:var(--muted);font-weight:500;padding:5px 8px;border-bottom:1px solid var(--border)}
.table-std td{padding:5px 8px;border-bottom:1px solid rgba(255,255,255,.04)}
.table-std tr:last-child td{border-bottom:none}
.pill{display:inline-block;padding:1px 7px;border-radius:8px;font-size:11px}
.pill-ok{background:rgba(34,197,94,.15);color:var(--green)}
.pill-no{background:rgba(107,114,128,.15);color:var(--muted)}
.io-row{font-size:11px;color:var(--cyan);margin-top:3px}
.gpu-card{border-top:2px solid var(--accent2)}
.sep{height:1px;background:var(--border);margin:10px 0}
.key-card{background:var(--surface2);border-radius:8px;padding:12px 14px;border:1px solid var(--border)}
.key-card.active{border-color:rgba(34,197,94,.35)}
.key-card.invalid{border-color:rgba(239,68,68,.4);background:rgba(239,68,68,.04)}
.key-card.not_configured{border-color:var(--border);opacity:.6}
.key-card.rate_limited{border-color:rgba(234,179,8,.4)}
.key-icon{width:28px;height:28px;border-radius:6px;background:var(--border);display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;flex-shrink:0}
.key-top{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.key-name{font-size:13px;font-weight:600}
.key-masked{font-size:10px;color:var(--muted);font-family:monospace}
.key-status{font-size:11px;font-weight:600;margin-top:3px}
.ks-active{color:var(--green)}
.ks-invalid{color:var(--red)}
.ks-not_configured{color:var(--muted)}
.ks-rate_limited{color:var(--yellow)}
.ks-unreachable{color:var(--orange)}
.ks-error{color:var(--orange)}
.key-cost{font-size:11px;color:var(--cyan);margin-top:4px}
.key-actions{display:flex;gap:6px;margin-top:8px}
/* Session monitor */
.sess-row{display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--border)}
.sess-row:last-child{border-bottom:none}
.sess-slug{font-size:12px;font-weight:600;flex:0 0 180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sess-bar-wrap{flex:1;height:8px;background:var(--surface2);border-radius:4px;overflow:hidden}
.sess-bar{height:100%;border-radius:4px;transition:width .3s}
.sess-bar.ok{background:var(--green)}
.sess-bar.warn{background:var(--yellow)}
.sess-bar.crit{background:var(--red)}
.sess-pct{font-size:11px;font-weight:700;flex:0 0 38px;text-align:right}
.sess-burn{font-size:10px;color:var(--muted);flex:0 0 90px;text-align:right}
/* MemoryWeb */
.mw-stat{display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid var(--border);font-size:12px}
.mw-stat:last-child{border-bottom:none}
.mw-val{font-weight:600;color:var(--cyan)}
/* Governance */
.gov-ev{padding:5px 0;border-bottom:1px solid var(--border);font-size:11px}
.gov-ev:last-child{border-bottom:none}
.gov-sev-CRITICAL{color:var(--red);font-weight:700}
.gov-sev-HIGH{color:var(--orange);font-weight:700}
.gov-sev-warn{color:var(--yellow)}
.gov-sev-info{color:var(--muted)}
.gov-action{font-weight:600;margin-right:4px}
.gov-pair{font-family:monospace;font-size:10px;color:var(--muted)}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px}
.cost-provider-row{padding:4px 0}
.cost-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:2px}
.cost-label{font-size:12px;font-weight:600}
.cost-mtd{font-size:13px;font-weight:700;color:var(--cyan)}
.cost-spark{width:100%;height:40px;display:block;margin:4px 0 2px}
.cost-range{font-size:10px;color:var(--muted)}
/* ── Tooltips & callouts ──────────────────────────────────────────────────── */
.info-icon{display:inline-flex;align-items:center;justify-content:center;width:15px;height:15px;border-radius:50%;background:var(--border);color:var(--muted);font-size:9px;text-align:center;cursor:help;margin-left:6px;font-style:normal;vertical-align:middle;flex-shrink:0}
.info-icon:hover{background:var(--muted);color:var(--bg)}
.callout{display:flex;gap:6px;align-items:flex-start;margin-top:8px;padding:7px 9px;border-radius:5px;font-size:11px;line-height:1.5}
.callout-icon{flex-shrink:0;font-size:13px}
.callout-warn{background:rgba(251,191,36,.1);border:1px solid rgba(251,191,36,.3);color:var(--yellow)}
.callout-err{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:var(--red)}
.callout-info{background:rgba(56,189,248,.1);border:1px solid rgba(56,189,248,.3);color:var(--cyan)}
/* ── Help modal ─────────────────────────────────────────────────────────── */
#help-modal{display:none;position:fixed;inset:0;z-index:400;background:rgba(0,0,0,.7);align-items:flex-start;justify-content:center;padding-top:50px}
#help-modal.open{display:flex}
.help-body{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:24px;max-width:660px;width:100%;max-height:80vh;overflow-y:auto}
.help-body h2{margin:0 0 4px;font-size:16px}
.help-body h3{margin:16px 0 4px;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--muted)}
.help-body p,.help-body li{font-size:12px;line-height:1.6;color:var(--fg);margin:4px 0}
.help-body ul{margin:4px 0 0 14px;padding:0}
.help-close{float:right;background:var(--border);border:none;color:var(--fg);border-radius:4px;padding:4px 12px;cursor:pointer;font-size:12px}
.help-close:hover{background:var(--muted)}
.btn-help{background:transparent;border:1px solid var(--border);color:var(--muted);border-radius:4px;padding:3px 10px;cursor:pointer;font-size:11px;margin-left:8px}
.btn-help:hover{color:var(--fg);border-color:var(--muted)}

/* ── Agent Mesh ──────────────────────────────────────────────────────────── */
.mesh-health-line{font-size:11px;color:var(--muted);margin-bottom:10px}
.mesh-node-row{display:flex;align-items:center;justify-content:space-between;padding:7px 0;border-bottom:1px solid var(--border)}
.mesh-node-row:last-of-type{border-bottom:none}
.mesh-node-left{display:flex;align-items:center;gap:10px}
.mesh-node-right{display:flex;flex-direction:column;align-items:flex-end;gap:2px}
.mesh-dot{width:9px;height:9px;border-radius:50%;flex-shrink:0}
.mesh-dot-up{background:var(--green)}
.mesh-dot-dn{background:var(--red);opacity:.7}
.mesh-node-name{font-size:13px;font-weight:600}
.mesh-node-sub{font-size:10px;color:var(--muted)}
.mesh-node-cnt{font-size:12px;font-weight:500;color:var(--cyan)}
.mesh-node-lat{font-size:10px;color:var(--muted)}
.mesh-hub-line{font-size:10px;color:var(--muted);padding:2px 0 6px 19px}
.mesh-agent-table-wrap{overflow-x:auto;margin-top:12px}
.mesh-agent-table{width:100%;border-collapse:collapse;font-size:11px}
.mesh-agent-table th{text-align:left;color:var(--muted);font-weight:500;padding:4px 8px;border-bottom:1px solid var(--border);white-space:nowrap}
.mesh-agent-table td{padding:4px 8px;border-bottom:1px solid rgba(255,255,255,.04)}
.mesh-agent-table tr:last-child td{border-bottom:none}
.mesh-st-online{color:var(--green);font-weight:600}
.mesh-st-offline{color:var(--muted)}
</style>
</head>
<body>

<div class="topbar">
  <h1>System Dashboard</h1>
  <div class="meta">
    <span class="dot-live" id="live-dot"></span>
    <div class="stale-banner" id="stale-banner">STALE — daemon stopped</div>
    <span id="ts">Loading...</span>
    <span>|</span>
    <span>Refresh in <span id="countdown">10</span>s</span>
    <span id="uptime-span"></span>
    <button class="btn-help" onclick="openHelp()" title="Dashboard guide &amp; panel descriptions">? Help</button>
  </div>
</div>

<!-- Help Modal -->
<div id="help-modal" onclick="if(event.target===this)closeHelp()">
  <div class="help-body">
    <button class="help-close" onclick="closeHelp()">Close ✕</button>
    <h2>Dashboard Guide</h2>
    <p style="color:var(--muted);font-size:11px">Live workstation monitor — updates every 10 seconds. AI chat is always available on the right.</p>

    <h3>Active Issues</h3>
    <p>Auto-detected problems that need attention. Each issue can be <strong>Diagnosed</strong> (AI explains root cause + fix), <strong>Acknowledged</strong> (clears it for this session), or <strong>Suppressed</strong> (hides it for 60 min).</p>

    <h3>System — CPU / RAM / GPU</h3>
    <p>Live hardware utilization. GPU panel shows RTX 5090 load, VRAM use, and temperature. Warnings appear when CPU &gt;90%, RAM &gt;90%, or GPU temp &gt;85°C.</p>

    <h3>Storage</h3>
    <ul>
      <li>Red bar = drive is at or near capacity (&lt;10 GB free threshold in config)</li>
      <li><strong>FAILING</strong> flag = NTFS write errors (Event IDs 50/140) detected in the last 6 hours — this is auto-detected, not manually set</li>
      <li>If FAILING, open an elevated PowerShell and run: <code>chkdsk D: /scan</code></li>
      <li>Config override: <code>config.yaml → storage.failing_drives</code> (manual force-flag, use sparingly)</li>
    </ul>

    <h3>AI &amp; Agent Processes</h3>
    <p>Tracks processes defined in <code>config.yaml → processes.tracked</code>. Yellow border = process has a warning (e.g. runs autonomously). Count is number of instances. Click <strong>Kill</strong> to terminate a specific PID.</p>

    <h3>Service Ports</h3>
    <p>Polls each configured port every 10 s. Green dot + bright label = listening. Gray dot + dim label = nothing on that port. Click a live port to open it in a new tab. Ports are defined in <code>config.yaml → services.ports</code>.</p>

    <h3>API Keys</h3>
    <p>Validates API keys for each provider (Anthropic, OpenAI, Gemini, Groq, Ollama). <strong>Set Key</strong> saves to <code>.env.local</code> and activates immediately — no restart needed. <strong>Recheck</strong> forces a live validation ping. Keys are never shown in full — only the last 4 characters are visible.</p>

    <h3>Claude Code Sessions</h3>
    <p>Shows all Claude Code conversations active in the last 24h. Context bar = how full the session's context window is (200K tokens). <span style="color:var(--green)">▶</span> = active. <span style="color:var(--muted)">⏸</span> = idle/closed.</p>
    <ul>
      <li><strong>↩ Resume</strong> launches a new terminal with <code>claude --resume &lt;session-id&gt;</code> — reconnects to that exact conversation. All prior context is restored from the JSONL transcript on disk.</li>
      <li>Sessions survive crashes because transcripts are written to disk live. Even after a crash, Resume recovers them.</li>
      <li>95%+ context = near limit. Use <code>/compact</code> inside Claude Code to summarize before it fills up.</li>
    </ul>

    <h3>AI Chat (right panel)</h3>
    <p>Conversational interface to the local AI model (gemma3:latest via Ollama). The AI has access to the current system snapshot — CPU, RAM, GPU, active issues, and storage state. Ask it anything: "why is my C drive red?", "what's using all the RAM?", "is Ollama healthy?" Multi-turn — it remembers the last 10 exchanges.</p>

    <h3>Network Health</h3>
    <p>Live ping latency and packet loss to Cloudflare (1.1.1.1) and Google (8.8.8.8) — refreshes every 30 seconds. A red tile means &gt;50% packet loss; yellow means some loss. Below the tiles, each active interface shows send/recv MB/s, link speed, bandwidth utilisation %, and dropped packets per second. High drops/s indicate congestion or a bad cable.</p>

    <h3>Network Connections</h3>
    <p>Active TCP connections grouped by external vs. LAN. Known IPs are labelled (Spark-1, Spark-2, Cloudflare). Suspicious unknown external connections appear without a label.</p>

    <h3>Cost Tracker</h3>
    <p>Month-to-date API spend per provider. Requires an admin key set via the API Keys panel. Refreshes every 5 minutes.</p>

    <h3>Agent Mesh</h3>
    <p>Connectivity to Spark-1 (AI Army Hub), Spark-2 (MemoryWeb), and the local agent-status daemon. Each node shows latency and whether it is reachable.</p>
  </div>
</div>

<div class="main">

  <!-- Issues -->
  <div id="issues-wrap" style="display:none">
    <div class="card">
      <div class="card-title">Active Issues &mdash; <span id="issue-count">0</span> detected</div>
      <div id="issues-list"></div>
    </div>
  </div>

  <!-- CPU / RAM / GPU -->
  <div class="grid-3" id="sys-row"></div>

  <!-- Storage -->
  <div class="card">
    <div class="card-title">Storage <i class="info-icon" title="Drive space and health. Red bar = near-full (&lt;10 GB). FAILING = auto-detected NTFS errors in last 6h. Hover any drive card for details.">i</i></div>
    <div class="grid-auto" id="storage-grid"></div>
  </div>

          <div class="card" id="fleet-card" style="display:none">
            <div class="card-title">AGENT FLEET <span id="fleet-count" style="font-size:11px;color:#666;margin-left:8px"></span>
              <button onclick="clearFleet()" style="float:right;font-size:10px;padding:2px 7px;background:#1a1a1a;border:1px solid #333;color:#888;border-radius:3px;cursor:pointer">Clear done/crashed</button>
            </div>
            <div id="fleet-guard-bar" style="display:none;padding:7px 10px;border-radius:4px;font-size:11px;font-weight:600;letter-spacing:.5px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center">
              <span id="fleet-guard-label"></span>
              <span id="fleet-guard-reason" style="font-weight:400;font-size:10px;opacity:.85"></span>
              <button id="fleet-guard-resume" onclick="resumeGuard()" style="display:none;font-size:10px;padding:2px 8px;background:#222;border:1px solid #555;color:#aaa;border-radius:3px;cursor:pointer;margin-left:10px">Resume</button>
            </div>
            <div id="fleet-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(195px,1fr));gap:8px"></div>
          </div>

  <!-- Processes -->
  <div class="card">
    <div class="card-title">AI &amp; Agent Processes <i class="info-icon" title="Tracked processes from config.yaml. Yellow border = autonomy warning. Kill button stops a specific PID.">i</i></div>
    <div class="grid-auto" id="proc-tiles" style="margin-bottom:14px"></div>
    <div class="sep"></div>
    <table class="proc-table" style="margin-top:12px">
      <thead><tr>
        <th>Process</th><th>PID</th><th>RAM MB</th><th>CPU%</th><th>Status</th><th>Age</th><th></th>
      </tr></thead>
      <tbody id="proc-rows"></tbody>
    </table>
  </div>

  <!-- Ports -->
  <div class="card">
    <div class="card-title">Service Ports &mdash; <span id="ports-up">0</span> / <span id="ports-total">0</span> up <i class="info-icon" title="Polls each port every 10s. Green = listening. Click a live port to open it. Add ports in config.yaml → services.ports.">i</i></div>
    <div class="port-grid" id="port-grid"></div>
  </div>

  <!-- Network Health -->
  <div class="card">
    <div class="card-title">Network Health</div>
    <div id="net-health-ping" style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:10px"></div>
    <div id="net-health-ifaces"></div>
  </div>

  <!-- Network Connections -->
  <div class="card">
    <div class="card-title">Network Connections</div>
    <div id="net-ext"></div>
    <div id="net-int"></div>
  </div>

  <!-- API Keys -->
  <div class="card">
    <div class="card-title" style="display:flex;align-items:center;justify-content:space-between">
      <span>API Keys</span>
      <button class="btn btn-neutral" style="font-size:11px;padding:3px 10px" onclick="recheckAllKeys()">Re-check All</button>
    </div>
    <div id="keys-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px"></div>
    <div style="font-size:10px;color:var(--muted);margin-top:10px">Keys read from environment variables. Only last 4 chars shown. Cost data requires admin key env var (ANTHROPIC_ADMIN_KEY / OPENAI_ADMIN_KEY). Cached 5 min.</div>
  </div>

  <!-- Claude Code Sessions -->
  <div class="card">
    <div class="card-title" style="display:flex;align-items:center;justify-content:space-between">
      <span>Claude Code Sessions — Context Burn</span>
      <button class="btn btn-neutral" style="font-size:11px;padding:3px 10px" onclick="fetchSessions()">Refresh</button>
    </div>
    <div id="sessions-list"></div>
  </div>

  <!-- MemoryWeb + BPC/TSK row -->
  <div class="grid-2">
    <div class="card">
      <div class="card-title" style="display:flex;align-items:center;justify-content:space-between">
        <span>MemoryWeb</span>
        <button class="btn btn-neutral" style="font-size:11px;padding:3px 10px" onclick="fetchMemoryWeb(true)">Refresh</button>
      </div>
      <div id="mw-panel"></div>
    </div>
    <div class="card">
      <div class="card-title" style="display:flex;align-items:center;justify-content:space-between">
        <span>BPC / TSK Governance</span>
        <button class="btn btn-neutral" style="font-size:11px;padding:3px 10px" onclick="fetchGovernance(true)">Refresh</button>
      </div>
      <div id="gov-panel"></div>
    </div>
  </div>

  <!-- Cost Tracker -->
  <div class="card">
    <div class="card-title" style="display:flex;align-items:center;justify-content:space-between">
      <span>Cost Tracker</span>
      <button class="btn btn-neutral" style="font-size:11px;padding:3px 10px" onclick="fetchCostHistory(true)">Update</button>
    </div>
    <div id="cost-panel"><div style="color:var(--muted);font-size:12px">Loading...</div></div>
    <div style="font-size:10px;color:var(--muted);margin-top:10px">MTD cost from admin keys. Snapshots stored daily in SQLite. Sparkline = last 14 days. Refreshes every 15 min.</div>
  </div>

  <!-- Agent Mesh panel — insert in .main after the MemoryWeb/BPC row -->
  <div class="card" id="mesh-panel-card">
    <div class="card-title" style="display:flex;align-items:center;justify-content:space-between">
      <span>Agent Mesh</span>
      <button class="btn btn-neutral" style="font-size:11px;padding:3px 10px" onclick="fetchMesh(true)">Refresh</button>
    </div>
    <div id="mesh-panel"><div style="color:var(--muted);font-size:12px">Loading...</div></div>
  </div>

  <!-- Dashboard API Tokens -->
  <div class="card">
    <div class="card-title" style="display:flex;align-items:center;justify-content:space-between">
      <span>Dashboard API Tokens <i class="info-icon" title="Scoped tokens for external tools (AI Army, scripts, agents) to call dashboard endpoints via X-Dashboard-Token header. Raw token shown once at creation.">i</i></span>
      <button class="btn btn-neutral" style="font-size:11px;padding:3px 10px;background:rgba(99,102,241,.18);color:#a5b4fc" onclick="openTokenModal()">+ Generate Token</button>
    </div>
    <div id="tokens-panel"><div style="color:var(--muted);font-size:12px">Loading...</div></div>
  </div>

  <!-- Bottom row -->
  <div class="grid-3">
    <div class="card">
      <div class="card-title">Projects</div>
      <table class="table-std">
        <thead><tr><th>Name</th><th>Branch</th><th></th></tr></thead>
        <tbody id="proj-rows"></tbody>
      </table>
    </div>
    <div class="card">
      <div class="card-title">Claude Code Hooks</div>
      <table class="table-std">
        <thead><tr><th>Hook</th><th>Present</th><th>KB</th></tr></thead>
        <tbody id="hook-rows"></tbody>
      </table>
    </div>
    <div class="card">
      <div class="card-title">Alert History</div>
      <div id="alert-hist" style="max-height:240px;overflow-y:auto"></div>
    </div>
  </div>

</div>

<!-- Chat Drawer -->
<div id="chat-drawer" style="position:fixed;bottom:0;right:24px;width:380px;z-index:300;display:none;flex-direction:column;border:1px solid var(--border);border-bottom:none;border-radius:10px 10px 0 0;background:var(--surface);box-shadow:0 -4px 24px rgba(0,0,0,.4)">
  <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 14px;border-bottom:1px solid var(--border);cursor:pointer" onclick="toggleChat()">
    <span style="font-size:13px;font-weight:600">AI Chat <span style="font-size:10px;color:var(--muted);font-weight:400" id="chat-model-label"></span></span>
    <div style="display:flex;gap:8px;align-items:center">
      <button class="btn btn-neutral" style="font-size:10px;padding:2px 8px" onclick="event.stopPropagation();clearChat()">Clear</button>
      <span style="color:var(--muted);font-size:16px" id="chat-chevron">▲</span>
    </div>
  </div>
  <div id="chat-messages" style="flex:1;overflow-y:auto;max-height:340px;padding:10px 14px;display:flex;flex-direction:column;gap:8px"></div>
  <div style="padding:10px 14px;border-top:1px solid var(--border);display:flex;gap:8px">
    <textarea id="chat-input" rows="2" placeholder="Ask anything about your system…" style="flex:1;background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:7px 10px;color:var(--text);font-size:12px;resize:none;font-family:inherit" onkeydown="chatKeydown(event)"></textarea>
    <button class="btn btn-primary" style="align-self:flex-end;padding:7px 14px" onclick="sendChat()" id="chat-send-btn">Send</button>
  </div>
</div>
<!-- Chat toggle button -->
<button id="chat-fab" onclick="toggleChat()" style="position:fixed;bottom:20px;right:24px;z-index:299;background:var(--accent);color:#000;border:none;border-radius:50px;padding:10px 18px;font-size:13px;font-weight:700;cursor:pointer;box-shadow:0 2px 12px rgba(0,0,0,.4)">AI Chat</button>

<!-- Set Key Modal -->
<div id="key-modal" onclick="if(event.target===this)closeKeyModal()" style="display:none;position:fixed;inset:0;z-index:400;background:rgba(0,0,0,.6);align-items:center;justify-content:center">
  <div style="background:var(--surface2);border:1px solid var(--border);border-radius:12px;padding:24px;width:420px;max-width:95vw">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
      <span id="km-title" style="font-size:14px;font-weight:600"></span>
      <button onclick="closeKeyModal()" style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:16px">&#x2715;</button>
    </div>
    <div style="font-size:11px;color:var(--muted);margin-bottom:8px">Paste your API key. Saved to .env.local and validated immediately. Leave blank to clear.</div>
    <input id="km-input" type="password" placeholder="sk-..." autocomplete="off" onkeydown="if(event.key==='Enter')submitKeyModal()" style="width:100%;box-sizing:border-box;background:var(--bg);border:1px solid var(--border);border-radius:7px;padding:9px 12px;color:var(--fg);font-size:13px;font-family:monospace;outline:none;margin-bottom:12px">
    <div style="font-size:11px;color:var(--muted);margin-bottom:6px">Model for this provider <span style="opacity:.6">(determines which AI is used — pick based on task)</span></div>
    <select id="km-model" style="width:100%;background:var(--bg);border:1px solid var(--border);border-radius:7px;padding:8px 10px;color:var(--fg);font-size:12px;outline:none;margin-bottom:12px"></select>
    <div style="font-size:10px;color:var(--muted);margin:-8px 0 12px;line-height:1.5" id="km-model-hint"></div>
    <div style="display:flex;gap:8px;align-items:center">
      <button onclick="submitKeyModal()" style="background:var(--accent);color:#000;border:none;border-radius:7px;padding:8px 18px;font-size:12px;font-weight:700;cursor:pointer">Save &amp; Validate</button>
      <button onclick="closeKeyModal()" style="background:var(--surface2);border:1px solid var(--border);color:var(--fg);border-radius:7px;padding:8px 14px;font-size:12px;cursor:pointer">Cancel</button>
      <span id="km-status" style="font-size:11px;flex:1;text-align:right"></span>
    </div>
  </div>
</div>

<!-- Token Generation Modal -->
<div id="token-modal" onclick="if(event.target===this)closeTokenModal()" style="display:none;position:fixed;inset:0;z-index:400;background:rgba(0,0,0,.7);align-items:center;justify-content:center">
  <div style="background:var(--surface2);border:1px solid var(--border);border-radius:12px;padding:24px;width:440px;max-width:95vw">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
      <span style="font-size:14px;font-weight:600">Generate Dashboard API Token</span>
      <button onclick="closeTokenModal()" style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:16px">&#x2715;</button>
    </div>
    <div style="font-size:11px;color:var(--muted);margin-bottom:12px">The raw token is shown <strong style="color:var(--fg)">once</strong> after creation. Copy it immediately — only the hash is stored.</div>
    <label style="font-size:11px;color:var(--muted)">Token Name (what is this for?)</label>
    <input id="tm-name" placeholder="e.g. AI Army Node / CI script / agent-status" autocomplete="off" style="width:100%;box-sizing:border-box;background:var(--bg);border:1px solid var(--border);border-radius:7px;padding:8px 12px;color:var(--fg);font-size:12px;outline:none;margin:6px 0 12px">
    <label style="font-size:11px;color:var(--muted)">Scope</label>
    <select id="tm-scope" style="width:100%;background:var(--bg);border:1px solid var(--border);border-radius:7px;padding:8px 10px;color:var(--fg);font-size:12px;outline:none;margin:6px 0 4px">
      <option value="read">read — status, sessions, keys (no changes)</option>
      <option value="write">write — read + acknowledge issues, kill PIDs, set keys</option>
      <option value="admin">admin — full access including token management</option>
    </select>
    <div style="font-size:10px;color:var(--muted);margin-bottom:14px" id="tm-scope-hint">Read-only: /api/status, /api/sessions, /api/memoryweb, /api/keys</div>
    <div id="tm-result" style="display:none;background:var(--bg);border:1px solid var(--green);border-radius:7px;padding:12px;margin-bottom:14px;word-break:break-all">
      <div style="font-size:10px;color:var(--green);margin-bottom:4px">Token generated — copy now, it won't be shown again:</div>
      <code id="tm-raw" style="font-size:12px;color:var(--fg)"></code>
      <button onclick="copyToken()" style="display:block;margin-top:8px;background:var(--green);color:#000;border:none;border-radius:5px;padding:4px 14px;font-size:11px;cursor:pointer">Copy to Clipboard</button>
    </div>
    <div style="display:flex;gap:8px;align-items:center">
      <button onclick="submitTokenModal()" id="tm-submit" style="background:var(--accent);color:#000;border:none;border-radius:7px;padding:8px 18px;font-size:12px;font-weight:700;cursor:pointer">Generate</button>
      <button onclick="closeTokenModal()" style="background:var(--surface2);border:1px solid var(--border);color:var(--fg);border-radius:7px;padding:8px 14px;font-size:12px;cursor:pointer">Close</button>
      <span id="tm-status" style="font-size:11px;flex:1;text-align:right"></span>
    </div>
  </div>
</div>

<!-- Modal -->
<div class="modal-backdrop" id="backdrop" onclick="bgClick(event)">
  <div class="modal">
    <div class="modal-header">
      <div class="modal-title" id="modal-title">Terminal</div>
      <button class="modal-close" onclick="closeModal()">&#x2715;</button>
    </div>
    <div class="diag-box" id="diag-box">
      <div class="diag-row"><div class="diag-label">Summary</div><div class="diag-val" id="d-sum"></div></div>
      <div class="diag-row"><div class="diag-label">Root Cause</div><div class="diag-val" id="d-cause"></div></div>
      <div class="diag-row"><div class="diag-label">Suggested Fix</div><div class="diag-val" id="d-fix"></div></div>
      <div class="diag-row"><div class="diag-label">Confidence</div><div class="diag-val" id="d-conf"></div></div>
    </div>
    <div class="terminal" id="terminal"></div>
    <div class="modal-footer">
      <button class="btn btn-neutral" onclick="closeModal()">Close</button>
    </div>
  </div>
</div>

<script>
const REFRESH_S = 10;
let countdown = REFRESH_S;
const histData = {};

// helpers
function barCls(p){return p>=85?'bar-red':p>=60?'bar-yellow':'bar-green'}
function esc(s){return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function sesc(s){return (s||'').replace(/'/g,"\\'").replace(/"/g,'&quot;')}
function fmtAge(s){
  s=parseInt(s)||0;
  if(s<60)return s+'s';
  if(s<3600)return Math.floor(s/60)+'m '+Math.floor(s%60)+'s';
  return Math.floor(s/3600)+'h '+Math.floor((s%3600)/60)+'m';
}
function fmtUptime(s){
  if(!s)return'';s=parseInt(s);
  if(s<60)return'up '+s+'s';
  if(s<3600)return'up '+Math.floor(s/60)+'m';
  return'up '+Math.floor(s/3600)+'h '+Math.floor((s%3600)/60)+'m';
}

// sparkline SVG
function spark(key, color='#6366f1'){
  const data = histData[key]||[];
  if(data.length<2)return'';
  const w=200,h=36,n=data.length;
  const mn=Math.min(...data),mx=Math.max(...data),range=mx-mn||1;
  const pts=data.map((v,i)=>{
    const x=(i/(n-1))*w, y=h-((v-mn)/range)*(h-4)-2;
    return x.toFixed(1)+','+y.toFixed(1);
  }).join(' ');
  const area='0,'+h+' '+pts+' '+w+','+h;
  return`<svg class="spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">
    <polygon points="${area}" style="fill:${color}22"/>
    <polyline points="${pts}" style="fill:none;stroke:${color};stroke-width:1.5"/>
  </svg>`;
}

function pushHist(key,val){
  if(!histData[key])histData[key]=[];
  histData[key].push(val);
  if(histData[key].length>60)histData[key].shift();
}

// ── System row ──────────────────────────────────────────────────────────────
function renderSys(snap){
  const s=snap.system||{};
  pushHist('cpu',s.cpu_pct||0);
  pushHist('ram',s.ram_pct||0);
  const cH=(snap.history||{}).cpu_pct||histData.cpu;
  const rH=(snap.history||{}).ram_pct||histData.ram;

  if(s.boot_time_s){
    document.getElementById('uptime-span').textContent=' | System up '+fmtAge(s.boot_time_s);
  }

  let html='';
  // CPU
  const cpu=s.cpu_pct||0;
  html+=`<div class="card">
    <div class="card-title">CPU</div>
    <div class="metric-big">${cpu.toFixed(1)}<span style="font-size:14px;font-weight:400">%</span></div>
    <div class="metric-sub">${s.cpu_count||0} logical cores</div>
    <div class="bar-track"><div class="bar-fill ${barCls(cpu)}" style="width:${cpu}%"></div></div>
    ${spark('cpu','#6366f1')}
  </div>`;
  // RAM
  const ram=s.ram_pct||0;
  html+=`<div class="card">
    <div class="card-title">RAM</div>
    <div class="metric-big">${(s.ram_used_gb||0).toFixed(1)}<span style="font-size:14px;font-weight:400"> / ${(s.ram_total_gb||0).toFixed(0)}GB</span></div>
    <div class="metric-sub">${(s.ram_avail_gb||0).toFixed(1)}GB free${s.ram_compressed_mb?` &bull; ${s.ram_compressed_mb}MB compressed`:''}</div>
    <div class="bar-track"><div class="bar-fill ${barCls(ram)}" style="width:${ram}%"></div></div>
    ${spark('ram','#8b5cf6')}
  </div>`;
  // GPU
  const gpus=s.gpus||[];
  if(!gpus.length){
    html+=`<div class="card gpu-card"><div class="card-title">GPU</div><div style="color:var(--muted);font-size:12px">No GPU detected</div></div>`;
  } else {
    const g=gpus[0];
    pushHist('gpu_pct',g.gpu_pct||0);
    pushHist('gpu_mem',g.mem_pct||0);
    const gH=(snap.history||{}).gpu0_pct||histData.gpu_pct;
    const temp=g.temp_c!=null?g.temp_c+'&#xb0;C':'--';
    const pwr=g.power_w!=null?`${g.power_w}W/${g.power_limit_w}W`:'';
    html+=`<div class="card gpu-card">
      <div class="card-title">GPU &mdash; ${esc(g.name)}</div>
      <div class="metric-big">${g.gpu_pct}<span style="font-size:14px;font-weight:400">% util</span></div>
      <div class="metric-sub">VRAM: ${(g.mem_used_mb/1024).toFixed(1)} / ${(g.mem_total_mb/1024).toFixed(1)} GB &bull; ${temp}${pwr?' &bull; '+pwr:''}</div>
      <div class="bar-track" style="margin-top:6px"><div class="bar-fill ${barCls(g.gpu_pct)}" style="width:${g.gpu_pct}%"></div></div>
      <div style="font-size:10px;color:var(--muted);margin-top:3px">GPU util &nbsp;&bull;&nbsp; VRAM ${g.mem_pct.toFixed(1)}%</div>
      <div class="bar-track" style="margin-top:3px"><div class="bar-fill ${barCls(g.mem_pct)}" style="width:${g.mem_pct}%"></div></div>
      ${spark('gpu_pct','#06b6d4')}
      ${gpus.length>1?`<div style="font-size:11px;color:var(--muted);margin-top:4px">+${gpus.length-1} more GPU(s)</div>`:''}
    </div>`;
  }
  document.getElementById('sys-row').innerHTML=html;
}

// ── Storage ──────────────────────────────────────────────────────────────────
function renderStorage(snap){
  const drives=(snap.system||{}).drives||{};
  const io=snap.disk_io||{};
  let html='';
  for(const [lt,d] of Object.entries(drives)){
    if(d.total_gb===0){
      html+=`<div class="card"><div class="card-title">Drive ${lt}:</div><div style="color:var(--muted);font-size:12px">Unavailable / unmounted</div></div>`;
      continue;
    }
    const bdr=d.failing?'border:1px solid var(--red)':d.warn?'border:1px solid var(--yellow)':'';
    const diskKey=Object.keys(io).find(k=>k.toUpperCase().startsWith(lt.toUpperCase()));
    const ioD=diskKey?io[diskKey]:null;
    const failReasonMap={'ntfs_events_6h':'NTFS errors in last 6h','config_override':'Manually flagged in config','mount_error':'Failed to mount'};
    const failTag=d.failing?`<span style="color:var(--red)">FAILING</span>${d.failing_reason?` <span style="font-size:9px;color:var(--red);opacity:.7">(${failReasonMap[d.failing_reason]||d.failing_reason})</span>`:''}`:''
    // Callout suggestions for flagged / near-full drives
    let callout='';
    if(d.failing){
      const hint=d.failing_reason==='ntfs_events_6h'?'Run <code>chkdsk '+lt+': /scan</code> in an elevated PowerShell to check integrity. No reboot needed for /scan.'
                :d.failing_reason==='mount_error'?'Drive failed to mount. Check Device Manager and disk connections.'
                :'Drive was manually flagged in config.yaml. Remove from failing_drives once resolved.';
      callout=`<div class="callout callout-err"><span class="callout-icon">⚠</span><span>Drive health issue detected. ${hint}</span></div>`;
    } else if(d.pct>=95){
      callout=`<div class="callout callout-err"><span class="callout-icon">⚠</span><span>Drive ${lt}: is critically full (${d.pct}% used). Free space now or risk write failures. Check large folders: <code>WinDirStat</code> or Settings → Storage Sense.</span></div>`;
    } else if(d.pct>=85){
      callout=`<div class="callout callout-warn"><span class="callout-icon">!</span><span>Drive ${lt}: is getting full (${d.pct}% used, ${d.free_gb} GB left). Consider clearing Downloads, temp files, or moving large projects to D:.</span></div>`;
    }
    html+=`<div class="card" style="${bdr}" title="Drive ${lt}: — ${d.free_gb}GB free of ${d.total_gb}GB (${d.pct}% used)${d.failing?' — FAILING: '+( failReasonMap[d.failing_reason]||''):''}">
      <div class="card-title">Drive ${lt}: ${failTag}</div>
      <div class="metric-big">${d.free_gb}<span style="font-size:13px;font-weight:400">GB free</span></div>
      <div class="metric-sub">${d.used_gb} / ${d.total_gb}GB &bull; ${d.pct}% used</div>
      <div class="bar-track"><div class="bar-fill ${d.failing?'bar-red':barCls(d.pct)}" style="width:${d.pct}%"></div></div>
      ${ioD?`<div class="io-row">R: ${ioD.read_mbs}MB/s &uarr;&nbsp;&nbsp; W: ${ioD.write_mbs}MB/s &darr;</div>`:''}
      ${callout}
    </div>`;
  }
  document.getElementById('storage-grid').innerHTML=html;
}

// ── Processes ────────────────────────────────────────────────────────────────
function renderProcs(snap){
  const procs=snap.processes||{};
  let tiles='',rows='';
  for(const [nm,pd] of Object.entries(procs)){
    const procTip=pd.warn&&pd.warn_reason?`title="${esc(pd.warn_reason)}"`:pd.warn?'title="Process has autonomy or risk warning"':'';
    tiles+=`<div class="proc-tile" style="${pd.warn?'border:1px solid var(--yellow)':''}" ${procTip}>
      <div class="count">${pd.count}</div>
      <div class="pname">${esc(pd.label||nm)}</div>
      <div class="pmem">${pd.total_mb}MB</div>
      ${pd.warn&&pd.warn_reason?`<div class="callout callout-warn" style="margin:6px -2px -2px;font-size:10px;padding:4px 6px"><span class="callout-icon" style="font-size:10px">!</span><span>${esc(pd.warn_reason)}</span></div>`:''}
    </div>`;
    for(const p of (pd.procs||[])){
      const cpuW=Math.min((p.cpu_pct||0)*0.6,60);
      rows+=`<tr>
        <td>${esc(nm)}</td><td>${p.pid}</td><td>${p.mem_mb}</td>
        <td><span class="cpu-mini" style="width:${cpuW}px"></span>${(p.cpu_pct||0).toFixed(1)}%</td>
        <td>${p.status||'?'}</td>
        <td>${fmtAge(p.age_s||0)}</td>
        <td><button class="btn btn-danger" style="padding:2px 8px;font-size:11px" onclick="killPid(${p.pid},'${sesc(nm)}')">Kill</button></td>
      </tr>`;
    }
  }
  document.getElementById('proc-tiles').innerHTML=tiles;
  document.getElementById('proc-rows').innerHTML=rows;
}

// ── Ports ────────────────────────────────────────────────────────────────────
function renderPorts(snap){
  const ports=snap.ports||{};
  let up=0,total=0,html='';
  for(const [port,pd] of Object.entries(ports)){
    total++;
    if(pd.up)up++;
    const ut=pd.up&&pd.uptime_s?fmtUptime(pd.uptime_s):'';
    const inner=`
      <span class="dot ${pd.up?'dot-up':'dot-dn'}"></span>
      <div>
        <div class="port-name ${pd.up?'port-name-up':'port-name-dn'}">${esc(pd.label||'')}</div>
        <div class="port-num">:${port}${pd.proc?' &bull; '+esc(pd.proc):''}</div>
        ${ut?`<div class="port-up">${ut}</div>`:''}
      </div>`;
    const portTip=`title="${esc(pd.label||'')} on port ${port} — ${pd.up?'UP':'DOWN'}${pd.proc?' ('+pd.proc+')':''}${ut?' uptime '+ut:''}"`;
    if(pd.up){
      html+=`<div class="port-item is-up" ${portTip}><a href="http://127.0.0.1:${port}" target="_blank">${inner}</a></div>`;
    } else {
      html+=`<div class="port-item is-dn" ${portTip}>${inner}</div>`;
    }
  }
  document.getElementById('ports-up').textContent=up;
  document.getElementById('ports-total').textContent=total;
  document.getElementById('port-grid').innerHTML=html;
}

// ── Network ──────────────────────────────────────────────────────────────────
// ── Network Health (ping + bandwidth) ────────────────────────────────────────
function renderNetHealth(snap){
  const nh=snap.net_health||{};
  const pings=nh.ping||[];
  const ifaces=nh.interfaces||{};

  // Ping tiles
  const pingEl=document.getElementById('net-health-ping');
  if(pingEl){
    if(!pings.length){
      pingEl.innerHTML='<span style="color:var(--muted);font-size:12px">Pinging…</span>';
    } else {
      pingEl.innerHTML=pings.map(p=>{
        const ok=p.ok;
        const latStr=p.latency_ms!=null?p.latency_ms+'ms':'timeout';
        const lossStr=p.packet_loss_pct>0?` ${p.packet_loss_pct}% loss`:'';
        const cls=ok&&p.packet_loss_pct===0?'var(--green)':p.packet_loss_pct>=50?'var(--red)':'var(--yellow)';
        const tip=`Ping to ${p.host} (${p.label}). Latency: ${latStr}${lossStr}`;
        return `<div title="${tip}" style="background:var(--panel);border:1px solid ${cls};border-radius:6px;padding:6px 14px;text-align:center;min-width:110px;cursor:default">
          <div style="font-size:10px;color:var(--muted);margin-bottom:2px">${esc(p.label)}</div>
          <div style="font-size:16px;font-weight:700;color:${cls}">${latStr}</div>
          ${lossStr?`<div style="font-size:10px;color:var(--red)">${lossStr}</div>`:''}
        </div>`;
      }).join('');
    }
  }

  // Interface table — only show active (is_up) interfaces
  const ifaceEl=document.getElementById('net-health-ifaces');
  if(ifaceEl){
    const active=Object.entries(ifaces).filter(([,v])=>v.is_up&&v.speed_mbps!==0);
    if(!active.length){
      ifaceEl.innerHTML='<div style="color:var(--muted);font-size:12px">No active interfaces</div>';
      return;
    }
    const hdr=`<div style="display:grid;grid-template-columns:1fr 80px 90px 90px 70px;gap:6px;font-size:10px;color:var(--muted);margin-bottom:4px;padding:0 4px">
      <span>Interface</span><span style="text-align:right">Speed</span>
      <span style="text-align:right">↑ Send</span><span style="text-align:right">↓ Recv</span>
      <span style="text-align:right">Drops/s</span></div>`;
    const rows=active.map(([nic,v])=>{
      const dropWarn=v.dropped_ps>0?'var(--red)':'var(--fg)';
      const errWarn=v.errs_ps>0?'var(--red)':'var(--fg)';
      const bwPct=v.speed_mbps?(Math.max(v.sent_mbs,v.recv_mbs)/v.speed_mbps*100).toFixed(0):null;
      const tip=`${nic}${v.ipv4?' ('+v.ipv4+')':''} | Speed: ${v.speed_mbps??'?'}Mbps | Drops/s: ${v.dropped_ps} | Errs/s: ${v.errs_ps}`;
      return `<div title="${tip}" style="display:grid;grid-template-columns:1fr 80px 90px 90px 70px;gap:6px;font-size:12px;padding:4px;border-radius:4px;background:var(--panel)">
        <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(nic)}${v.ipv4?`<span style="color:var(--muted);font-size:10px;margin-left:6px">${esc(v.ipv4)}</span>`:''}</span>
        <span style="text-align:right;color:var(--muted)">${v.speed_mbps!=null?v.speed_mbps+'M':'?'}${bwPct?`<span style="color:${bwPct>80?'var(--red)':'var(--muted)'}"> ${bwPct}%</span>`:''}</span>
        <span style="text-align:right">${v.sent_mbs} MB/s</span>
        <span style="text-align:right">${v.recv_mbs} MB/s</span>
        <span style="text-align:right;color:${dropWarn}">${v.dropped_ps}</span>
      </div>`;
    }).join('');
    ifaceEl.innerHTML=hdr+`<div style="display:flex;flex-direction:column;gap:3px">${rows}</div>`;
  }
}

      function renderFleet(snap) {
        const agents = snap.fleet || [];
        const guard = snap.fleet_guard || {};
        const gbar = document.getElementById('fleet-guard-bar');
        const glabel = document.getElementById('fleet-guard-label');
        const greason = document.getElementById('fleet-guard-reason');
        const gresume = document.getElementById('fleet-guard-resume');
        const GCOLOR = {ok:'#1a1a1a',halt_recommended:'#2d2200',degraded:'#1a1500',blocked:'#2d1200',hard_stop:'#2d0000'};
        const GTEXTC = {ok:'#2ecc71',halt_recommended:'#f39c12',degraded:'#e67e22',blocked:'#e74c3c',hard_stop:'#ff3333'};
        const GLABEL = {ok:'● ALL CLEAR',halt_recommended:'⚠ HALT RECOMMENDED',degraded:'⚠ DEGRADED',blocked:'⚠ AGENTS BLOCKED','hard_stop':'■ HARD STOP'};
        if (gbar && guard.state) {
          gbar.style.display = 'flex';
          gbar.style.background = GCOLOR[guard.state] || '#1a1a1a';
          gbar.style.borderLeft = '3px solid ' + (GTEXTC[guard.state]||'#555');
          if (glabel) { glabel.textContent = GLABEL[guard.state] || guard.state; glabel.style.color = GTEXTC[guard.state]||'#aaa'; }
          if (greason) greason.textContent = guard.reason || '';
          if (gresume) gresume.style.display = guard.state === 'hard_stop' ? '' : 'none';
        }
        const card = document.getElementById('fleet-card');
        const grid = document.getElementById('fleet-grid');
        const cnt = document.getElementById('fleet-count');
        if (!card || !grid) return;
        card.style.display = agents.length ? '' : 'none';
        cnt.textContent = agents.length ? agents.length + ' agent' + (agents.length !== 1 ? 's' : '') : '';
        const SC = {starting:'#888',working:'#2ecc71',stalled:'#f39c12',done:'#3498db',crashed:'#e74c3c'};
        grid.innerHTML = agents.map(a => {
          const c = SC[a.status] || '#888';
          const m = Math.floor((a.runtime_s||0)/60), s = (a.runtime_s||0)%60;
          const rt = m > 0 ? m+'m '+s+'s' : s+'s';
          const bar = a.progress > 0
            ? '<div style="height:2px;background:#222;border-radius:1px;margin-top:5px"><div style="height:2px;background:'+c+';width:'+a.progress+'%;border-radius:1px;transition:width .4s"></div></div>'
            : '';
          const note = a.note
            ? '<div style="font-size:10px;color:#666;margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+a.note+'">'+a.note+'</div>'
            : '';
          const res = (a.status==='done'||a.status==='crashed') && a.result
            ? '<div style="font-size:10px;color:'+c+';margin-top:2px">'+a.result+'</div>'
            : '';
          return '<div style="background:#111;border:1px solid '+c+'44;border-radius:6px;padding:9px">'
            +'<div style="display:flex;justify-content:space-between;align-items:center">'
            +'<span style="font-weight:600;font-size:12px;color:#ddd;overflow:hidden;text-overflow:ellipsis">'+a.name+'</span>'
            +'<span style="font-size:10px;font-weight:700;color:'+c+';text-transform:uppercase;flex-shrink:0;margin-left:6px">'+a.status+'</span>'
            +'</div>'
            +'<div style="font-size:11px;color:#666;margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+a.task+'">'+a.task+'</div>'
            +'<div style="font-size:10px;color:#444;margin-top:4px;display:flex;gap:8px">'
            +'<span>'+rt+'</span>'
            +(a.cpu_pct!=null?'<span>'+a.cpu_pct+'% CPU</span>':'')
            +(a.ram_mb!=null?'<span>'+Math.round(a.ram_mb)+'MB</span>':'')
            +(a.progress>0?'<span style="margin-left:auto">'+a.progress+'%</span>':'')
            +'</div>'
            +bar+note+res
            +'</div>';
        }).join('');
      }

      async function clearFleet() {
        const snap = window._lastSnap || {};
        const agents = (snap.fleet||[]).filter(a=>a.status==='done'||a.status==='crashed');
        await Promise.all(agents.map(a=>fetch('/api/fleet/'+encodeURIComponent(a.name),{method:'DELETE'})));
        if (typeof fetchStatus === 'function') fetchStatus();
      }

      async function resumeGuard() {
        await fetch('/api/fleet/guard/resume', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({note:'operator resume'})});
        fetchStatus();
      }

function renderNet(snap){
  const net=snap.network||{};
  function group(conns){
    const g={};
    for(const c of conns){if(!g[c.proc])g[c.proc]=[];g[c.proc].push(c);}
    return g;
  }
  function rows(conns,tagCls,tagLbl){
    const g=group(conns);
    return Object.entries(g).map(([proc,cs])=>
      cs.map(c=>`<div class="net-item">
        <span class="net-proc">${esc(proc)}</span>
        <span class="net-remote">${esc(c.named?c.label:c.remote_ip+':'+c.remote_port)}</span>
        <span class="${tagCls}">${tagLbl}</span>
        <span class="tag-st">${c.status}</span>
      </div>`).join('')
    ).join('');
  }
  const ext=net.external||[];
  const intl=net.internal||[];
  document.getElementById('net-ext').innerHTML=
    `<div class="net-section-title">External (${ext.length})</div>`+
    (ext.length?`<div>${rows(ext,'tag-ext','EXT')}</div>`:`<div style="color:var(--muted);font-size:12px;padding:4px 0">None</div>`);
  document.getElementById('net-int').innerHTML=
    intl.length?`<div class="net-section-title">LAN / Loopback (${intl.length})</div><div>${rows(intl,'tag-lan','LAN')}</div>`:'';
}

// ── Issues ───────────────────────────────────────────────────────────────────
function renderIssues(snap){
  const issues=snap.issues||[];
  document.getElementById('issues-wrap').style.display=issues.length?'':'none';
  document.getElementById('issue-count').textContent=issues.length;
  document.getElementById('issues-list').innerHTML=issues.map(iss=>{
    const hasFixer=!!iss.fixer_id;
    const state=iss.state||'active';
    return`<div class="issue-card ${iss.severity}">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
        <span class="badge badge-${iss.severity}">${iss.severity.toUpperCase()}</span>
        <div class="issue-title">${esc(iss.title)}</div>
        <span class="state-badge state-${state}">${state}</span>
      </div>
      <div class="issue-desc">${esc(iss.description)}</div>
      <div class="issue-actions">
        <button class="btn btn-diagnose" onclick="diagnose('${iss.id}','${sesc(iss.title)}')">&#x1F4AC; Diagnose with AI</button>
        ${hasFixer?`<button class="btn btn-fix" onclick="runFix('${iss.id}','${iss.fixer_id}','${sesc(iss.title)}')">&#x26A1; Auto-Fix</button>`:''}
        <button class="btn btn-ack" onclick="ackIssue('${iss.id}')">&#x2713; Ack</button>
        <button class="btn btn-suppress" onclick="suppressIssue('${iss.id}')">Snooze 1h</button>
      </div>
    </div>`;
  }).join('');
}

// ── Alert History ────────────────────────────────────────────────────────────
function renderAlertHist(snap){
  const hist=snap.alert_history||[];
  document.getElementById('alert-hist').innerHTML=hist.length
    ?hist.map(h=>`<div class="hist-item">
        <span class="hist-ts">${h.ts}</span>
        <span class="badge badge-${h.severity}" style="margin-right:4px">${h.severity.charAt(0).toUpperCase()}</span>
        <span>${esc(h.title)}</span>
      </div>`).join('')
    :'<div style="color:var(--muted);font-size:12px">No alerts yet</div>';
}

// ── Projects / Hooks ─────────────────────────────────────────────────────────
function renderProj(snap){
  document.getElementById('proj-rows').innerHTML=(snap.projects||[]).map(p=>
    `<tr><td title="${esc(p.path)}">${esc(p.name)}</td>
     <td>${p.branch||'—'}</td>
     <td><span class="pill ${p.exists?'pill-ok':'pill-no'}">${p.exists?'OK':'Missing'}</span></td></tr>`).join('');
}
function renderHooks(snap){
  document.getElementById('hook-rows').innerHTML=(snap.hooks||[]).map(h=>
    `<tr><td>${esc(h.name)}</td>
     <td><span class="pill ${h.exists?'pill-ok':'pill-no'}">${h.exists?'Yes':'No'}</span></td>
     <td>${h.size_kb!=null?h.size_kb:'—'}</td></tr>`).join('');
}

// ── Full render ──────────────────────────────────────────────────────────────
function render(snap){
  document.getElementById('ts').textContent=snap.ts_display||'';
  const alive=snap.daemon_alive!==false;
  document.getElementById('live-dot').style.display=alive?'':' none';
  document.getElementById('stale-banner').style.display=alive?'none':'';
  document.getElementById('live-dot').className=alive?'dot-live':'dot-stale';
  renderSys(snap);
  renderStorage(snap);
  renderProcs(snap);
  renderPorts(snap);
        window._lastSnap = snap;
        renderFleet(snap);
  renderNetHealth(snap);
  renderNet(snap);
  renderIssues(snap);
  renderAlertHist(snap);
  renderProj(snap);
  renderHooks(snap);
}

// ── API Keys ─────────────────────────────────────────────────────────────────
const STATUS_LABEL = {
  active:'Active', invalid:'Invalid — key rejected', not_configured:'Not configured',
  rate_limited:'Rate limited (key OK)', unreachable:'Unreachable', error:'Error',
  unknown:'Unknown',
};
function renderKeys(data){
  const grid=document.getElementById('keys-grid');
  if(!data||!Object.keys(data).length){
    grid.innerHTML='<div style="color:var(--muted);font-size:12px">Loading...</div>';return;
  }
  _keyDataCache=data;  // cache for modal use
  grid.innerHTML=Object.entries(data).map(([pid,p])=>{
    const v=p.validation||{};
    const st=v.status||'unknown';
    const label=STATUS_LABEL[st]||st;
    const costHtml=p.cost
      ? (p.cost.error
          ? `<div class="key-cost">Cost: error (${p.cost.error})</div>`
          : `<div class="key-cost">Cost MTD: $${(p.cost.usd||0).toFixed(4)}</div>`)
      : (p.cost_available && !p.has_admin_key
          ? `<div style="font-size:10px;color:var(--muted)">Add ${pid.toUpperCase()}_ADMIN_KEY for cost</div>`
          : (!p.cost_available && p.found ? `<div style="font-size:10px;color:var(--muted)">Cost: no API available</div>` : ''));
    const rotateBtn=p.rotate_url
      ? `<a href="${p.rotate_url}" target="_blank" class="btn btn-neutral" style="font-size:10px;padding:3px 8px">Rotate Key</a>`
      : '';
    const recheckBtn=`<button class="btn btn-neutral" style="font-size:10px;padding:3px 8px" onclick="recheckKey('${pid}')">Re-check</button>`;
    const setBtn=`<button class="btn btn-neutral" style="font-size:10px;padding:3px 8px;background:rgba(99,102,241,.18);color:#a5b4fc" onclick="openKeyModal('${pid}','${esc(p.label)}')">Set Key / Model</button>`;
    const modelLabel=(p.models||[]).find(m=>m.id===p.selected_model);
    const modelTag=p.selected_model
      ? `<div style="font-size:10px;margin-top:3px"><span style="color:var(--muted)">Model: </span><span style="color:var(--cyan)">${esc(p.selected_model)}</span>${modelLabel&&modelLabel.label!==p.selected_model?` <span style="color:var(--muted);font-size:9px">${esc(modelLabel.label.split('—')[1]||'').trim()}</span>`:''}</div>`
      : '';
    return`<div class="key-card ${st}">
      <div class="key-top">
        <div class="key-icon">${esc(p.icon||'?')}</div>
        <div>
          <div class="key-name">${esc(p.label)}</div>
          <div class="key-masked">${p.masked||'(no key)'}</div>
        </div>
      </div>
      <div class="key-status ks-${st}">${label}</div>
      ${modelTag}
      ${v.models?`<div style="font-size:10px;color:var(--muted)">${v.models} models available</div>`:''}
      ${v.error&&st!=='active'?`<div style="font-size:10px;color:var(--muted)">${esc(v.error)}</div>`:''}
      ${costHtml}
      <div style="font-size:9px;color:var(--muted);margin-top:4px">Checked ${esc(p.checked_at||'—')}</div>
      <div class="key-actions">${rotateBtn}${setBtn}${recheckBtn}</div>
    </div>`;
  }).join('');
}
function recheckKey(pid){
  fetch('/api/keys/'+pid+'/refresh',{method:'POST'})
    .then(r=>r.json()).then(()=>fetchKeys()).catch(e=>console.error(e));
}
function recheckAllKeys(){
  fetch('/api/keys?refresh=1').then(r=>r.json()).then(renderKeys).catch(e=>console.error(e));
}

// ── Set Key Modal ─────────────────────────────────────────────────────────────
let _keyModalPid='';
let _keyDataCache={};
function openKeyModal(pid,label){
  _keyModalPid=pid;
  document.getElementById('km-title').textContent='Set key: '+label;
  document.getElementById('km-input').value='';
  document.getElementById('km-status').textContent='';
  // Populate model dropdown from cached key data
  const sel=document.getElementById('km-model');
  const hint=document.getElementById('km-model-hint');
  const pdata=_keyDataCache[pid]||{};
  const models=pdata.models||[];
  const current=pdata.selected_model||pdata.default_model||'';
  sel.innerHTML='';
  if(models.length===0){
    sel.innerHTML='<option value="">— no model list for this provider —</option>';
    hint.textContent='';
  } else {
    models.forEach(m=>{
      const opt=document.createElement('option');
      opt.value=m.id;
      opt.textContent=m.label||m.id;
      if(m.id===current)opt.selected=true;
      sel.appendChild(opt);
    });
    sel.addEventListener('change',()=>{
      const m=models.find(x=>x.id===sel.value);
      hint.textContent=m?m.label.split('—').slice(1).join('—').trim():'';
    });
    const initM=models.find(x=>x.id===current);
    hint.textContent=initM?initM.label.split('—').slice(1).join('—').trim():'';
  }
  document.getElementById('key-modal').style.display='flex';
  setTimeout(()=>document.getElementById('km-input').focus(),50);
}
function closeKeyModal(){document.getElementById('key-modal').style.display='none';}
function submitKeyModal(){
  const val=document.getElementById('km-input').value.trim();
  const model=document.getElementById('km-model').value.trim();
  const st=document.getElementById('km-status');
  st.textContent='Saving...';st.style.color='var(--muted)';
  fetch('/api/keys/'+_keyModalPid+'/set',{method:'POST',
    headers:{'Content-Type':'application/json'},body:JSON.stringify({key:val,model:model})})
  .then(r=>r.json()).then(d=>{
    if(d.ok){
      st.textContent=(val?'Saved & validated':'Cleared')+(model?' | Model: '+model:'');
      st.style.color='var(--green)';
      setTimeout(()=>{closeKeyModal();fetchKeys();},900);
    } else {
      st.textContent=d.error||'Error';st.style.color='var(--red)';
    }
  }).catch(e=>{st.textContent='Network error';st.style.color='var(--red)';});
}
function fetchKeys(){
  fetch('/api/keys').then(r=>r.json()).then(renderKeys).catch(e=>console.error(e));
}
// Load keys on startup and every 5 minutes
fetchKeys();
setInterval(fetchKeys, 300*1000);

// ── Claude Code Sessions ──────────────────────────────────────────────────────
function renderSessions(list){
  const el=document.getElementById('sessions-list');
  if(!list||!list.length){
    el.innerHTML='<div style="color:var(--muted);font-size:12px;padding:8px 0">No active sessions in last 24h</div>';return;
  }
  el.innerHTML=list.map(s=>{
    const pct=s.utilization_pct||0;
    const cls=pct>=95?'crit':pct>=85?'warn':'ok';
    const pctColor=pct>=95?'var(--red)':pct>=85?'var(--yellow)':'var(--green)';
    const slug=(s.slug||s.session_id||'?').replace(/^C--Users-techai--?/,'').slice(-32);
    const burn=s.burn_rate_tpm>0?`${Math.round(s.burn_rate_tpm)} tok/min`:'';
    const ageS=s.last_activity_ts?(Date.now()/1000)-s.last_activity_ts:999999;
    const ageLabel=ageS<120?'just now':ageS<3600?Math.round(ageS/60)+'m ago':Math.round(ageS/3600)+'h ago';
    const isStale=ageS>300;  // inactive >5 min — good candidate for resume
    const statusDot=isStale
      ?`<span style="color:var(--muted);font-size:9px" title="Idle ${ageLabel}">⏸</span>`
      :`<span style="color:var(--green);font-size:9px" title="Active ${ageLabel}">▶</span>`;
    const resumeBtn=`<button class="btn btn-neutral" style="font-size:9px;padding:2px 7px;margin-left:4px" title="Launch new terminal with: claude --resume ${esc(s.session_id)}" onclick="resumeSession('${esc(s.session_id)}')">↩ Resume</button>`;
    return`<div class="sess-row" title="Session: ${esc(s.session_id)}\nTurns: ${s.turn_count||0}\nOutput: ${(s.output_tokens_total||0).toLocaleString()} tokens\nLast active: ${ageLabel}">
      <div class="sess-slug" title="${esc(s.slug||'')} · ${ageLabel}">${statusDot} ${esc(slug)}</div>
      <div class="sess-bar-wrap"><div class="sess-bar ${cls}" style="width:${pct}%"></div></div>
      <div class="sess-pct" style="color:${pctColor}">${pct}%</div>
      <div class="sess-burn">${burn||ageLabel}${resumeBtn}</div>
    </div>`;
  }).join('');
}
function fetchSessions(){
  fetch('/api/sessions').then(r=>r.json()).then(renderSessions).catch(e=>console.error(e));
}
function resumeSession(id){
  const btn=event.target;
  btn.textContent='Launching...';btn.disabled=true;
  fetch('/api/sessions/'+encodeURIComponent(id)+'/resume',{method:'POST'})
    .then(r=>r.json()).then(d=>{
      if(d.ok){
        btn.textContent='✓ Launched';btn.style.color='var(--green)';
        setTimeout(()=>{btn.textContent='↩ Resume';btn.disabled=false;},3000);
      } else {
        btn.textContent='✗ '+((d.error||'').slice(0,30));btn.style.color='var(--red)';
        setTimeout(()=>{btn.textContent='↩ Resume';btn.disabled=false;btn.style.color='';},4000);
      }
    }).catch(()=>{btn.textContent='✗ Error';btn.style.color='var(--red)';
      setTimeout(()=>{btn.textContent='↩ Resume';btn.disabled=false;btn.style.color='';},3000);});
}
fetchSessions();
setInterval(fetchSessions, 30*1000);  // refresh every 30 s

// ── MemoryWeb ─────────────────────────────────────────────────────────────────
function renderMemoryWeb(d){
  const el=document.getElementById('mw-panel');
  if(!d){el.innerHTML='<div style="color:var(--muted);font-size:12px">Loading...</div>';return;}
  const dot=d.connected?'<span style="color:var(--green)">●</span>':'<span style="color:var(--red)">●</span>';
  const rows=[
    ['Status', dot+' '+(d.status||'unknown')],
    ['Memories', d.memory_count!=null?d.memory_count.toLocaleString():'—'],
    ['Embedding coverage', d.embedding_coverage_pct!=null?d.embedding_coverage_pct+'%':'—'],
    ['Search latency', d.search_latency_ms!=null?d.search_latency_ms+'ms':'—'],
    ['Last ingestion', d.last_ingestion||'—'],
    ['Checked', d.checked_at||'—'],
    ['URL', d.url||'—'],
  ];
  if(!d.connected&&d.error) rows.splice(1,0,['Error',`<span style="color:var(--red);font-size:10px">${esc(d.error)}</span>`]);
  el.innerHTML=rows.map(([k,v])=>`<div class="mw-stat"><span style="color:var(--muted)">${k}</span><span class="mw-val">${v}</span></div>`).join('');
}
function fetchMemoryWeb(force){
  const url='/api/memoryweb'+(force?'?refresh=1':'');
  fetch(url).then(r=>r.json()).then(renderMemoryWeb).catch(e=>console.error(e));
}
fetchMemoryWeb(false);
setInterval(()=>fetchMemoryWeb(false), 60*1000);

// ── BPC/TSK Governance ────────────────────────────────────────────────────────
let _govLastData=null;

function bpcStartServer(){
  fetch('/api/bpc/start',{method:'POST'}).then(r=>r.json()).then(r=>{
    if(r.started) setTimeout(()=>fetchGovernance(true),3000);
    else alert('BPC start failed: '+(r.error||'unknown'));
  }).catch(e=>alert('BPC start error: '+e));
}

function tskStartServer(){
  fetch('/api/tsk/start',{method:'POST'}).then(r=>r.json()).then(r=>{
    if(r.started) setTimeout(()=>fetchGovernance(true),3000);
    else alert('TSK start failed: '+(r.error||'unknown'));
  }).catch(e=>alert('TSK start error: '+e));
}

function bpcRevokePair(pairId){
  if(!confirm('Revoke pair '+pairId+'?')) return;
  fetch('/api/bpc/revoke/'+encodeURIComponent(pairId),{method:'POST'})
    .then(r=>r.json())
    .then(r=>{ alert(r.revoked?'Revoked.':'Failed: '+(r.error||'?')); fetchGovernance(true); })
    .catch(e=>alert('Error: '+e));
}

let _bpcModal=null;
function bpcShowGenModal(){
  if(!document.getElementById('bpc-gen-modal')){
    const m=document.createElement('div');
    m.id='bpc-gen-modal';
    m.style=`position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.7);z-index:9999;display:flex;align-items:center;justify-content:center`;
    m.innerHTML=`<div style="background:#1e1e2e;border:1px solid var(--cyan);border-radius:8px;padding:20px;min-width:340px;max-width:480px">
      <div style="font-size:13px;font-weight:700;color:var(--cyan);margin-bottom:12px">Generate BPC Keypair</div>
      <div style="margin-bottom:8px"><label style="font-size:11px;color:var(--muted)">Name</label><br>
        <input id="bpc-gen-name" value="dashboard-pair" style="width:100%;background:#2a2a3e;border:1px solid #444;color:#e2e8f0;padding:4px 8px;border-radius:4px;font-size:12px;box-sizing:border-box;margin-top:3px"></div>
      <div style="margin-bottom:8px"><label style="font-size:11px;color:var(--muted)">Scope</label><br>
        <select id="bpc-gen-scope" style="width:100%;background:#2a2a3e;border:1px solid #444;color:#e2e8f0;padding:4px 8px;border-radius:4px;font-size:12px;margin-top:3px">
          <option value="read-write">read-write</option><option value="read">read</option><option value="admin">admin</option>
        </select></div>
      <div style="margin-bottom:12px"><label style="font-size:11px;color:var(--muted)">Mode</label><br>
        <select id="bpc-gen-mode" style="width:100%;background:#2a2a3e;border:1px solid #444;color:#e2e8f0;padding:4px 8px;border-radius:4px;font-size:12px;margin-top:3px">
          <option value="development">development</option><option value="production">production</option>
        </select></div>
      <div style="display:flex;gap:8px;justify-content:flex-end">
        <button class="btn btn-neutral" onclick="document.getElementById('bpc-gen-modal').remove()">Cancel</button>
        <button class="btn btn-primary" onclick="bpcDoGenerate()">Generate</button>
      </div>
      <div id="bpc-gen-result" style="margin-top:12px;display:none"></div>
    </div>`;
    document.body.appendChild(m);
  } else {
    document.getElementById('bpc-gen-modal').style.display='flex';
    document.getElementById('bpc-gen-result').style.display='none';
    document.getElementById('bpc-gen-result').innerHTML='';
  }
}

function bpcDoGenerate(){
  const name=document.getElementById('bpc-gen-name').value.trim()||'dashboard-pair';
  const scope=document.getElementById('bpc-gen-scope').value;
  const mode=document.getElementById('bpc-gen-mode').value;
  const res=document.getElementById('bpc-gen-result');
  res.style.display='block'; res.innerHTML='<div style="color:var(--muted);font-size:11px">Generating...</div>';
  fetch('/api/bpc/generate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,scope,mode})})
    .then(r=>r.json())
    .then(data=>{
      if(data.error){res.innerHTML=`<div style="color:var(--red);font-size:11px">Error: ${esc(data.error)}</div>`;return;}
      res.innerHTML=`<div style="font-size:11px;color:var(--green);margin-bottom:6px">Pair registered: <b>${esc(data.pairId)}</b></div>
        <div style="font-size:10px;color:var(--muted);margin-bottom:4px">Copy and store the private credentials — they are shown only once:</div>
        <textarea readonly style="width:100%;height:90px;background:#0d0d1a;border:1px solid #444;color:#a0a0c0;font-size:9px;padding:4px;border-radius:4px;box-sizing:border-box">${esc(JSON.stringify({pairId:data.pairId,rawSecret:data.rawSecret,privJwk:data.privJwk,scope:data.scope,mode:data.mode},null,2))}</textarea>
        <button class="btn btn-neutral" style="margin-top:6px;font-size:10px" onclick="document.getElementById('bpc-gen-modal').remove();fetchGovernance(true)">Close &amp; Refresh</button>`;
    }).catch(e=>{ res.innerHTML=`<div style="color:var(--red);font-size:11px">Error: ${esc(String(e))}</div>`; });
}

// ── Rotation modal (browser-side ECDSA — old privJwk never leaves client) ────
function bpcShowRotateModal(pairId){
  const id='bpc-rot-modal';
  if(!document.getElementById(id)){
    const m=document.createElement('div');
    m.id=id;
    m.style=`position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.75);z-index:9999;display:flex;align-items:center;justify-content:center`;
    m.innerHTML=`<div style="background:#1e1e2e;border:1px solid var(--orange);border-radius:8px;padding:20px;min-width:380px;max-width:520px">
      <div style="font-size:13px;font-weight:700;color:var(--orange);margin-bottom:4px">Rotate BPC Keypair</div>
      <div style="font-size:10px;color:var(--muted);margin-bottom:10px">Old private key signs the rotation — it never leaves your browser.</div>
      <div style="margin-bottom:8px"><label style="font-size:11px;color:var(--muted)">Pair ID to rotate</label><br>
        <input id="bpc-rot-pair-id" style="width:100%;background:#2a2a3e;border:1px solid #444;color:#e2e8f0;padding:4px 8px;border-radius:4px;font-size:11px;box-sizing:border-box;margin-top:3px;font-family:monospace"></div>
      <div style="margin-bottom:10px"><label style="font-size:11px;color:var(--muted)">Old private key JWK (paste the privJwk from when the pair was generated)</label><br>
        <textarea id="bpc-rot-priv-jwk" rows="4" style="width:100%;background:#2a2a3e;border:1px solid #444;color:#e2e8f0;padding:4px 8px;border-radius:4px;font-size:10px;font-family:monospace;box-sizing:border-box;margin-top:3px"></textarea></div>
      <div style="display:flex;gap:8px;justify-content:flex-end">
        <button class="btn btn-neutral" onclick="document.getElementById('bpc-rot-modal').remove()">Cancel</button>
        <button class="btn btn-primary" style="background:#d97706" onclick="bpcDoRotate()">Rotate</button>
      </div>
      <div id="bpc-rot-result" style="margin-top:10px;display:none"></div>
    </div>`;
    document.body.appendChild(m);
  }
  document.getElementById('bpc-rot-modal').style.display='flex';
  document.getElementById('bpc-rot-pair-id').value=pairId||'';
  document.getElementById('bpc-rot-priv-jwk').value='';
  document.getElementById('bpc-rot-result').style.display='none';
  document.getElementById('bpc-rot-result').innerHTML='';
}

// BPC canonical sort — mirrors @bpc/core canonical.ts (keys sorted, scalars only)
function bpcCanonJson(obj){
  const sorted={};
  Object.keys(obj).sort().forEach(k=>{ sorted[k]=obj[k]; });
  return JSON.stringify(sorted);
}

function b64url(buf){
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}

async function bpcDoRotate(){
  const res=document.getElementById('bpc-rot-result');
  res.style.display='block'; res.innerHTML='<div style="color:var(--muted);font-size:11px">Working...</div>';

  const oldPairId=document.getElementById('bpc-rot-pair-id').value.trim();
  let oldPrivJwk;
  try{ oldPrivJwk=JSON.parse(document.getElementById('bpc-rot-priv-jwk').value.trim()); }
  catch(e){ res.innerHTML='<div style="color:var(--red);font-size:11px">Invalid JSON in private key field.</div>'; return; }

  try{
    // 1. Import old private key
    const oldPrivKey=await crypto.subtle.importKey('jwk',oldPrivJwk,
      {name:'ECDSA',namedCurve:'P-256'},false,['sign']);

    // 2. Generate new keypair
    const newKp=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
    const newPubJwk=await crypto.subtle.exportKey('jwk',newKp.publicKey);
    const newPrivJwk=await crypto.subtle.exportKey('jwk',newKp.privateKey);

    // 3. Build rotation payload (BPC canonical: sorted keys, scalar values only)
    const ts=Date.now();
    const payload={
      new_pub_jwk_json: JSON.stringify(newPubJwk),
      old_pair_id: oldPairId,
      purpose: 'rotation',
      timestamp: ts,
    };
    const canonStr=bpcCanonJson(payload);
    const signedData=b64url(new TextEncoder().encode(canonStr));

    // 4. Sign with old private key
    const sigBuf=await crypto.subtle.sign(
      {name:'ECDSA',hash:'SHA-256'}, oldPrivKey,
      new TextEncoder().encode(canonStr)
    );
    const signature=b64url(sigBuf);

    // 5. Send to dashboard proxy → BPC server
    const rotReq={oldPairId,newPubJwk,signature,signedData,timestamp:ts};
    const r=await fetch('/api/bpc/rotate/'+encodeURIComponent(oldPairId),
      {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(rotReq)});
    const data=await r.json();

    if(data.newPairId){
      res.innerHTML=`<div style="color:var(--green);font-size:11px;margin-bottom:6px">Rotation complete. New pair: <b>${esc(data.newPairId)}</b></div>
        <div style="font-size:10px;color:var(--muted);margin-bottom:4px">Save the new private credentials — shown once only:</div>
        <textarea readonly style="width:100%;height:70px;background:#0d0d1a;border:1px solid #444;color:#a0a0c0;font-size:9px;padding:4px;border-radius:4px;box-sizing:border-box">${esc(JSON.stringify({pairId:data.newPairId,privJwk:newPrivJwk,pubJwk:newPubJwk},null,2))}</textarea>
        <button class="btn btn-neutral" style="margin-top:6px;font-size:10px" onclick="document.getElementById('bpc-rot-modal').remove();fetchGovernance(true)">Close &amp; Refresh</button>`;
    } else {
      res.innerHTML=`<div style="color:var(--red);font-size:11px">Rotation failed: ${esc(JSON.stringify(data))}</div>`;
    }
  } catch(e){
    res.innerHTML=`<div style="color:var(--red);font-size:11px">Error: ${esc(String(e))}</div>`;
  }
}

// ── PID health display ────────────────────────────────────────────────────────
let _svcHealth={};
function fetchSvcHealth(){
  fetch('/api/gov/health').then(r=>r.json()).then(h=>{
    _svcHealth=h;
    renderSvcHealth(h);
  }).catch(()=>{});
}
function renderSvcHealth(h){
  const el=document.getElementById('svc-health-row');
  if(!el||!h) return;
  const fmt=s=>{
    const status=s.status||'unknown';
    const pid=s.pid?`PID ${s.pid}`:'no pid';
    const since=s.started_at||'';
    const crashed=s.crashed_at?` crashed ${s.crashed_at}`:'';
    const col=status==='running'?'var(--green)':status==='crashed'?'var(--red)':'var(--muted)';
    return `<span style="color:${col};font-weight:700">${status.toUpperCase()}</span> <span style="color:var(--muted);font-size:10px">${pid}${since?' since '+since:''}${crashed}</span>`;
  };
  el.innerHTML=`<span style="font-size:10px;color:var(--muted)">BPC proc: ${fmt(h.bpc||{})} &nbsp;|&nbsp; TSK proc: ${fmt(h.tsk||{})}</span>`;
}
fetchSvcHealth();
setInterval(fetchSvcHealth, 10*1000);

function renderGovernance(d){
  _govLastData=d;
  const el=document.getElementById('gov-panel');
  if(!d){el.innerHTML='<div style="color:var(--muted);font-size:12px">Loading...</div>';return;}
  let html='';

  // ── BPC section ──────────────────────────────────────────────────────────
  const bpc=d.bpc||{};
  const bpcOnline=bpc.connected===true;
  const bpcOffline=bpc.offline===true||(!bpcOnline&&(bpc.error||'').match(/10061|refused|10060/));

  html+=`<div style="display:flex;align-items:center;gap:6px;margin-bottom:6px;flex-wrap:wrap">
    <span style="font-size:11px;font-weight:700;color:var(--cyan)">BPC</span>
    <span style="font-size:10px;padding:1px 5px;border-radius:3px;background:${bpcOnline?'#065f46':'#450a0a'};color:${bpcOnline?'#6ee7b7':'#fca5a5'}">${bpcOnline?'ONLINE':'OFFLINE'}</span>
    ${bpcOnline?`<span style="font-size:10px;color:var(--muted)">${bpc.active||0} active · ${bpc.revoked||0} revoked</span>`:''}
    <span style="margin-left:auto;display:flex;gap:5px">
      ${!bpcOnline?`<button class="btn btn-primary" style="font-size:10px;padding:2px 8px" onclick="bpcStartServer()">Start BPC Server</button>`:''}
      ${bpcOnline?`<button class="btn btn-primary" style="font-size:10px;padding:2px 8px" onclick="bpcShowGenModal()">+ Generate</button>`:''}
      ${bpcOnline?`<button class="btn btn-neutral" style="font-size:10px;padding:2px 8px;color:var(--orange)" onclick="bpcShowRotateModal('')">Rotate</button>`:''}
      ${bpcOnline?`<button class="btn btn-neutral" style="font-size:10px;padding:2px 8px" onclick="bpcShowAudit()">Audit</button>`:''}
    </span>
  </div>`;

  if(bpcOnline){
    const pairs=(bpc.pairs||[]).slice(0,12);
    if(pairs.length){
      html+=`<table style="width:100%;font-size:10px;border-collapse:collapse;margin-bottom:6px">
        <tr style="color:var(--muted)"><th style="text-align:left;padding:2px 3px">Pair ID</th><th>Name</th><th>Scope</th><th>Status</th><th>Reqs</th><th></th></tr>`;
      pairs.forEach(p=>{
        const stCol=p.status==='active'?'var(--green)':p.status==='revoked'?'var(--red)':p.status==='rotated'?'var(--orange)':'var(--muted)';
        const pid=esc(p.id||'');
        html+=`<tr style="border-top:1px solid #2a2a3e">
          <td style="padding:2px 3px;font-family:monospace;color:var(--cyan);font-size:9px">${esc((p.id||'').slice(0,16)+'…')}</td>
          <td style="padding:2px 3px;color:var(--muted)">${esc(p.name||'')}</td>
          <td style="padding:2px 3px;color:var(--muted)">${esc(p.scope||'')}</td>
          <td style="padding:2px 3px;color:${stCol}">${esc(p.status||'?')}</td>
          <td style="padding:2px 3px;color:var(--muted);text-align:right">${p.requests||0}</td>
          <td style="padding:2px 3px;white-space:nowrap">
            ${p.status==='active'?`<button class="btn btn-neutral" style="font-size:9px;padding:1px 4px;color:var(--orange)" onclick="bpcShowRotateModal('${pid}')">↻</button> <button class="btn btn-neutral" style="font-size:9px;padding:1px 4px;color:var(--red)" onclick="bpcRevokePair('${pid}')">✕</button>`:''}
          </td>
        </tr>`;
      });
      html+='</table>';
      if((bpc.pairs||[]).length>12) html+=`<div style="font-size:10px;color:var(--muted);margin-bottom:4px">${bpc.pairs.length-12} more pairs not shown</div>`;
    } else {
      html+=`<div style="font-size:11px;color:var(--muted);margin-bottom:6px">No pairs yet — click <b>+ Generate</b> to create the first pair.</div>`;
    }
    const anomaly=bpc.anomaly||{};
    if(anomaly.score!=null){
      const sc=anomaly.score; const scCol=sc>70?'var(--red)':sc>30?'var(--orange)':'var(--green)';
      html+=`<div style="font-size:10px;color:var(--muted)">Anomaly score: <span style="color:${scCol};font-weight:700">${sc}</span></div>`;
    }
  } else if(bpcOffline){
    html+=`<div style="font-size:10px;color:var(--muted)">Server at <code>${esc(d.bpc_url||'localhost:3100')}</code> is not running. Click <b>Start BPC Server</b> above or run: <code>cd ~/bpc-protocol/demo &amp;&amp; npx tsx server.ts</code></div>`;
  } else {
    html+=`<div style="font-size:10px;color:var(--red)">${esc(bpc.error||'connection error')}</div>`;
  }

  // ── TSK section ──────────────────────────────────────────────────────────
  html+='<div class="sep" style="margin:7px 0"></div>';
  const tsk=(d.tsk||{}).anomaly||{};
  const tskOnline=tsk.connected===true;

  html+=`<div style="display:flex;align-items:center;gap:6px;margin-bottom:6px">
    <span style="font-size:11px;font-weight:700;color:var(--cyan)">TSK</span>
    <span style="font-size:10px;padding:1px 5px;border-radius:3px;background:${tskOnline?'#065f46':'#450a0a'};color:${tskOnline?'#6ee7b7':'#fca5a5'}">${tskOnline?'ONLINE':'OFFLINE'}</span>
    ${!tskOnline?`<button class="btn btn-primary" style="font-size:10px;padding:2px 8px;margin-left:auto" onclick="tskStartServer()">Start TSK Server</button>`:''}
  </div>`;

  if(tskOnline){
    const scores=tsk.scores||{};
    const clients=Object.keys(scores);
    const attacks=clients.filter(c=>scores[c]&&scores[c].verdict==='attack');
    const suspicious=clients.filter(c=>scores[c]&&scores[c].verdict==='suspicious');
    html+=`<div style="font-size:11px">${clients.length} clients`;
    if(attacks.length) html+=` · <span style="color:var(--red);font-weight:700">${attacks.length} ATTACK</span>`;
    if(suspicious.length) html+=` · <span style="color:var(--orange)">${suspicious.length} suspicious</span>`;
    html+='</div>';
    [...attacks,...suspicious].slice(0,4).forEach(c=>{
      const s=scores[c]; const col=s.verdict==='attack'?'var(--red)':'var(--orange)';
      html+=`<div class="gov-ev" style="margin-top:2px"><span style="color:${col};font-weight:700">[${(s.verdict||'?').toUpperCase()}]</span> ${esc(c)} <span style="color:var(--muted)">score=${s.score||0}</span></div>`;
    });
    const tskEvs=((d.tsk||{}).recent_events||[]).slice(-4);
    if(tskEvs.length){
      html+='<div style="margin-top:4px;font-size:10px;color:var(--muted)">Recent:</div>';
      tskEvs.forEach(ev=>{
        const ts=ev.ts?new Date(ev.ts).toLocaleTimeString():'';
        html+=`<div style="font-size:9px;color:var(--muted)">${ts} ${esc(ev.event||'')} ${ev.session?'·'+ev.session.slice(0,8):''}</div>`;
      });
    }
  } else {
    html+=`<div style="font-size:10px;color:var(--muted)">Server at <code>${esc(d.tsk_url||'localhost:3200')}</code>. Click <b>Start TSK Server</b> or run: <code>cd ~/tsk-protocol &amp;&amp; npx tsx demo/server.ts</code></div>`;
  }

  // ── PID health row ────────────────────────────────────────────────────────
  html+='<div class="sep" style="margin:7px 0"></div>';
  html+=`<div id="svc-health-row" style="font-size:10px;color:var(--muted)">loading process health...</div>`;

  el.innerHTML=html;
  renderSvcHealth(_svcHealth);
}

function bpcShowAudit(){
  fetch('/api/bpc/audit?n=20').then(r=>r.json()).then(data=>{
    const entries=data.entries||[];
    const integrity=data.integrity||{};
    let html=`<div style="font-size:12px;font-weight:700;color:var(--cyan);margin-bottom:8px">BPC Audit Chain`;
    html+=` <span style="font-size:10px;font-weight:400;color:${integrity.ok?'var(--green)':'var(--red)'}">${integrity.ok?'✓ intact':'TAMPERED at entry '+integrity.broken_at}</span> (${integrity.checked||0} checked)</div>`;
    if(!entries.length){ html+='<div style="color:var(--muted);font-size:11px">No entries yet.</div>'; }
    entries.slice().reverse().forEach(e=>{
      const actCol=e.action==='generate'?'var(--green)':e.action==='revoke'?'var(--red)':e.action==='rotate'?'var(--orange)':'var(--cyan)';
      html+=`<div style="font-size:10px;border-bottom:1px solid #2a2a3e;padding:3px 0">
        <span style="color:${actCol};font-weight:700">${esc(e.action||'')}</span>
        <span style="color:var(--muted);margin-left:6px;font-family:monospace">${esc((e.pair_id||'').slice(0,20))}</span>
        <span style="float:right;color:var(--muted)">${esc(e.ts||'')}</span><br>
        <span style="font-size:9px;color:#444;font-family:monospace">${esc((e.entry_hash||'').slice(0,20)+'…')}</span>
      </div>`;
    });
    const m=document.createElement('div');
    m.style='position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.75);z-index:9999;display:flex;align-items:center;justify-content:center';
    m.innerHTML=`<div style="background:#1e1e2e;border:1px solid var(--cyan);border-radius:8px;padding:18px;min-width:420px;max-width:580px;max-height:80vh;overflow-y:auto">
      ${html}
      <button class="btn btn-neutral" style="margin-top:10px" onclick="this.closest('[style*=fixed]').remove()">Close</button>
    </div>`;
    document.body.appendChild(m);
  }).catch(e=>alert('Audit fetch failed: '+e));
}

function fetchGovernance(force){
  const url='/api/governance'+(force?'?refresh=1':'');
  fetch(url).then(r=>r.json()).then(renderGovernance).catch(e=>console.error(e));
}
fetchGovernance(false);
setInterval(()=>fetchGovernance(false), 30*1000);

// ── Cost Tracker ─────────────────────────────────────────────────────────────
const COST_COLORS = {
  anthropic: '#06b6d4',
  openai:    '#22c55e',
  gemini:    '#eab308',
  groq:      '#f97316',
};
const COST_LABELS = {
  anthropic: 'Anthropic (Claude)',
  openai:    'OpenAI (GPT)',
  gemini:    'Google Gemini',
  groq:      'Groq',
};

function costSparkline(points, color) {
  const W = 200, H = 40, N = points.length;
  if (N < 2) {
    return `<svg viewBox="0 0 ${W} ${H}" class="cost-spark"><line x1="0" y1="${H/2}" x2="${W}" y2="${H/2}" stroke="${color}" stroke-width="1" stroke-dasharray="4 3" opacity="0.4"/></svg>`;
  }
  const mn = Math.min(...points), mx = Math.max(...points);
  const range = mx - mn || 0.0001;
  const pad = 3;
  const pts = points.map((v, i) => {
    const x = (i / (N - 1)) * W;
    const y = H - pad - ((v - mn) / range) * (H - pad * 2);
    return x.toFixed(1) + ',' + y.toFixed(1);
  }).join(' ');
  const area = `0,${H} ${pts} ${W},${H}`;
  return `<svg viewBox="0 0 ${W} ${H}" class="cost-spark" preserveAspectRatio="none">
    <polygon points="${area}" style="fill:${color}22"/>
    <polyline points="${pts}" style="fill:none;stroke:${color};stroke-width:1.5;stroke-linejoin:round"/>
  </svg>`;
}

function renderCostHistory(data) {
  const el = document.getElementById('cost-panel');
  if (!data || !Object.keys(data).length) {
    el.innerHTML = '<div style="color:var(--muted);font-size:12px">No cost data yet — requires ANTHROPIC_ADMIN_KEY or OPENAI_ADMIN_KEY.</div>';
    return;
  }
  const providers = Object.keys(data).filter(k => data[k] && data[k].length > 0);
  if (!providers.length) {
    el.innerHTML = '<div style="color:var(--muted);font-size:12px">No cost snapshots recorded yet.</div>';
    return;
  }
  el.innerHTML = providers.map(pid => {
    const series = data[pid];
    // Last 14 entries for sparkline
    const slice = series.slice(-14);
    const vals = slice.map(r => r.cost_usd);
    const mtd = vals.length ? vals[vals.length - 1] : 0;
    const color = COST_COLORS[pid] || '#6366f1';
    const label = COST_LABELS[pid] || pid;
    const spark = costSparkline(vals, color);
    const firstDate = slice.length ? slice[0].date : '';
    const lastDate  = slice.length ? slice[slice.length - 1].date : '';
    const rangeText = slice.length > 1 ? `${firstDate} → ${lastDate}` : lastDate;
    return `<div class="cost-provider-row">
      <div class="cost-header">
        <span class="cost-label" style="color:${color}">${esc(label)}</span>
        <span class="cost-mtd">$${mtd.toFixed(4)} MTD</span>
      </div>
      ${spark}
      <div class="cost-range">${esc(rangeText)}</div>
    </div>`;
  }).join('<div class="sep" style="margin:8px 0"></div>');
}

function fetchCostHistory(force) {
  const url = '/api/cost-history' + (force ? '?refresh=1' : '');
  fetch(url).then(r => r.json()).then(renderCostHistory).catch(e => console.error(e));
}
fetchCostHistory(false);
setInterval(() => fetchCostHistory(false), 15 * 60 * 1000);


// ── Agent Mesh ────────────────────────────────────────────────────────────────
function renderMesh(data) {
  const el = document.getElementById('mesh-panel');
  if (!el) return;
  if (!data) {
    el.innerHTML = '<div style="color:var(--muted);font-size:12px">Loading...</div>';
    return;
  }

  const army   = data.army   || {};
  const hub    = data.hub    || {};
  const agentd = data.agentd || {};

  // Node row builder
  function nodeRow(node, label, sublabel) {
    const up   = node.reachable;
    const dot  = up
      ? '<span class="mesh-dot mesh-dot-up"></span>'
      : '<span class="mesh-dot mesh-dot-dn"></span>';
    const lat  = node.latency_ms != null ? node.latency_ms + 'ms' : '—';
    const cnt  = node.agents_online != null
      ? node.agents_online + ' / ' + (node.agent_count || '?') + ' agents'
      : node.agent_count != null
        ? node.agent_count + ' agents'
        : (up ? '—' : (node.start_hint
            ? '<span style="color:var(--muted);font-size:10px" title="' + esc(node.start_hint) + '">not running</span>'
            : 'unreachable'));
    return `<div class="mesh-node-row">
      <div class="mesh-node-left">
        ${dot}
        <div>
          <div class="mesh-node-name">${esc(label)}</div>
          <div class="mesh-node-sub">${esc(sublabel)}</div>
        </div>
      </div>
      <div class="mesh-node-right">
        <div class="mesh-node-cnt">${cnt}</div>
        <div class="mesh-node-lat">${up ? lat : ''}</div>
      </div>
    </div>`;
  }

  // Army agent detail rows
  let agentDetail = '';
  const agents = army.api_data;
  if (Array.isArray(agents) && agents.length) {
    agentDetail = '<div class="mesh-agent-table-wrap"><table class="mesh-agent-table">'
      + '<thead><tr>'
      + '<th>Agent</th><th>Machine</th><th>Status</th>'
      + '<th>Done</th><th>Fail</th><th>Tokens</th><th>Cost</th>'
      + '</tr></thead><tbody>'
      + agents.map(a => {
          const st    = a.status || '?';
          const stCls = st === 'online' ? 'mesh-st-online' : 'mesh-st-offline';
          const cost  = a.total_cost_usd != null ? '$' + (+a.total_cost_usd).toFixed(4) : '—';
          const tok   = a.total_tokens != null ? (+a.total_tokens).toLocaleString() : '—';
          const hb    = a.last_heartbeat
            ? (() => {
                try {
                  const d = (Date.now() / 1000) - new Date(a.last_heartbeat).getTime() / 1000;
                  return d < 120 ? 'just now' : d < 3600 ? Math.round(d / 60) + 'm ago' : Math.round(d / 3600) + 'h ago';
                } catch(e) { return a.last_heartbeat; }
              })()
            : '—';
          return `<tr title="Last heartbeat: ${esc(hb)}">
            <td>${esc(a.role || a.id || '?')}</td>
            <td>${esc(a.machine || '—')}</td>
            <td><span class="${stCls}">${esc(st)}</span></td>
            <td>${a.tasks_completed != null ? a.tasks_completed : '—'}</td>
            <td>${a.tasks_failed    != null ? a.tasks_failed    : '—'}</td>
            <td>${tok}</td>
            <td>${cost}</td>
          </tr>`;
        }).join('')
      + '</tbody></table></div>';
  }

  // Hub conversations badge
  let hubExtra = '';
  if (hub.reachable) {
    const ca = hub.conversations_active != null ? hub.conversations_active : '?';
    const ct = hub.conversations_total  != null ? hub.conversations_total  : '?';
    const dead = hub.dead_agent_count != null ? ` &bull; ${hub.dead_agent_count} stale` : '';
    hubExtra = `<div class="mesh-hub-line">${ca} active convs / ${ct} total${dead}</div>`;
  }

  const healthDot = data.mesh_healthy
    ? '<span style="color:var(--green)">&#9679;</span> Healthy'
    : '<span style="color:var(--red)">&#9679;</span> Degraded';

  el.innerHTML = `
    <div class="mesh-health-line">${healthDot} &bull; checked ${esc(data.checked_at || '—')}</div>
    ${nodeRow(army,   'AI Army OS',     'Spark-1 · 192.168.12.132:8500 · GB10 119.7 GB')}
    ${nodeRow(hub,    'Army Hub',       'Spark-1 · 192.168.12.132:8765')}
    ${hubExtra}
    ${nodeRow(agentd, 'Agent-Status',   'localhost:8089 · Windows PC · RTX 5090')}
    ${agentDetail}
  `;
}

function fetchMesh(force) {
  const url = '/api/mesh' + (force ? '?refresh=1' : '');
  fetch(url)
    .then(r => r.json())
    .then(renderMesh)
    .catch(e => console.error('mesh fetch error', e));
}

// Startup + 15 s interval
fetchMesh(false);
setInterval(() => fetchMesh(false), 15 * 1000);


// ── AI Chat ───────────────────────────────────────────────────────────────────
let _chatHistory = [];
let _chatOpen = false;
let _chatBusy = false;

function toggleChat(){
  _chatOpen = !_chatOpen;
  const drawer = document.getElementById('chat-drawer');
  const fab = document.getElementById('chat-fab');
  const chevron = document.getElementById('chat-chevron');
  drawer.style.display = _chatOpen ? 'flex' : 'none';
  fab.style.display = _chatOpen ? 'none' : '';
  chevron.textContent = _chatOpen ? '▼' : '▲';
  if(_chatOpen) document.getElementById('chat-input').focus();
}

function clearChat(){
  _chatHistory = [];
  document.getElementById('chat-messages').innerHTML = '';
}

function chatKeydown(e){
  if(e.key==='Enter' && !e.shiftKey){ e.preventDefault(); sendChat(); }
}

function _appendMsg(role, text){
  const el = document.createElement('div');
  el.style.cssText = role==='user'
    ? 'align-self:flex-end;background:var(--accent);color:#000;padding:7px 11px;border-radius:10px 10px 2px 10px;font-size:12px;max-width:85%;white-space:pre-wrap'
    : 'align-self:flex-start;background:var(--surface2);color:var(--text);padding:7px 11px;border-radius:10px 10px 10px 2px;font-size:12px;max-width:90%;white-space:pre-wrap;border:1px solid var(--border)';
  el.textContent = text;
  const msgs = document.getElementById('chat-messages');
  msgs.appendChild(el);
  msgs.scrollTop = msgs.scrollHeight;
  return el;
}

function sendChat(){
  if(_chatBusy) return;
  const inp = document.getElementById('chat-input');
  const msg = inp.value.trim();
  if(!msg) return;
  inp.value = '';
  _chatBusy = true;
  document.getElementById('chat-send-btn').disabled = true;

  _appendMsg('user', msg);
  const thinking = _appendMsg('assistant', '…');

  fetch('/api/chat', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({message: msg, history: _chatHistory})
  })
  .then(r=>r.json())
  .then(d=>{
    const reply = d.reply || d.error || '(no response)';
    thinking.textContent = reply;
    _chatHistory.push({role:'user', content:msg});
    _chatHistory.push({role:'assistant', content:reply});
    // Keep last 20 turns
    if(_chatHistory.length > 20) _chatHistory = _chatHistory.slice(-20);
  })
  .catch(e=>{ thinking.textContent = 'Error: '+e; })
  .finally(()=>{
    _chatBusy = false;
    document.getElementById('chat-send-btn').disabled = false;
  });
}

// Show model label in chat header once status loads
function _setChatModelLabel(snap){
  const lbl = document.getElementById('chat-model-label');
  if(lbl && snap && snap.system) {
    fetch('/api/status').then(()=>{}).catch(()=>{});
  }
}

// ── Polling ──────────────────────────────────────────────────────────────────
function fetchStatus(){
  fetch('/api/status').then(r=>r.json()).then(render).catch(e=>console.error(e));
}
fetchStatus();
setInterval(fetchStatus,REFRESH_S*1000);
setInterval(()=>{
  countdown--;if(countdown<0)countdown=REFRESH_S;
  document.getElementById('countdown').textContent=countdown;
},1000);

// ── Acknowledge / Suppress ───────────────────────────────────────────────────
function ackIssue(id){
  fetch('/api/issues/'+encodeURIComponent(id)+'/acknowledge',{method:'POST'})
    .then(r=>r.json()).then(()=>fetchStatus()).catch(e=>console.error(e));
}
function suppressIssue(id){
  fetch('/api/issues/'+encodeURIComponent(id)+'/suppress',{
    method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({until_minutes:60})
  }).then(r=>r.json()).then(()=>fetchStatus()).catch(e=>console.error(e));
}

// ── Kill PID ─────────────────────────────────────────────────────────────────
function killPid(pid,name){
  if(!confirm(`Kill ${name} PID ${pid}?`))return;
  openModal('Kill PID '+pid);
  fetch('/api/kill_pid',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pid})})
    .then(r=>r.json()).then(d=>{(d.output||[]).forEach(l=>addLine(l+'\n'));})
    .catch(e=>addLine('ERROR: '+e+'\n'));
}

// ── Diagnose ─────────────────────────────────────────────────────────────────
function diagnose(id,title){
  openModal('Diagnosing: '+title);
  document.getElementById('diag-box').style.display='none';
  addLine('Sending to AI for analysis...\n');
  fetch('/api/diagnose',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({issue_id:id})})
    .then(r=>r.json()).then(d=>{
      clearTerm();
      if(d.error){addLine('ERROR: '+d.error+'\n');return;}
      const box=document.getElementById('diag-box');
      box.style.display='block';
      document.getElementById('d-sum').textContent=d.summary||'—';
      document.getElementById('d-cause').textContent=d.root_cause||'—';
      document.getElementById('d-fix').textContent=d.suggested_fix||'—';
      const ce=document.getElementById('d-conf');
      ce.textContent=d.confidence||'—';
      ce.className='diag-val conf-'+(d.confidence||'low');
      addLine('Analysis complete. Confidence: '+d.confidence+'\n');
    }).catch(e=>addLine('ERROR: '+e+'\n'));
}

// ── Fix ───────────────────────────────────────────────────────────────────────
// EventSource cannot send custom headers, so we exchange the session token for a
// single-use 30-second ticket via POST /api/fix/ticket, then open the SSE stream
// with ?ticket=<ticket>.  This keeps the main token out of server access logs.
function runFix(id,fixerId,title){
  if(!confirm('Run automated fix for:\n'+title))return;
  document.getElementById('diag-box').style.display='none';
  openModal('Fixing: '+title);
  const token=window._dashToken||'';
  // Step 1: obtain a short-lived SSE ticket
  fetch('/api/fix/ticket',{
    method:'POST',
    headers:token?{'X-Dashboard-Token':token}:{},
  }).then(r=>{
    if(!r.ok){addLine('Auth error obtaining SSE ticket (status '+r.status+')\n','t-fail');return;}
    return r.json();
  }).then(data=>{
    if(!data)return;
    const ticket=data.ticket||'';
    // Step 2: open EventSource with the single-use ticket
    const url='/api/fix/stream?issue_id='+encodeURIComponent(id)+'&fixer_id='+encodeURIComponent(fixerId)+(ticket?'&ticket='+encodeURIComponent(ticket):'');
    const es=new EventSource(url);
    es.onmessage=e=>{
      const l=e.data;
      const cls=l.startsWith('DONE')?'t-done':l.startsWith('FAILED')?'t-fail':'';
      addLine(l+'\n',cls);
      if(l==='DONE'||l.startsWith('FAILED')){es.close();if(l==='DONE')setTimeout(fetchStatus,1000);}
    };
    es.onerror=()=>{addLine('Stream ended.\n');es.close();};
  }).catch(e=>addLine('ERROR: '+e+'\n','t-fail'));
}

// ── Modal ────────────────────────────────────────────────────────────────────
function openModal(title){
  document.getElementById('modal-title').textContent=title;
  clearTerm();
  document.getElementById('backdrop').classList.add('open');
}
function closeModal(){document.getElementById('backdrop').classList.remove('open');}
function bgClick(e){if(e.target===document.getElementById('backdrop'))closeModal();}
// ── Dashboard API Tokens ──────────────────────────────────────────────────────
const SCOPE_HINTS={
  read:'Read-only: /api/status, /api/sessions, /api/memoryweb, /api/keys',
  write:'Read + acknowledge issues, kill PIDs, set keys',
  admin:'Full access including token management'
};
function renderTokens(d){
  const el=document.getElementById('tokens-panel');
  const tokens=(d&&d.tokens)||[];
  if(!tokens.length){
    el.innerHTML='<div style="color:var(--muted);font-size:12px">No tokens yet. Generate one to let external tools call dashboard endpoints.</div>';
    return;
  }
  const rows=tokens.map(t=>{
    const age=t.created_at?(()=>{const s=(Date.now()/1000)-t.created_at;return s<3600?Math.round(s/60)+'m ago':Math.round(s/3600)+'h ago';})():'';
    const used=t.last_used_at?(()=>{const s=(Date.now()/1000)-t.last_used_at;return s<3600?Math.round(s/60)+'m ago':Math.round(s/3600)+'h ago';})():'never';
    const revokedStyle=t.revoked?'opacity:.4;text-decoration:line-through':'';
    return`<tr style="${revokedStyle}">
      <td><span style="font-weight:600">${esc(t.name)}</span></td>
      <td><code style="font-size:10px;color:var(--muted)">${esc(t.id)}</code></td>
      <td><span style="font-size:10px;background:rgba(99,102,241,.18);color:#a5b4fc;border-radius:3px;padding:1px 6px">${esc(t.scope)}</span></td>
      <td style="font-size:10px;color:var(--muted)">${age}</td>
      <td style="font-size:10px;color:${t.use_count>0?'var(--green)':'var(--muted)'}">${t.use_count}x ${used!=='never'?'· '+used:''}</td>
      <td>${t.revoked
        ?`<button class="btn btn-neutral" style="font-size:9px;padding:2px 7px;color:var(--red)" onclick="deleteToken('${esc(t.id)}')">Delete</button>`
        :`<button class="btn btn-neutral" style="font-size:9px;padding:2px 7px" onclick="revokeToken('${esc(t.id)}')">Revoke</button>`
      }</td>
    </tr>`;
  }).join('');
  el.innerHTML=`<table style="width:100%;border-collapse:collapse;font-size:11px">
    <thead><tr style="color:var(--muted);font-size:10px">
      <th style="text-align:left;padding:4px 8px">Name</th>
      <th style="text-align:left;padding:4px 8px">Token ID</th>
      <th style="text-align:left;padding:4px 8px">Scope</th>
      <th style="text-align:left;padding:4px 8px">Created</th>
      <th style="text-align:left;padding:4px 8px">Usage</th>
      <th style="padding:4px 8px"></th>
    </tr></thead>
    <tbody>${rows}</tbody>
  </table>
  <div style="font-size:10px;color:var(--muted);margin-top:10px">Use header <code>X-Dashboard-Token: dtok_...</code> on any API call. Each use is tracked above.</div>`;
}
function fetchTokens(){
  fetch('/api/tokens').then(r=>r.json()).then(renderTokens).catch(e=>console.error(e));
}
function revokeToken(id){
  if(!confirm('Revoke this token? It will stop working immediately.'))return;
  fetch('/api/tokens/'+id+'/revoke',{method:'POST'}).then(()=>fetchTokens()).catch(e=>console.error(e));
}
function deleteToken(id){
  fetch('/api/tokens/'+id,{method:'DELETE'}).then(()=>fetchTokens()).catch(e=>console.error(e));
}
fetchTokens();

// Token Modal
function openTokenModal(){
  document.getElementById('tm-name').value='';
  document.getElementById('tm-result').style.display='none';
  document.getElementById('tm-status').textContent='';
  document.getElementById('tm-submit').disabled=false;
  document.getElementById('token-modal').style.display='flex';
  setTimeout(()=>document.getElementById('tm-name').focus(),50);
}
function closeTokenModal(){document.getElementById('token-modal').style.display='none';fetchTokens();}
document.getElementById('tm-scope').addEventListener('change',function(){
  document.getElementById('tm-scope-hint').textContent=SCOPE_HINTS[this.value]||'';
});
function submitTokenModal(){
  const name=document.getElementById('tm-name').value.trim();
  const scope=document.getElementById('tm-scope').value;
  const st=document.getElementById('tm-status');
  if(!name){st.textContent='Name required';st.style.color='var(--red)';return;}
  document.getElementById('tm-submit').disabled=true;
  st.textContent='Generating...';st.style.color='var(--muted)';
  fetch('/api/tokens',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,scope})})
    .then(r=>r.json()).then(d=>{
      if(d.ok&&d.token&&d.token.raw){
        document.getElementById('tm-raw').textContent=d.token.raw;
        document.getElementById('tm-result').style.display='block';
        st.textContent='';
      } else {
        st.textContent=d.error||'Error';st.style.color='var(--red)';
        document.getElementById('tm-submit').disabled=false;
      }
    }).catch(e=>{st.textContent='Network error';st.style.color='var(--red)';document.getElementById('tm-submit').disabled=false;});
}
function copyToken(){
  navigator.clipboard.writeText(document.getElementById('tm-raw').textContent)
    .then(()=>{const b=event.target;b.textContent='Copied!';setTimeout(()=>b.textContent='Copy to Clipboard',2000);});
}

// ── Help Modal ────────────────────────────────────────────────────────────────
function openHelp(){document.getElementById('help-modal').classList.add('open');}
function closeHelp(){document.getElementById('help-modal').classList.remove('open');}
document.addEventListener('keydown',e=>{if(e.key==='Escape'){closeHelp();closeTokenModal();}});
function addLine(text,cls){
  const t=document.getElementById('terminal');
  const s=document.createElement('span');
  if(cls)s.className=cls;
  s.textContent=text;t.appendChild(s);t.scrollTop=t.scrollHeight;
}
function clearTerm(){document.getElementById('terminal').innerHTML='';}
</script>
</body>
</html>"""

# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import psutil as _ps
    _boot_ts = _ps.boot_time()

    # Patch build_snapshot to include system uptime
    _orig_build = collector.build_snapshot
    def _patched_build():
        s = _orig_build()
        s["system"]["boot_time_s"] = round(time.time() - _boot_ts, 0)
        return s
    collector.build_snapshot = _patched_build

    dcfg = cfg.dashboard()
    port = dcfg.get("port", 8099)
    host = dcfg.get("host", "127.0.0.1")

    _start_daemon()
    _fleet.start_watcher()
    _guard.start_watcher()
    _svc_health.start_watcher()
    print_startup_token()
    print(f"System Dashboard -> http://{host}:{port}")
    app.run(host=host, port=port, debug=False, threaded=True)
