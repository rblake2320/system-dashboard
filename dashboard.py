"""System Dashboard — main Flask app with SSE fix streaming."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# Ensure stdout handles unicode on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Add project root to path
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import datetime

from flask import Flask, Response, jsonify, request, stream_with_context

from core import config as cfg, collector, issues as issue_mod
from core.persistence import db
from core.auth import require_token, generate_token, print_startup_token, issue_sse_ticket, require_sse_ticket
from core.audit import log_action
from core.pid_guard import pid_guard
from daemon.monitor import daemon, alert_history
from agents.ollama import get_agent
from fixers.process_fixer import ProcessFixer
from fixers.service_fixer import ServiceFixer, StorageFixer

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

FIXERS = {f.fixer_id: f for f in [ProcessFixer(), ServiceFixer(), StorageFixer()]}

# ── Bootstrap ──────────────────────────────────────────────────────────────────

def _start_daemon() -> None:
    dcfg = cfg.daemon()
    if dcfg.get("enabled", True):
        daemon.start()
        print("[dashboard] Background monitor started")


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
    success = any("DONE" in l for l in lines)
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
.port-item{background:var(--surface2);border-radius:7px;padding:8px 10px;display:flex;align-items:flex-start;gap:8px}
.port-item:hover{background:var(--border)}
.dot{width:8px;height:8px;border-radius:50%;flex-shrink:0;margin-top:4px}
.dot-up{background:var(--green)}
.dot-dn{background:var(--border)}
.port-name{font-size:12px;font-weight:500}
.port-num{font-size:10px;color:var(--muted)}
.port-up{font-size:10px;color:var(--muted)}

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
    <div class="card-title">Storage</div>
    <div class="grid-auto" id="storage-grid"></div>
  </div>

  <!-- Processes -->
  <div class="card">
    <div class="card-title">AI &amp; Agent Processes</div>
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
    <div class="card-title">Service Ports &mdash; <span id="ports-up">0</span> / <span id="ports-total">0</span> up</div>
    <div class="port-grid" id="port-grid"></div>
  </div>

  <!-- Network -->
  <div class="card">
    <div class="card-title">Network Connections</div>
    <div id="net-ext"></div>
    <div id="net-int"></div>
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
    html+=`<div class="card" style="${bdr}">
      <div class="card-title">Drive ${lt}: ${d.failing?'<span style="color:var(--red)">FAILING</span>':''}</div>
      <div class="metric-big">${d.free_gb}<span style="font-size:13px;font-weight:400">GB free</span></div>
      <div class="metric-sub">${d.used_gb} / ${d.total_gb}GB &bull; ${d.pct}% used</div>
      <div class="bar-track"><div class="bar-fill ${d.failing?'bar-red':barCls(d.pct)}" style="width:${d.pct}%"></div></div>
      ${ioD?`<div class="io-row">R: ${ioD.read_mbs}MB/s &uarr;&nbsp;&nbsp; W: ${ioD.write_mbs}MB/s &darr;</div>`:''}
    </div>`;
  }
  document.getElementById('storage-grid').innerHTML=html;
}

// ── Processes ────────────────────────────────────────────────────────────────
function renderProcs(snap){
  const procs=snap.processes||{};
  let tiles='',rows='';
  for(const [nm,pd] of Object.entries(procs)){
    tiles+=`<div class="proc-tile" style="${pd.warn?'border:1px solid var(--yellow)':''}">
      <div class="count">${pd.count}</div>
      <div class="pname">${esc(pd.label||nm)}</div>
      <div class="pmem">${pd.total_mb}MB</div>
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
        <div class="port-name">${esc(pd.label||'')}</div>
        <div class="port-num">:${port}${pd.proc?' &bull; '+esc(pd.proc):''}</div>
        ${ut?`<div class="port-up">${ut}</div>`:''}
      </div>`;
    if(pd.up){
      html+=`<div class="port-item"><a href="http://127.0.0.1:${port}" target="_blank">${inner}</a></div>`;
    } else {
      html+=`<div class="port-item">${inner}</div>`;
    }
  }
  document.getElementById('ports-up').textContent=up;
  document.getElementById('ports-total').textContent=total;
  document.getElementById('port-grid').innerHTML=html;
}

// ── Network ──────────────────────────────────────────────────────────────────
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
  renderNet(snap);
  renderIssues(snap);
  renderAlertHist(snap);
  renderProj(snap);
  renderHooks(snap);
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
    print_startup_token()
    print(f"System Dashboard -> http://{host}:{port}")
    app.run(host=host, port=port, debug=False, threaded=True)
