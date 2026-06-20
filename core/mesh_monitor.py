"""Agent Mesh monitor — polls AI Army OS, Hub, and local agent-status daemon.

Endpoint map (confirmed by live probe 2026-06-20):
  Army OS  http://192.168.12.132:8500  /health  /api/agents
  Hub      http://192.168.12.132:8765  /health  /agents
  AgentD   http://localhost:8089        /health  /status

Configure under the "mesh:" key in config.yaml.
"""
from __future__ import annotations

import json
import time
import urllib.request
import urllib.error

_CACHE_TTL = 15        # seconds — matches the spec
_DEFAULT_TIMEOUT = 3   # seconds per request

_cache: dict = {}
_cache_ts: float = 0.0


# ── Low-level HTTP helper ─────────────────────────────────────────────────────

def _get(url: str, timeout: int = _DEFAULT_TIMEOUT) -> tuple[int, dict | list | None]:
    """GET url → (http_status_code, parsed_json_body | None).

    Returns (0, None) on any connection/timeout error so callers never crash.
    """
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode(errors="replace")
            return resp.status, json.loads(body)
    except urllib.error.HTTPError as exc:
        return exc.code, None
    except Exception:
        return 0, None


# ── Per-source probers ────────────────────────────────────────────────────────

def _probe_army(base_url: str, timeout: int) -> dict:
    """Probe AI Army OS (:8500).

    Primary data: GET /api/agents (array of agent objects).
    Liveness:     GET /health
    """
    result: dict = {
        "name": "AI Army OS",
        "host": base_url,
        "reachable": False,
        "latency_ms": None,
        "agent_count": None,
        "agents_online": None,
        "tasks_completed": None,
        "tasks_failed": None,
        "total_tokens": None,
        "total_cost_usd": None,
        "last_seen": None,
        "api_data": None,
    }

    # Liveness ping
    t0 = time.time()
    code, health = _get(f"{base_url}/health", timeout)
    latency_ms = round((time.time() - t0) * 1000)

    if code != 200:
        return result

    result["reachable"] = True
    result["latency_ms"] = latency_ms
    result["last_seen"] = time.strftime("%H:%M:%S")

    # Authoritative agent roster
    _, agents = _get(f"{base_url}/api/agents", timeout)
    if isinstance(agents, list):
        result["agent_count"] = len(agents)
        result["agents_online"] = sum(1 for a in agents if a.get("status") == "online")
        result["tasks_completed"] = sum(a.get("tasks_completed", 0) or 0 for a in agents)
        result["tasks_failed"] = sum(a.get("tasks_failed", 0) or 0 for a in agents)
        result["total_tokens"] = sum(a.get("total_tokens", 0) or 0 for a in agents)
        result["total_cost_usd"] = round(
            sum(a.get("total_cost_usd", 0.0) or 0.0 for a in agents), 6
        )
        # Keep compact per-agent summary for the panel
        result["api_data"] = [
            {
                "id": a.get("id"),
                "role": a.get("role"),
                "machine": a.get("machine"),
                "status": a.get("status"),
                "tasks_completed": a.get("tasks_completed"),
                "tasks_failed": a.get("tasks_failed"),
                "total_tokens": a.get("total_tokens"),
                "total_cost_usd": a.get("total_cost_usd"),
                "last_heartbeat": a.get("last_heartbeat"),
                "current_task_id": a.get("current_task_id"),
            }
            for a in agents
        ]
    elif isinstance(health, dict):
        # Fallback: extract what /health offers
        result["api_data"] = health

    return result


def _probe_hub(base_url: str, timeout: int) -> dict:
    """Probe AI Army Hub (:8765).

    Uses GET /health for aggregate mesh stats.
    GET /agents is intentionally skipped — all 13 hub agents exceeded the 600 s TTL
    so the list is always empty; /health stats are the useful source.
    """
    result: dict = {
        "name": "Army Hub",
        "host": base_url,
        "reachable": False,
        "latency_ms": None,
        "agent_count": None,
        "agents_online": None,
        "conversations_active": None,
        "conversations_total": None,
        "dead_agent_count": None,
        "uptime": None,
        "last_seen": None,
        "api_data": None,
    }

    t0 = time.time()
    code, health = _get(f"{base_url}/health", timeout)
    latency_ms = round((time.time() - t0) * 1000)

    if code != 200 or not isinstance(health, dict):
        return result

    result["reachable"] = True
    result["latency_ms"] = latency_ms
    result["last_seen"] = time.strftime("%H:%M:%S")

    stats = health.get("stats") or health
    result["agent_count"] = stats.get("agent_count") or health.get("agent_count")
    result["dead_agent_count"] = stats.get("dead_agent_count") or health.get("dead_agent_count")
    result["agents_online"] = stats.get("agents_online")
    result["conversations_active"] = stats.get("conversations_active")
    result["conversations_total"] = stats.get("conversations_total")
    result["uptime"] = stats.get("uptime")
    result["api_data"] = health

    return result


def _probe_agentd(base_url: str, timeout: int) -> dict:
    """Probe local agent-status daemon (:8089).

    The daemon is often stopped — we degrade gracefully to unreachable
    and include a start hint so the panel can surface it.
    """
    result: dict = {
        "name": "Agent-Status",
        "host": base_url,
        "reachable": False,
        "latency_ms": None,
        "agent_count": None,
        "last_seen": None,
        "api_data": None,
        "start_hint": "python start.py --port 8089  (from C:/Users/techai/agent-status)",
    }

    t0 = time.time()
    code, body = _get(f"{base_url}/health", timeout)
    latency_ms = round((time.time() - t0) * 1000)

    if code == 200 and body:
        result["reachable"] = True
        result["latency_ms"] = latency_ms
        result["last_seen"] = time.strftime("%H:%M:%S")
        # Try /status for richer data
        _, status = _get(f"{base_url}/status", timeout)
        if isinstance(status, dict):
            result["agent_count"] = status.get("session_count") or status.get("agent_count")
            result["api_data"] = status
        else:
            result["api_data"] = body
    elif code == 0:
        # Connection refused / not started — expected state, not an error
        result["api_data"] = {"note": "daemon not running", "start_hint": result["start_hint"]}

    return result


# ── Mesh healthy heuristic ────────────────────────────────────────────────────

def _mesh_healthy(nodes: list[dict]) -> bool:
    """Mesh is healthy when at least the Army OS node is reachable."""
    army = next((n for n in nodes if "Army OS" in n.get("name", "")), None)
    return bool(army and army.get("reachable"))


# ── Public API ────────────────────────────────────────────────────────────────

def get_mesh_status(force: bool = False) -> dict:
    """Return mesh status dict.

    Keys:
      nodes         list[dict]  — one entry per probed node
      checked_at    str         — HH:MM:SS timestamp of last probe
      mesh_healthy  bool        — True when Army OS is reachable
      army          dict        — shortcut to the Army OS node (agents list etc.)
      hub           dict        — shortcut to the Hub node
      agentd        dict        — shortcut to the agent-status node
    """
    global _cache, _cache_ts

    if not force and _cache and (time.time() - _cache_ts) < _CACHE_TTL:
        return _cache

    # Load URLs from config.yaml (mesh: block) with documented defaults
    from core import config as cfg
    mesh_cfg = cfg.get().get("mesh", {})
    army_url  = mesh_cfg.get("army_url",  "http://192.168.12.132:8500")
    hub_url   = mesh_cfg.get("hub_url",   "http://192.168.12.132:8765")
    agentd_url = mesh_cfg.get("agentd_url", "http://localhost:8089")
    timeout   = int(mesh_cfg.get("timeout_seconds", _DEFAULT_TIMEOUT))

    army   = _probe_army(army_url,   timeout)
    hub    = _probe_hub(hub_url,     timeout)
    agentd = _probe_agentd(agentd_url, timeout)

    nodes = [army, hub, agentd]

    result = {
        "nodes": nodes,
        "checked_at": time.strftime("%H:%M:%S"),
        "mesh_healthy": _mesh_healthy(nodes),
        "army":   army,
        "hub":    hub,
        "agentd": agentd,
    }

    _cache = result
    _cache_ts = time.time()
    return result
