"""Network health monitor — ping latency, packet loss, bandwidth per interface.

Runs as a background thread; results are cached and read zero-cost by the
collector. Avoids blocking the daemon tick with slow ping operations.
"""
from __future__ import annotations

import subprocess
import sys
import threading
import time
from typing import Any

import psutil

# Targets to ping for connectivity/latency check
_PING_TARGETS = [
    ("Cloudflare DNS", "1.1.1.1"),
    ("Google DNS", "8.8.8.8"),
]

# How often to re-ping and re-sample bandwidth (seconds)
_REFRESH_S = 30

# Shared results — written by background thread, read by collector
_lock = threading.Lock()
_latest: dict[str, Any] = {
    "ping": [],
    "interfaces": {},
    "last_updated": 0.0,
    "error": None,
}

# Bandwidth delta state
_prev_io: dict[str, Any] = {}
_prev_ts: float = 0.0


def _ping_once(host: str, count: int = 4) -> dict[str, Any]:
    """Ping host, return {host, latency_ms, packet_loss_pct, ok}."""
    try:
        if sys.platform == "win32":
            cmd = ["ping", "-n", str(count), host]
        else:
            cmd = ["ping", "-c", str(count), "-W", "2", host]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=count * 2 + 3,
            creationflags=0x08000000 if sys.platform == "win32" else 0,
        )
        out = result.stdout + result.stderr

        # Parse latency — Windows: "Average = Xms", Linux/Mac: "avg = X"
        latency_ms: float | None = None
        if sys.platform == "win32":
            for line in out.splitlines():
                if "Average" in line and "ms" in line:
                    try:
                        latency_ms = float(line.split("=")[-1].strip().replace("ms", ""))
                    except ValueError:
                        pass
        else:
            for line in out.splitlines():
                if "avg" in line and "/" in line:
                    try:
                        # rtt min/avg/max/mdev = X/Y/Z/W ms
                        latency_ms = float(line.split("/")[4])
                    except (IndexError, ValueError):
                        pass

        # Parse packet loss — Windows: "X% loss", Linux: "X% packet loss"
        loss_pct: float = 0.0
        for line in out.splitlines():
            if "%" in line and ("loss" in line.lower() or "Lost" in line):
                try:
                    loss_pct = float(line.split("%")[0].split()[-1])
                except (IndexError, ValueError):
                    pass

        ok = latency_ms is not None and loss_pct < 100
        return {
            "host": host,
            "latency_ms": round(latency_ms, 1) if latency_ms is not None else None,
            "packet_loss_pct": loss_pct,
            "ok": ok,
        }
    except Exception as exc:
        return {"host": host, "latency_ms": None, "packet_loss_pct": 100.0, "ok": False, "error": str(exc)[:60]}


def _sample_interfaces() -> dict[str, dict]:
    """Return per-interface stats: speed, sent/recv bytes/s, is_up."""
    global _prev_io, _prev_ts

    try:
        counters = psutil.net_io_counters(pernic=True) or {}
    except Exception:
        return {}

    now = time.time()
    dt = now - _prev_ts if _prev_ts else 1.0
    stats = psutil.net_if_stats() or {}
    addrs = psutil.net_if_addrs() or {}

    # Virtual/tunnel interfaces always show artificial drops — exclude from alerts
    _VIRTUAL_PREFIXES = ("loopback", "nordlynx", "wg", "tun", "tap", "vethernet", "isatap")

    result: dict[str, dict] = {}
    for nic, c in counters.items():
        prev = _prev_io.get(nic)
        is_virtual = nic.lower().startswith(_VIRTUAL_PREFIXES)
        if prev and dt > 0:
            sent_mbs = round((c.bytes_sent - prev.bytes_sent) / 1e6 / dt, 3)
            recv_mbs = round((c.bytes_recv - prev.bytes_recv) / 1e6 / dt, 3)
            packets_sent_ps = round((c.packets_sent - prev.packets_sent) / dt, 1)
            packets_recv_ps = round((c.packets_recv - prev.packets_recv) / dt, 1)
            dropped_ps = round(
                ((c.dropin - prev.dropin) + (c.dropout - prev.dropout)) / dt, 2
            )
            errs_ps = round(
                ((c.errin - prev.errin) + (c.errout - prev.errout)) / dt, 2
            )
        else:
            sent_mbs = recv_mbs = 0.0
            packets_sent_ps = packets_recv_ps = 0.0
            dropped_ps = errs_ps = 0.0

        st = stats.get(nic)
        is_up = bool(st and st.isup)
        speed_mbps = int(st.speed) if st and st.speed else None

        # Grab IPv4 address if present
        ipv4 = ""
        for addr in addrs.get(nic, []):
            if addr.family == 2:  # AF_INET
                ipv4 = addr.address
                break

        result[nic] = {
            "is_up": is_up,
            "speed_mbps": speed_mbps,
            "ipv4": ipv4,
            "sent_mbs": max(0.0, sent_mbs),
            "recv_mbs": max(0.0, recv_mbs),
            "packets_sent_ps": max(0.0, packets_sent_ps),
            "packets_recv_ps": max(0.0, packets_recv_ps),
            "dropped_ps": max(0.0, dropped_ps),
            "errs_ps": max(0.0, errs_ps),
            "is_virtual": is_virtual,  # virtual/tunnel NICs show artificial drops — don't alert
        }

    _prev_io = {nic: c for nic, c in counters.items()}
    _prev_ts = now
    return result


def _refresh() -> None:
    """Run one round of pings and interface sampling."""
    ping_results = []
    for label, host in _PING_TARGETS:
        r = _ping_once(host)
        r["label"] = label
        ping_results.append(r)

    ifaces = _sample_interfaces()

    with _lock:
        _latest["ping"] = ping_results
        _latest["interfaces"] = ifaces
        _latest["last_updated"] = time.time()
        _latest["error"] = None


def get_network_health() -> dict[str, Any]:
    """Return the latest cached network health snapshot (zero blocking)."""
    with _lock:
        return dict(_latest)


def start_watcher() -> None:
    """Start the background network health watcher (call once at startup)."""
    def _loop() -> None:
        while True:
            try:
                _refresh()
            except Exception as exc:
                with _lock:
                    _latest["error"] = str(exc)[:80]
            time.sleep(_REFRESH_S)

    t = threading.Thread(target=_loop, daemon=True, name="net-monitor")
    t.start()
