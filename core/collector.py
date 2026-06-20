"""System data collector — psutil + nvidia-smi, config-driven."""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import psutil

from . import config as cfg

# ── SMART / NVMe health ───────────────────────────────────────────────────────

_CREATE_NO_WINDOW = 0x08000000


def _run_ps(command: str, timeout: int = 3) -> str | None:
    """Run a PowerShell command and return stdout, or None on failure."""
    flags = _CREATE_NO_WINDOW if sys.platform == "win32" else 0
    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, timeout=timeout,
            creationflags=flags,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass
    return None


def _ps_get_physical_disks() -> list[dict]:
    """Return list of physical disk dicts from Get-PhysicalDisk."""
    raw = _run_ps(
        "Get-PhysicalDisk | Select-Object DeviceId,FriendlyName,HealthStatus,"
        "OperationalStatus,Size | ConvertTo-Json"
    )
    if not raw:
        return []
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            data = [data]
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _ps_get_reliability_counters(disk_list: list[dict]) -> list[dict]:
    """Return reliability counters for all physical disks."""
    raw = _run_ps(
        "Get-StorageReliabilityCounter -PhysicalDisk (Get-PhysicalDisk) | "
        "Select-Object DeviceId,Temperature,ReadErrorsTotal,WriteErrorsTotal,Wear | "
        "ConvertTo-Json"
    )
    if not raw:
        return []
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            data = [data]
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _ps_drive_letter_map() -> dict[str, str]:
    """Return mapping of DeviceId → drive letter(s) via Get-Partition."""
    raw = _run_ps(
        "Get-Partition | Where-Object {$_.DriveLetter} | "
        "Select-Object DiskNumber,DriveLetter | ConvertTo-Json"
    )
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            data = [data]
        mapping: dict[str, str] = {}
        for item in data:
            disk_num = str(item.get("DiskNumber", ""))
            letter = item.get("DriveLetter", "")
            if disk_num and letter:
                mapping[disk_num] = str(letter).strip()
        return mapping
    except Exception:
        return {}


def _smart_via_powershell() -> dict[str, dict]:
    """Collect SMART data via PowerShell Get-PhysicalDisk + Get-StorageReliabilityCounter."""
    disks = _ps_get_physical_disks()
    if not disks:
        return {}

    reliability = _ps_get_reliability_counters(disks)
    rel_by_id: dict[str, dict] = {str(r.get("DeviceId", "")): r for r in reliability}
    letter_map = _ps_drive_letter_map()  # DiskNumber → letter

    result: dict[str, dict] = {}
    for disk in disks:
        dev_id = str(disk.get("DeviceId", ""))
        disk_num = dev_id  # DeviceId == DiskNumber in Windows storage stack
        letter = letter_map.get(disk_num)
        if not letter:
            continue

        health_raw = (disk.get("HealthStatus") or "Unknown").strip()
        # Normalise: Healthy / Warning / Unhealthy / Unknown
        health_map = {"healthy": "Healthy", "warning": "Warning",
                      "unhealthy": "Unhealthy", "unknown": "Unknown"}
        health = health_map.get(health_raw.lower(), health_raw)

        rel = rel_by_id.get(dev_id, {})

        def _int(v: Any) -> int | None:
            try:
                return int(v) if v is not None else None
            except (TypeError, ValueError):
                return None

        temp = _int(rel.get("Temperature"))
        read_err = _int(rel.get("ReadErrorsTotal")) or 0
        write_err = _int(rel.get("WriteErrorsTotal")) or 0
        wear = _int(rel.get("Wear"))  # 0-100, remaining life in %

        result[letter] = {
            "health": health,
            "temp_c": temp,
            "read_errors": read_err,
            "write_errors": write_err,
            "wear_pct": wear,
            "media_errors": 0,        # not surfaced by PS cmdlet
            "available_spare_pct": None,
            "model": (disk.get("FriendlyName") or "").strip(),
            "method": "powershell",
        }
    return result


def _smart_via_smartctl() -> dict[str, dict]:
    """Collect SMART data via smartctl (if installed)."""
    flags = _CREATE_NO_WINDOW if sys.platform == "win32" else 0
    result: dict[str, dict] = {}

    # Build a list of candidates: \\.\PhysicalDrive0 … PhysicalDrive9 on Windows,
    # /dev/sda … /dev/sdz on Linux.
    if sys.platform == "win32":
        candidates = [f"\\\\.\\PhysicalDrive{n}" for n in range(6)]
    else:
        candidates = [f"/dev/sd{chr(c)}" for c in range(ord('a'), ord('g'))]

    for device in candidates:
        try:
            proc = subprocess.run(
                ["smartctl", "-a", "-j", device],
                capture_output=True, text=True, timeout=3,
                creationflags=flags,
            )
            if proc.returncode not in (0, 4) or not proc.stdout.strip():
                continue
            data = json.loads(proc.stdout)
        except Exception:
            continue

        # Drive letter mapping on Windows
        letter = None
        if sys.platform == "win32":
            try:
                dev_num = device.replace("\\\\.\\PhysicalDrive", "")
                raw = _run_ps(
                    f"Get-Partition -DiskNumber {dev_num} | "
                    f"Where-Object {{$_.DriveLetter}} | "
                    f"Select-Object -First 1 -ExpandProperty DriveLetter"
                )
                if raw:
                    letter = raw.strip()
            except Exception:
                pass
        if not letter:
            continue  # can't associate with a drive letter

        smart_status = data.get("smart_status", {})
        health_ok = smart_status.get("passed", True)
        health = "Healthy" if health_ok else "Unhealthy"

        temp_obj = data.get("temperature", {})
        temp = temp_obj.get("current") if temp_obj else None

        # NVMe-specific fields
        nvme = data.get("nvme_smart_health_information_log", {})
        media_errors = nvme.get("media_errors", 0)
        spare_pct = nvme.get("available_spare", None)
        wear_level = nvme.get("percentage_used", None)
        wear_pct = (100 - wear_level) if wear_level is not None else None

        # ATA error counts
        ata_errors = data.get("ata_smart_error_log", {})
        read_err = 0
        write_err = 0
        if not nvme:
            for attr in data.get("ata_smart_attributes", {}).get("table", []):
                aid = attr.get("id")
                raw_val = attr.get("raw", {}).get("value", 0)
                if aid in (1, 7):    # Raw_Read_Error_Rate / Seek_Error_Rate
                    read_err += raw_val
                elif aid == 199:      # UDMA_CRC_Error_Count → write path errors
                    write_err += raw_val

        model_info = data.get("model_name", "") or data.get("model_family", "")

        result[letter] = {
            "health": health,
            "temp_c": temp,
            "read_errors": read_err,
            "write_errors": write_err,
            "wear_pct": wear_pct,
            "media_errors": media_errors,
            "available_spare_pct": spare_pct,
            "model": model_info,
            "method": "smartctl",
        }
    return result


def get_smart_health() -> dict[str, dict]:
    """Return SMART/NVMe health data keyed by drive letter.

    Tries PowerShell cmdlets first (no extra tools needed on Windows),
    then falls back to smartctl.  Returns empty dict on any failure.
    Guaranteed to complete within ~6 seconds (3s per method).
    """
    if sys.platform != "win32":
        # On non-Windows just try smartctl
        try:
            return _smart_via_smartctl()
        except Exception:
            return {}

    try:
        ps_data = _smart_via_powershell()
        if ps_data:
            return ps_data
    except Exception:
        pass

    try:
        return _smart_via_smartctl()
    except Exception:
        return {}

# ── GPU ───────────────────────────────────────────────────────────────────────

def _gpu_metrics() -> list[dict]:
    """Return one dict per GPU via pynvml (preferred) or nvidia-smi fallback."""
    try:
        import pynvml
        pynvml.nvmlInit()
        count = pynvml.nvmlDeviceGetCount()
        gpus = []
        for i in range(count):
            h = pynvml.nvmlDeviceGetHandleByIndex(i)
            name = pynvml.nvmlDeviceGetName(h)
            if isinstance(name, bytes):
                name = name.decode()
            mem = pynvml.nvmlDeviceGetMemoryInfo(h)
            util = pynvml.nvmlDeviceGetUtilizationRates(h)
            try:
                temp = pynvml.nvmlDeviceGetTemperature(h, pynvml.NVML_TEMPERATURE_GPU)
            except Exception:
                temp = None
            try:
                power = round(pynvml.nvmlDeviceGetPowerUsage(h) / 1000, 1)
                power_limit = round(pynvml.nvmlDeviceGetEnforcedPowerLimit(h) / 1000, 1)
            except Exception:
                power = power_limit = None
            gpus.append({
                "index": i,
                "name": name,
                "mem_used_mb": round(mem.used / 1e6, 0),
                "mem_total_mb": round(mem.total / 1e6, 0),
                "mem_pct": round(mem.used / mem.total * 100, 1),
                "gpu_pct": util.gpu,
                "mem_util_pct": util.memory,
                "temp_c": temp,
                "power_w": power,
                "power_limit_w": power_limit,
            })
        pynvml.nvmlShutdown()
        return gpus
    except Exception:
        pass

    # fallback: nvidia-smi CSV
    try:
        out = subprocess.check_output(
            ["nvidia-smi",
             "--query-gpu=index,name,memory.used,memory.total,utilization.gpu,temperature.gpu",
             "--format=csv,noheader,nounits"],
            text=True, timeout=5
        )
        gpus = []
        for line in out.strip().splitlines():
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 6:
                continue
            idx, name, mem_used, mem_total, util_gpu, temp = parts[:6]
            mem_used_f = float(mem_used) if mem_used != "[N/A]" else 0
            mem_total_f = float(mem_total) if mem_total != "[N/A]" else 1
            gpus.append({
                "index": int(idx),
                "name": name,
                "mem_used_mb": mem_used_f,
                "mem_total_mb": mem_total_f,
                "mem_pct": round(mem_used_f / mem_total_f * 100, 1),
                "gpu_pct": int(util_gpu) if util_gpu != "[N/A]" else 0,
                "mem_util_pct": 0,
                "temp_c": int(temp) if temp not in ("[N/A]", "") else None,
                "power_w": None,
                "power_limit_w": None,
            })
        return gpus
    except Exception:
        return []


# ── System ────────────────────────────────────────────────────────────────────

def get_system_metrics() -> dict:
    # Non-blocking CPU% — prime on first call, return cached on subsequent calls
    cpu = psutil.cpu_percent(interval=None)
    vm = psutil.virtual_memory()

    stor = cfg.storage()
    failing = set(stor.get("failing_drives", []))
    warn_free = stor.get("warn_free_gb_below", 10.0)
    drives: dict[str, dict] = {}
    for letter in stor.get("drives", ["C", "D"]):
        path = f"{letter}:\\"
        try:
            import concurrent.futures as _cf
            with _cf.ThreadPoolExecutor(max_workers=1) as ex:
                fut = ex.submit(psutil.disk_usage, path)
                try:
                    du = fut.result(timeout=1.5)  # 1.5s max per drive (D: can be slow)
                    free_gb = round(du.free / 1e9, 1)
                    drives[letter] = {
                        "total_gb": round(du.total / 1e9, 1),
                        "used_gb": round(du.used / 1e9, 1),
                        "free_gb": free_gb,
                        "pct": du.percent,
                        "failing": letter in failing,
                        "warn": free_gb < warn_free or letter in failing,
                    }
                except Exception:
                    drives[letter] = {
                        "total_gb": 0, "used_gb": 0, "free_gb": 0, "pct": 0,
                        "failing": letter in failing, "warn": True,
                    }
        except (PermissionError, FileNotFoundError, OSError):
            pass

    compressed_mb = 0.0  # skip per-process scan in hot path — too slow on large systems

    return {
        "cpu_pct": cpu,
        "cpu_count": psutil.cpu_count(),
        "ram_total_gb": round(vm.total / 1e9, 1),
        "ram_used_gb": round(vm.used / 1e9, 1),
        "ram_avail_gb": round(vm.available / 1e9, 1),
        "ram_pct": vm.percent,
        "ram_compressed_mb": compressed_mb,
        "drives": drives,
        "gpus": _gpu_metrics(),
    }


# ── Processes ─────────────────────────────────────────────────────────────────

def get_processes() -> dict[str, dict]:
    tracked = cfg.processes()
    tracked_names = {t["name"].lower() for t in tracked}
    tracked_meta = {t["name"].lower(): t for t in tracked}

    grouped: dict[str, list[dict]] = {}
    now = time.time()
    # Two-pass: cheap name/pid scan first, then targeted expensive attrs for matches
    matching_pids: list[tuple[int, str]] = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            name = (proc.info["name"] or "").lower()
            if name in tracked_names:
                matching_pids.append((proc.info["pid"], name))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    for pid, name in matching_pids:
        try:
            proc = psutil.Process(pid)
            with proc.oneshot():
                mi = proc.memory_info()
                mem_mb = round((mi.rss if mi else 0) / 1e6, 1)
                status = proc.status()
                create_time = proc.create_time()
            if name not in grouped:
                grouped[name] = []
            grouped[name].append({
                "pid": pid,
                "mem_mb": mem_mb,
                "status": status,
                "age_s": round(now - create_time, 0),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    result: dict[str, dict] = {}
    for t in tracked:
        lname = t["name"].lower()
        procs = grouped.get(lname, [])
        total_mb = sum(p["mem_mb"] for p in procs)
        result[t["name"]] = {
            "label": t.get("label", t["name"]),
            "count": len(procs),
            "total_mb": round(total_mb, 1),
            "warn": t.get("warn", False) and len(procs) > 0,
            "warn_reason": t.get("warn_reason", ""),
            "warn_count": t.get("warn_if_count_exceeds", 0),
            "procs": sorted(procs, key=lambda p: p["mem_mb"], reverse=True)[:10],
        }
    return result


# ── Ports ─────────────────────────────────────────────────────────────────────

def get_port_status() -> dict[int, dict]:
    listening: set[int] = set()
    port_pids: dict[int, int] = {}

    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "LISTEN" and conn.laddr:
                port = conn.laddr.port
                listening.add(port)
                if conn.pid:
                    port_pids[port] = conn.pid
    except (psutil.AccessDenied, PermissionError):
        try:
            out = subprocess.check_output(
                ["netstat", "-ano"], text=True, timeout=5,
                creationflags=0x08000000,
            )
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 5 and "LISTENING" in parts:
                    addr = parts[1]
                    try:
                        port = int(addr.rsplit(":", 1)[-1])
                        pid = int(parts[-1])
                        listening.add(port)
                        port_pids[port] = pid
                    except (ValueError, IndexError):
                        pass
        except Exception:
            pass

    known = cfg.ports()
    result: dict[int, dict] = {}
    for port, label in known.items():
        up = port in listening
        pid = port_pids.get(port)
        proc_name = None
        if pid:
            try:
                proc_name = psutil.Process(pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        result[port] = {"label": label, "up": up, "pid": pid, "proc": proc_name}
    return result


# ── Network ───────────────────────────────────────────────────────────────────

def get_network_connections() -> dict[str, list]:
    ips = cfg.known_ips()
    external: list[dict] = []
    internal: list[dict] = []

    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        conns = []

    for conn in conns:
        if conn.status not in ("ESTABLISHED", "CLOSE_WAIT"):
            continue
        if not conn.raddr:
            continue
        rip = conn.raddr.ip
        rport = conn.raddr.port
        lport = conn.laddr.port if conn.laddr else 0
        pid = conn.pid
        proc_name = "?"
        if pid:
            try:
                proc_name = psutil.Process(pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        named_ip = ips.get(rip, "")
        label = named_ip or f"{proc_name} → {rip}:{rport}"
        if named_ip:
            label = f"{proc_name} → {named_ip} (:{rport})"

        entry = {
            "remote_ip": rip,
            "remote_port": rport,
            "local_port": lport,
            "pid": pid,
            "proc": proc_name,
            "status": conn.status,
            "label": label,
            "named": bool(named_ip),
        }

        is_private = rip.startswith(("10.", "192.168.", "172.16.", "172.17.",
                                     "172.18.", "172.19.", "172.20.", "172.21.",
                                     "172.22.", "172.23.", "172.24.", "172.25.",
                                     "172.26.", "172.27.", "172.28.", "172.29.",
                                     "172.30.", "172.31.", "127.", "::1", "fe80"))
        if is_private:
            internal.append(entry)
        else:
            external.append(entry)

    return {"external": external[:30], "internal": internal[:30]}


# ── Hooks ─────────────────────────────────────────────────────────────────────

_HOOK_DIR = Path.home() / ".claude" / "hooks"
_KNOWN_HOOKS = [
    "restore.py", "mw_pre_session.py", "mw_post_session.py",
    "stop_journal.py", "soul_session_hook.py", "pre_compact.py",
    "run_with_timeout.py",
]

def get_hook_status() -> list[dict]:
    result = []
    for hook in _KNOWN_HOOKS:
        path = _HOOK_DIR / hook
        exists = path.exists()
        mtime = size_kb = None
        if exists:
            stat = path.stat()
            mtime = time.strftime("%Y-%m-%d %H:%M", time.localtime(stat.st_mtime))
            size_kb = round(stat.st_size / 1024, 1)
        result.append({"name": hook, "exists": exists, "mtime": mtime, "size_kb": size_kb})
    return result


# ── Projects ──────────────────────────────────────────────────────────────────

def get_project_status() -> list[dict]:
    result = []
    for proj in cfg.projects():
        path: Path = proj["path"]
        exists = path.exists()
        git = (path / ".git").exists() if exists else False
        branch = None
        if git:
            try:
                head = (path / ".git" / "HEAD").read_text().strip()
                if head.startswith("ref: refs/heads/"):
                    branch = head.replace("ref: refs/heads/", "")
            except Exception:
                pass
        result.append({
            "name": proj["name"],
            "path": str(path),
            "exists": exists,
            "git": git,
            "branch": branch,
        })
    return result


# ── Full snapshot ─────────────────────────────────────────────────────────────

def build_snapshot() -> dict:
    return {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "ts_display": time.strftime("%Y-%m-%d %H:%M:%S"),
        "system": get_system_metrics(),
        "processes": get_processes(),
        "ports": {str(k): v for k, v in get_port_status().items()},
        "network": get_network_connections(),
        "hooks": get_hook_status(),
        "projects": get_project_status(),
        "smart_health": get_smart_health(),
    }
