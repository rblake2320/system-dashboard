"""Service fixer — restart services, diagnose port conflicts."""
from __future__ import annotations

import subprocess
import sys
import time
from collections.abc import Generator

import psutil

from .base import FixerBase


class ServiceFixer(FixerBase):
    fixer_id = "service_fixer"

    def can_fix(self, issue: dict) -> bool:
        return issue.get("fixer_id") == self.fixer_id

    def fix(self, issue: dict) -> Generator[str, None, None]:
        params = issue.get("fix_params", {})
        action = params.get("action", "diagnose_port")

        if action == "restart_nssm":
            yield from self._restart_nssm(params)
        elif action == "diagnose_port":
            yield from self._diagnose_port(params)
        elif action == "kill_port":
            yield from self._kill_port(params)
        else:
            yield f"Unknown action: {action}"
            yield "DONE"

    def _restart_nssm(self, params: dict) -> Generator[str, None, None]:
        service_name = params.get("service_name", "")

        # Validate service_name against the config allowlist (services.allowed_service_names).
        # If the allowlist is absent or empty, any name is permitted (backward-compatible).
        from core import config as cfg
        allowed_names = cfg.get().get("services", {}).get("allowed_service_names", [])
        if allowed_names and service_name not in allowed_names:
            yield (
                f"FAILED: service_name '{service_name}' is not in the allowed list. "
                f"Add it to services.allowed_service_names in config.yaml."
            )
            return

        yield f"Attempting to restart NSSM service: {service_name}..."
        nssm_paths = [
            r"D:\tools\nssm\nssm.exe",
            r"C:\nssm\nssm.exe",
            "nssm",
        ]
        nssm = None
        for p in nssm_paths:
            try:
                subprocess.check_output([p, "version"], timeout=3, creationflags=0x08000000)
                nssm = p
                break
            except Exception:
                pass
        if not nssm:
            yield "NSSM not found. Trying sc.exe..."
            try:
                out = subprocess.check_output(
                    ["sc", "stop", service_name], text=True, timeout=10, creationflags=0x08000000
                )
                yield f"Stop: {out.strip()}"
                time.sleep(2)
                out = subprocess.check_output(
                    ["sc", "start", service_name], text=True, timeout=10, creationflags=0x08000000
                )
                yield f"Start: {out.strip()}"
                yield "DONE"
            except subprocess.CalledProcessError as e:
                yield f"FAILED: {e}"
            return
        try:
            out = subprocess.check_output(
                [nssm, "restart", service_name], text=True, timeout=15, creationflags=0x08000000
            )
            yield f"NSSM restart output: {out.strip()}"
            yield "DONE"
        except subprocess.CalledProcessError as e:
            yield f"FAILED: {e}"

    def _diagnose_port(self, params: dict) -> Generator[str, None, None]:
        port = params.get("port")
        if not port:
            yield "FAILED: no port specified"
            return
        port = int(port)
        yield f"Diagnosing port {port}..."
        pid = None
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == "LISTEN" and conn.laddr and conn.laddr.port == port:
                    pid = conn.pid
                    break
        except (psutil.AccessDenied, PermissionError):
            pass
        if pid:
            try:
                proc = psutil.Process(pid)
                yield f"Port {port} is held by: {proc.name()} (PID {pid})"
                yield f"  Command: {' '.join(proc.cmdline()[:5])}"
                yield f"  Memory: {proc.memory_info().rss / 1e6:.1f}MB"
                yield f"  Status: {proc.status()}"
            except Exception as e:
                yield f"Port {port} held by PID {pid} (can't read details: {e})"
        else:
            yield f"Port {port} is NOT listening — the service appears to be down"
            yield "Consider restarting the service that should be on this port"
        yield "DONE"

    def _kill_port(self, params: dict) -> Generator[str, None, None]:
        port = params.get("port")
        if not port:
            yield "FAILED: no port specified"
            return
        port = int(port)
        yield f"Finding process on port {port}..."
        pid = None
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == "LISTEN" and conn.laddr and conn.laddr.port == port:
                    pid = conn.pid
                    break
        except (psutil.AccessDenied, PermissionError):
            pass
        if not pid:
            yield f"No process found listening on port {port}"
            yield "DONE"
            return
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            yield f"Terminating {name} (PID {pid}) on port {port}..."
            proc.terminate()
            time.sleep(0.5)
            if proc.is_running():
                proc.kill()
                yield f"Force-killed {name} (PID {pid})"
            else:
                yield f"Terminated {name} (PID {pid})"
            yield "DONE"
        except psutil.AccessDenied:
            yield f"FAILED: Access denied for PID {pid}"
        except Exception as e:
            yield f"FAILED: {e}"


class StorageFixer(FixerBase):
    fixer_id = "storage_fixer"

    def can_fix(self, issue: dict) -> bool:
        return issue.get("fixer_id") == self.fixer_id

    def fix(self, issue: dict) -> Generator[str, None, None]:
        params = issue.get("fix_params", {})
        action = params.get("action", "find_large_files")

        if action == "find_large_files":
            yield from self._find_large_files(params)
        elif action == "scan_drive":
            yield from self._scan_drive(params)
        else:
            yield f"Unknown action: {action}"
            yield "DONE"

    def _find_large_files(self, params: dict) -> Generator[str, None, None]:
        drive = params.get("drive", "C")
        root = f"{drive}:\\"
        yield f"Scanning {root} for large files (>500MB)..."
        yield "This may take a moment..."
        found: list[tuple[int, str]] = []
        try:
            import os
            for dirpath, dirnames, filenames in os.walk(root):
                # Skip system dirs
                dirnames[:] = [d for d in dirnames if d not in (
                    "Windows", "System Volume Information", "$Recycle.Bin",
                    "Recovery", "ProgramData", "pagefile.sys"
                )]
                for fname in filenames:
                    try:
                        fpath = os.path.join(dirpath, fname)
                        size = os.path.getsize(fpath)
                        if size > 500 * 1024 * 1024:
                            found.append((size, fpath))
                    except (OSError, PermissionError):
                        pass
        except Exception as e:
            yield f"Scan error: {e}"
            yield "DONE"
            return

        found.sort(reverse=True)
        yield ""
        yield f"Found {len(found)} files > 500MB on {drive}:"
        for size, path in found[:20]:
            yield f"  {size/1e9:6.2f} GB  {path}"
        if not found:
            yield "  None found (or insufficient access)"
        yield "DONE"

    def _scan_drive(self, params: dict) -> Generator[str, None, None]:
        drive = params.get("drive", "D")
        yield f"Running diagnostics on drive {drive}:..."
        try:
            out = subprocess.check_output(
                ["wmic", "diskdrive", "get", "Status,Size,Model,InterfaceType", "/format:csv"],
                text=True, timeout=10, creationflags=0x08000000,
            )
            yield "WMIC disk status:"
            for line in out.strip().splitlines():
                if line.strip() and "," in line:
                    yield f"  {line.strip()}"
        except Exception as e:
            yield f"WMIC query failed: {e}"
        yield ""
        yield f"Recommendation: Run 'chkdsk {drive}: /f /r' in an admin terminal"
        yield "If drive is truly failing, back up data immediately"
        yield "DONE"
