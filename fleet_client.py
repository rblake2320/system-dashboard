"""
AI Agent Fleet Client for System Dashboard

Usage examples:

  # Context manager (auto-reports done on exit, error if exception):
  with FleetClient("billing-agent", "process Q2 invoices") as fleet:
      fleet.heartbeat(progress=25, note="reading invoices")
      do_work()
      fleet.heartbeat(progress=75, note="writing output")

  # One-liner with auto-heartbeat:
  fc = fleet_register("data-agent", "scrape prices")
  try:
      for i, item in enumerate(items):
          fc.heartbeat(progress=int(i/len(items)*100), note=item)
          process(item)
      fc.done("success")
  except Exception as e:
      fc.done(f"error: {e}")

  # Manual (no auto-heartbeat):
  fc = FleetClient("search-agent", "index documents", auto_heartbeat=False)
  fc.register()
  fc.heartbeat(status="working", progress=50)
  fc.done()
"""

import json
import os
import threading
import urllib.error
import urllib.request
from typing import Optional


class FleetClient:
    """Client for reporting agent status to the System Dashboard fleet endpoint."""

    def __init__(
        self,
        name: str,
        task: str,
        dashboard_url: str = "http://127.0.0.1:8099",
        auto_heartbeat: bool = True,
        pid: Optional[int] = None,
    ) -> None:
        self.name = name
        self.task = task
        self.dashboard_url = dashboard_url.rstrip("/")
        self.auto_heartbeat = auto_heartbeat
        self.pid = pid if pid is not None else os.getpid()

        self._stop_event = threading.Event()
        self._heartbeat_thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _post(self, path: str, payload: dict) -> bool:
        """POST JSON payload to dashboard_url + path. Returns True on HTTP 2xx."""
        url = f"{self.dashboard_url}{path}"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return 200 <= resp.status < 300
        except Exception:
            return False

    def _heartbeat_loop(self) -> None:
        """Background thread: send a heartbeat every 30 seconds until stopped."""
        while not self._stop_event.wait(30):
            self.heartbeat()

    def _start_heartbeat_thread(self) -> None:
        if self._heartbeat_thread is not None and self._heartbeat_thread.is_alive():
            return
        self._stop_event.clear()
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            name=f"fleet-heartbeat-{self.name}",
            daemon=True,
        )
        self._heartbeat_thread.start()

    def _stop_heartbeat_thread(self) -> None:
        self._stop_event.set()
        if self._heartbeat_thread is not None:
            self._heartbeat_thread.join(timeout=2)
            self._heartbeat_thread = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register(self) -> bool:
        """
        Register this agent with the dashboard.

        POSTs to /api/fleet/register with name, pid, and task.
        If auto_heartbeat is enabled, starts the background heartbeat thread.
        Returns True on success, False on any network error.
        """
        payload = {
            "name": self.name,
            "pid": self.pid,
            "task": self.task,
        }
        ok = self._post("/api/fleet/register", payload)
        if ok and self.auto_heartbeat:
            self._start_heartbeat_thread()
        return ok

    def heartbeat(
        self,
        status: str = "working",
        progress: int = 0,
        note: str = "",
    ) -> bool:
        """
        Send a heartbeat to the dashboard.

        Parameters
        ----------
        status:   short status string, e.g. "working", "idle", "waiting"
        progress: integer 0-100 representing percent completion
        note:     free-form string visible in the dashboard UI

        Returns True on success, False on any network error.
        """
        payload = {
            "name": self.name,
            "pid": self.pid,
            "status": status,
            "progress": progress,
            "note": note,
        }
        return self._post("/api/fleet/heartbeat", payload)

    def done(self, result: str = "success") -> bool:
        """
        Report completion to the dashboard and stop the heartbeat thread.

        Parameters
        ----------
        result: outcome string, e.g. "success", "error", "error: <msg>"

        Returns True on success, False on any network error.
        """
        self._stop_heartbeat_thread()
        payload = {
            "name": self.name,
            "pid": self.pid,
            "result": result,
        }
        return self._post("/api/fleet/done", payload)

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "FleetClient":
        self.register()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        result = "error" if exc_type is not None else "success"
        self.done(result)
        # Do not suppress exceptions
        return False


# ---------------------------------------------------------------------------
# Module-level convenience function
# ---------------------------------------------------------------------------


def fleet_register(
    name: str,
    task: str,
    dashboard_url: str = "http://127.0.0.1:8099",
) -> FleetClient:
    """
    Create a FleetClient, register it with the dashboard, and return it.

    This is the recommended one-liner for agents that manage their own lifecycle.

    Example
    -------
    fc = fleet_register("my-agent", "doing important work")
    try:
        fc.heartbeat(progress=50, note="halfway")
        do_work()
        fc.done("success")
    except Exception as e:
        fc.done(f"error: {e}")
    """
    client = FleetClient(name=name, task=task, dashboard_url=dashboard_url)
    client.register()
    return client
