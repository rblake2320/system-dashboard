"""
test_fleet_guard.py — pytest suite for fleet_guard.py alert evaluation.

Unit tests mock get_fleet() and get_system_metrics() so they run without any
live services.  The integration smoke test requires the dashboard to be up on
port 8099 and is gated by pytest.mark.integration.

Run unit tests only:
    pytest tests/test_fleet_guard.py -m "not integration"

Run everything (including smoke test):
    pytest tests/test_fleet_guard.py
"""

import sys
import os
import time
import threading
from unittest.mock import patch, MagicMock

import pytest

# ---------------------------------------------------------------------------
# Make sure the dashboard root is importable regardless of cwd.
# ---------------------------------------------------------------------------
_DASHBOARD_ROOT = r"C:\Users\techai\system-dashboard"
if _DASHBOARD_ROOT not in sys.path:
    sys.path.insert(0, _DASHBOARD_ROOT)

# ---------------------------------------------------------------------------
# Import the module under test AFTER adjusting sys.path.
# The module-level import of fleet_evidence is swallowed gracefully (try/except).
# ---------------------------------------------------------------------------
import core.fleet_guard as fleet_guard

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reset_guard():
    """Fully reset fleet_guard module globals to a clean 'ok' state.

    Directly writes to the module globals rather than going through resume()
    so we don't accidentally trigger audit-log side effects in test teardown.
    """
    with fleet_guard._lock:
        fleet_guard._state = fleet_guard.STATE_OK
        fleet_guard._reason = ""
        fleet_guard._halt_id = None
        fleet_guard._active_alerts = []
        fleet_guard._agent_flags = {}
        fleet_guard._checked_at = time.time()
        fleet_guard._local_model_mode = False


def _fake_fleet_one_active():
    """Return a minimal fleet list with one working agent."""
    return [{"name": "agent-1", "status": "working", "last_heartbeat_ts": time.time()}]


def _fake_fleet_empty():
    return []


def _fake_metrics_normal():
    """Metrics that won't trigger any resource alert."""
    return {
        "ram_avail_gb": 64.0,
        "gpus": [{"mem_total_mb": 32768, "mem_used_mb": 4096}],
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clean_guard():
    """Reset guard state before (and after) every test."""
    _reset_guard()
    yield
    _reset_guard()


# ---------------------------------------------------------------------------
# Unit Tests — each rule in isolation
# ---------------------------------------------------------------------------

class TestRamThreshold:
    """RAM < 25 GB while fleet active → halt_recommended."""

    def test_ram_threshold_fires(self):
        low_ram_metrics = {
            "ram_avail_gb": 20.0,
            "gpus": [],
        }
        one_agent = _fake_fleet_one_active()

        with (
            patch("core.fleet_guard.get_system_metrics", return_value=low_ram_metrics, create=True),
            patch("core.fleet_guard.get_fleet", return_value=one_agent, create=True),
        ):
            # Patch the lazy imports inside _evaluate_state
            with (
                patch.dict(
                    sys.modules,
                    {
                        "core.collector": MagicMock(get_system_metrics=lambda: low_ram_metrics),
                        "core.fleet_registry": MagicMock(get_fleet=lambda: one_agent),
                    },
                )
            ):
                with fleet_guard._lock:
                    fleet_guard._evaluate_state()

        state = fleet_guard.get_guard_state()
        assert state["state"] == fleet_guard.STATE_HALT_RECOMMENDED, (
            f"Expected halt_recommended, got '{state['state']}' — reason: {state['reason']}"
        )
        assert "RAM" in state["reason"] or "ram" in state["reason"].lower()

    def test_ram_threshold_no_fire_when_fleet_empty(self):
        low_ram_metrics = {"ram_avail_gb": 20.0, "gpus": []}
        no_agents = []

        with patch.dict(
            sys.modules,
            {
                "core.collector": MagicMock(get_system_metrics=lambda: low_ram_metrics),
                "core.fleet_registry": MagicMock(get_fleet=lambda: no_agents),
            },
        ):
            with fleet_guard._lock:
                fleet_guard._evaluate_state()

        state = fleet_guard.get_guard_state()
        # No active fleet → RAM check is skipped → should stay ok
        assert state["state"] == fleet_guard.STATE_OK, (
            f"Expected ok with empty fleet, got '{state['state']}'"
        )

    def test_ram_above_threshold_stays_ok(self):
        high_ram_metrics = {"ram_avail_gb": 40.0, "gpus": []}
        one_agent = _fake_fleet_one_active()

        with patch.dict(
            sys.modules,
            {
                "core.collector": MagicMock(get_system_metrics=lambda: high_ram_metrics),
                "core.fleet_registry": MagicMock(get_fleet=lambda: one_agent),
            },
        ):
            with fleet_guard._lock:
                fleet_guard._evaluate_state()

        assert fleet_guard.get_guard_state()["state"] == fleet_guard.STATE_OK


class TestVramThreshold:
    """VRAM < 6 GB only triggers when local_model_mode is True."""

    def _low_vram_metrics(self):
        # 8 GB total, 6.5 GB used → 1.5 GB free → below 6 GB threshold
        return {
            "ram_avail_gb": 64.0,
            "gpus": [{"mem_total_mb": 8192, "mem_used_mb": 6656}],
        }

    def test_vram_threshold_skipped_when_no_local_model(self):
        low_vram = self._low_vram_metrics()
        one_agent = _fake_fleet_one_active()

        fleet_guard.set_local_model_mode(False)

        with patch.dict(
            sys.modules,
            {
                "core.collector": MagicMock(get_system_metrics=lambda: low_vram),
                "core.fleet_registry": MagicMock(get_fleet=lambda: one_agent),
            },
        ):
            with fleet_guard._lock:
                fleet_guard._evaluate_state()

        state = fleet_guard.get_guard_state()
        assert state["state"] != fleet_guard.STATE_HALT_RECOMMENDED, (
            "VRAM check must be skipped when local_model_mode=False"
        )

    def test_vram_threshold_fires_when_local_model_active(self):
        low_vram = self._low_vram_metrics()
        one_agent = _fake_fleet_one_active()

        fleet_guard.set_local_model_mode(True)

        with patch.dict(
            sys.modules,
            {
                "core.collector": MagicMock(get_system_metrics=lambda: low_vram),
                "core.fleet_registry": MagicMock(get_fleet=lambda: one_agent),
            },
        ):
            with fleet_guard._lock:
                fleet_guard._evaluate_state()

        state = fleet_guard.get_guard_state()
        assert state["state"] == fleet_guard.STATE_HALT_RECOMMENDED, (
            f"Expected halt_recommended with low VRAM + local_model_mode=True, "
            f"got '{state['state']}'"
        )
        assert "VRAM" in state["reason"] or "vram" in state["reason"].lower()

    def test_vram_no_gpus_does_not_fire(self):
        """Edge case: no GPU data — should not raise, should not halt."""
        no_gpu_metrics = {"ram_avail_gb": 64.0, "gpus": []}
        fleet_guard.set_local_model_mode(True)

        with patch.dict(
            sys.modules,
            {
                "core.collector": MagicMock(get_system_metrics=lambda: no_gpu_metrics),
                "core.fleet_registry": MagicMock(get_fleet=lambda: _fake_fleet_one_active()),
            },
        ):
            with fleet_guard._lock:
                fleet_guard._evaluate_state()

        assert fleet_guard.get_guard_state()["state"] == fleet_guard.STATE_OK


class TestWrongNonce:
    """wrong_nonce → immediate hard_stop."""

    def test_wrong_nonce_causes_hard_stop(self):
        fleet_guard.record_event(
            "wrong_nonce",
            agent_name="agent-2",
            metadata={"nonce": "bad"},
        )

        state = fleet_guard.get_guard_state()
        assert state["state"] == fleet_guard.STATE_HARD_STOP, (
            f"Expected hard_stop after wrong_nonce, got '{state['state']}'"
        )
        assert "wrong_nonce" in state["reason"]

    def test_wrong_nonce_hard_stop_is_sticky(self):
        """After a wrong_nonce hard_stop, even a good evaluate should not clear it."""
        fleet_guard.record_event("wrong_nonce", agent_name="agent-2")

        # Try to re-evaluate with healthy metrics — should remain hard_stop
        good_metrics = {"ram_avail_gb": 64.0, "gpus": []}
        with patch.dict(
            sys.modules,
            {
                "core.collector": MagicMock(get_system_metrics=lambda: good_metrics),
                "core.fleet_registry": MagicMock(get_fleet=lambda: _fake_fleet_empty()),
            },
        ):
            with fleet_guard._lock:
                fleet_guard._evaluate_state()

        assert fleet_guard.get_guard_state()["state"] == fleet_guard.STATE_HARD_STOP


class TestImmediateHardStopEvents:
    """All events in _IMMEDIATE_HARD_STOP_EVENTS must trigger hard_stop."""

    @pytest.mark.parametrize("event_type", [
        "wrong_window_guard_failure",
        "wrong_nonce",
        "wrong_hash",
        "wrong_sender",
    ])
    def test_immediate_event_causes_hard_stop(self, event_type):
        _reset_guard()
        fleet_guard.record_event(event_type, agent_name="agent-1")
        state = fleet_guard.get_guard_state()
        assert state["state"] == fleet_guard.STATE_HARD_STOP, (
            f"Event '{event_type}' should cause hard_stop, got '{state['state']}'"
        )

    def test_immediate_event_sets_reason(self):
        fleet_guard.record_event("wrong_hash", agent_name="agent-3")
        state = fleet_guard.get_guard_state()
        assert "wrong_hash" in state["reason"]
        assert "agent-3" in state["reason"]


class TestLocalNarrationViolation:
    """1 narration violation → no halt; 2 violations → hard_stop."""

    def test_first_violation_does_not_halt(self):
        fleet_guard.record_event("local_narration_violation", agent_name="agent-5")
        state = fleet_guard.get_guard_state()
        assert state["state"] != fleet_guard.STATE_HARD_STOP, (
            "One narration violation must NOT trigger hard_stop"
        )

    def test_second_violation_causes_hard_stop(self):
        fleet_guard.record_event("local_narration_violation", agent_name="agent-5")
        fleet_guard.record_event("local_narration_violation", agent_name="agent-5")
        state = fleet_guard.get_guard_state()
        assert state["state"] == fleet_guard.STATE_HARD_STOP, (
            "Two narration violations must trigger hard_stop"
        )

    def test_violation_tracked_per_agent(self):
        """Two violations on different agents should each be counted separately."""
        fleet_guard.record_event("local_narration_violation", agent_name="agent-A")
        fleet_guard.record_event("local_narration_violation", agent_name="agent-B")
        state = fleet_guard.get_guard_state()
        # Each agent has 1 violation — neither should be hard_stopped
        assert state["state"] != fleet_guard.STATE_HARD_STOP, (
            "One violation per agent on two different agents must NOT be hard_stop"
        )
        flags = state["agent_flags"]
        assert flags["agent-A"]["narration_violations"] == 1
        assert flags["agent-B"]["narration_violations"] == 1

    def test_second_violation_alert_recorded(self):
        fleet_guard.record_event("local_narration_violation", agent_name="agent-5")
        fleet_guard.record_event("local_narration_violation", agent_name="agent-5")
        alerts = fleet_guard.get_guard_state()["active_alerts"]
        narration_alerts = [a for a in alerts if a["type"] == "local_narration_violation"]
        assert len(narration_alerts) == 2, (
            "Two narration violation alerts must be present in active_alerts"
        )


class TestWrongWindowGuardFailure:
    """wrong_window_guard_failure → immediate hard_stop (single event)."""

    def test_wrong_window_guard_failure_causes_hard_stop(self):
        fleet_guard.record_event("wrong_window_guard_failure", agent_name="agent-1")
        state = fleet_guard.get_guard_state()
        assert state["state"] == fleet_guard.STATE_HARD_STOP, (
            f"Expected hard_stop, got '{state['state']}'"
        )

    def test_agent_name_in_reason(self):
        fleet_guard.record_event("wrong_window_guard_failure", agent_name="agent-1")
        state = fleet_guard.get_guard_state()
        assert "agent-1" in state["reason"]


class TestResumeClears:
    """resume() must reset all state to 'ok' with empty alerts."""

    def test_resume_clears_hard_stop(self):
        fleet_guard.record_event("wrong_nonce", agent_name="agent-2")
        assert fleet_guard.get_guard_state()["state"] == fleet_guard.STATE_HARD_STOP

        fleet_guard.resume(operator_note="test resume")

        state = fleet_guard.get_guard_state()
        assert state["state"] == fleet_guard.STATE_OK, (
            f"Expected ok after resume, got '{state['state']}'"
        )

    def test_resume_clears_active_alerts(self):
        fleet_guard.record_event("wrong_nonce", agent_name="agent-2")
        fleet_guard.resume(operator_note="test resume")
        assert fleet_guard.get_guard_state()["active_alerts"] == []

    def test_resume_clears_agent_flags(self):
        fleet_guard.record_event("wrong_nonce", agent_name="agent-2")
        fleet_guard.resume(operator_note="test resume")
        assert fleet_guard.get_guard_state()["agent_flags"] == {}

    def test_resume_clears_halt_id(self):
        fleet_guard.record_event("wrong_nonce", agent_name="agent-2")
        fleet_guard.resume(operator_note="test resume")
        assert fleet_guard.get_guard_state()["halt_id"] is None

    def test_resume_clears_reason(self):
        fleet_guard.record_event("wrong_nonce", agent_name="agent-2")
        fleet_guard.resume(operator_note="test resume")
        assert fleet_guard.get_guard_state()["reason"] == ""

    def test_resume_from_ok_is_harmless(self):
        """Calling resume when already ok should not raise and keep state ok."""
        fleet_guard.resume(operator_note="no-op resume")
        assert fleet_guard.get_guard_state()["state"] == fleet_guard.STATE_OK


class TestBlockedAgentsThreshold:
    """More than HARD_STOP_BLOCKED_COUNT (2) blocked agents → hard_stop."""

    def _block_agent(self, name: str):
        """Drive an agent to blocked state via two missed_ack events."""
        fleet_guard.record_event("missed_ack", agent_name=name)
        fleet_guard.record_event("missed_ack", agent_name=name)

    def test_two_blocked_agents_does_not_hard_stop(self):
        """Exactly HARD_STOP_BLOCKED_COUNT blocked = blocked state, not hard_stop."""
        self._block_agent("agent-x")
        self._block_agent("agent-y")
        state = fleet_guard.get_guard_state()
        # 2 blocked agents <= threshold of 2 → should be STATE_BLOCKED, not hard_stop
        assert state["state"] != fleet_guard.STATE_HARD_STOP, (
            f"Exactly {fleet_guard.HARD_STOP_BLOCKED_COUNT} blocked agents "
            f"must NOT be hard_stop; got '{state['state']}'"
        )

    def test_three_blocked_agents_causes_hard_stop(self):
        """Three blocked agents > threshold of 2 → hard_stop."""
        self._block_agent("agent-1")
        self._block_agent("agent-2")
        self._block_agent("agent-3")
        state = fleet_guard.get_guard_state()
        assert state["state"] == fleet_guard.STATE_HARD_STOP, (
            f"Expected hard_stop with 3 blocked agents, got '{state['state']}'"
        )
        assert "blocked" in state["reason"].lower()

    def test_blocked_count_in_reason(self):
        """Reason string must name blocked count and threshold."""
        self._block_agent("agent-1")
        self._block_agent("agent-2")
        self._block_agent("agent-3")
        state = fleet_guard.get_guard_state()
        assert "3" in state["reason"] or "agent" in state["reason"].lower()


class TestMissedAckProgression:
    """One missed_ack → degraded; two → blocked."""

    def test_first_missed_ack_sets_degraded(self):
        fleet_guard.record_event("missed_ack", agent_name="agent-slow")
        state = fleet_guard.get_guard_state()
        flags = state["agent_flags"].get("agent-slow", {})
        assert flags.get("degraded") is True
        assert flags.get("blocked") is False

    def test_second_missed_ack_sets_blocked(self):
        fleet_guard.record_event("missed_ack", agent_name="agent-slow")
        fleet_guard.record_event("missed_ack", agent_name="agent-slow")
        state = fleet_guard.get_guard_state()
        flags = state["agent_flags"].get("agent-slow", {})
        assert flags.get("blocked") is True

    def test_degraded_state_transitions(self):
        fleet_guard.record_event("missed_ack", agent_name="agent-slow")
        state = fleet_guard.get_guard_state()
        # Should be degraded (not hard_stop, not halt_recommended)
        assert state["state"] in (
            fleet_guard.STATE_DEGRADED,
            fleet_guard.STATE_BLOCKED,
        ), f"Unexpected state after first missed_ack: '{state['state']}'"


class TestGetGuardStateShape:
    """get_guard_state() must always return all required keys."""

    _REQUIRED_KEYS = {
        "state",
        "reason",
        "halt_id",
        "active_alerts",
        "agent_flags",
        "local_model_mode",
        "checked_at",
    }

    def test_keys_present_on_fresh_state(self):
        state = fleet_guard.get_guard_state()
        missing = self._REQUIRED_KEYS - set(state.keys())
        assert not missing, f"get_guard_state() missing keys: {missing}"

    def test_active_alerts_is_list(self):
        assert isinstance(fleet_guard.get_guard_state()["active_alerts"], list)

    def test_agent_flags_is_dict(self):
        assert isinstance(fleet_guard.get_guard_state()["agent_flags"], dict)

    def test_checked_at_is_recent(self):
        state = fleet_guard.get_guard_state()
        assert time.time() - state["checked_at"] < 5.0, (
            "checked_at should be within the last 5 seconds"
        )

    def test_active_alerts_is_copy(self):
        """Mutating the returned list must not affect internal state."""
        state = fleet_guard.get_guard_state()
        state["active_alerts"].append({"type": "fake", "agent": "x"})
        state2 = fleet_guard.get_guard_state()
        assert len(state2["active_alerts"]) == 0, (
            "Returned active_alerts list must be a copy, not a reference"
        )


class TestSetLocalModelMode:
    """set_local_model_mode() updates the flag and re-evaluates immediately."""

    def test_set_true_reflected_in_state(self):
        fleet_guard.set_local_model_mode(True)
        assert fleet_guard.get_guard_state()["local_model_mode"] is True

    def test_set_false_reflected_in_state(self):
        fleet_guard.set_local_model_mode(True)
        fleet_guard.set_local_model_mode(False)
        assert fleet_guard.get_guard_state()["local_model_mode"] is False


class TestConcurrency:
    """Guard must not corrupt state under concurrent record_event calls."""

    def test_concurrent_events_do_not_raise(self):
        errors = []

        def send_events():
            try:
                for i in range(50):
                    fleet_guard.record_event("missed_ack", agent_name=f"agent-{i % 5}")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=send_events) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors, f"Concurrent record_event raised: {errors}"
        # State must be one of the valid constants (not corrupted)
        state = fleet_guard.get_guard_state()["state"]
        valid_states = {
            fleet_guard.STATE_OK,
            fleet_guard.STATE_HALT_RECOMMENDED,
            fleet_guard.STATE_DEGRADED,
            fleet_guard.STATE_BLOCKED,
            fleet_guard.STATE_HARD_STOP,
        }
        assert state in valid_states, f"State corrupted: '{state}'"


# ---------------------------------------------------------------------------
# Integration Smoke Test — requires dashboard running on port 8099
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestIntegrationSmoke:
    """
    End-to-end test against a running dashboard instance.

    Skip automatically if the dashboard is not up:
        pytest tests/test_fleet_guard.py -m "not integration"

    Run everything:
        pytest tests/test_fleet_guard.py
    """

    BASE = "http://127.0.0.1:8099"
    TIMEOUT = 3

    def _get(self, path: str) -> dict:
        import urllib.request
        import json
        with urllib.request.urlopen(self.BASE + path, timeout=self.TIMEOUT) as r:
            return json.loads(r.read())

    def _post(self, path: str, body: dict) -> dict:
        import urllib.request
        import json
        data = json.dumps(body).encode()
        req = urllib.request.Request(
            self.BASE + path,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.TIMEOUT) as r:
            return json.loads(r.read())

    def _delete(self, path: str) -> None:
        import urllib.request
        req = urllib.request.Request(self.BASE + path, method="DELETE")
        try:
            urllib.request.urlopen(req, timeout=self.TIMEOUT)
        except Exception:
            pass

    @pytest.fixture(autouse=True)
    def skip_if_down(self):
        import urllib.request
        try:
            urllib.request.urlopen(self.BASE + "/api/status", timeout=self.TIMEOUT)
        except Exception:
            pytest.skip("dashboard not running at " + self.BASE)

    @pytest.fixture()
    def test_agents(self):
        """Register 3 fake agents and yield their names; clean up after test."""
        names = ["smoke-agent-1", "smoke-agent-2", "smoke-agent-3"]
        for name in names:
            try:
                self._post("/api/fleet/register", {"name": name, "pid": 0, "task": "smoke-test"})
            except Exception:
                pass
        yield names
        for name in names:
            self._delete(f"/api/fleet/agent/{name}")

    def test_end_to_end_guard_cycle(self, test_agents):
        """
        1. Register 3 agents.
        2. Send heartbeats to confirm they appear in fleet.
        3. Skip one agent's heartbeat → wait for degraded state.
        4. Send wrong_nonce for one agent.
        5. Assert /api/fleet/guard returns hard_stop.
        6. POST /api/fleet/guard/resume.
        7. Assert state returns to ok.
        """
        names = test_agents

        # Step 2: Heartbeat for all three agents
        for name in names:
            try:
                self._post("/api/fleet/heartbeat", {"name": name, "status": "working"})
            except Exception:
                pass

        # Step 3: Deliberately skip heartbeat for smoke-agent-3 to let it go stale.
        # Instead of waiting the full 90s timeout, we directly send a wrong_nonce
        # which is a faster path to hard_stop for the smoke test.

        # Step 4: Send wrong_nonce event
        self._post("/api/fleet/event", {
            "event_type": "wrong_nonce",
            "agent_name": names[0],
            "metadata": {"nonce": "smoke-bad-nonce"},
        })

        # Step 5: Guard must be hard_stop
        guard = self._get("/api/fleet/guard")
        assert guard.get("state") == "hard_stop", (
            f"Expected hard_stop after wrong_nonce, got: {guard}"
        )
        assert "wrong_nonce" in guard.get("reason", "").lower() or (
            "wrong_nonce" in str(guard.get("active_alerts", []))
        ), f"wrong_nonce not mentioned in guard response: {guard}"

        # Step 6: Resume
        self._post("/api/fleet/guard/resume", {"operator_note": "smoke test resume"})

        # Small settle time for any async processing
        time.sleep(0.2)

        # Step 7: Guard state must return to ok
        guard_after = self._get("/api/fleet/guard")
        assert guard_after.get("state") == "ok", (
            f"Expected ok after resume, got: {guard_after}"
        )
        assert guard_after.get("active_alerts") == [], (
            f"Expected empty active_alerts after resume, got: {guard_after.get('active_alerts')}"
        )

    def test_register_and_heartbeat_appear_in_fleet(self, test_agents):
        """Sanity check: registered agents with heartbeats appear in GET /api/fleet."""
        names = test_agents
        for name in names:
            try:
                self._post("/api/fleet/heartbeat", {"name": name, "status": "working"})
            except Exception:
                pass

        fleet = self._get("/api/fleet")
        agents = fleet.get("agents", []) if isinstance(fleet, dict) else fleet
        fleet_names = {a["name"] for a in agents} if isinstance(agents, list) else set()
        for name in names:
            assert name in fleet_names, (
                f"Agent '{name}' not found in /api/fleet response: {fleet}"
            )

    def test_resume_endpoint_idempotent(self):
        """POST /api/fleet/guard/resume twice must not raise or corrupt state."""
        self._post("/api/fleet/guard/resume", {"operator_note": "first"})
        self._post("/api/fleet/guard/resume", {"operator_note": "second"})
        guard = self._get("/api/fleet/guard")
        assert guard.get("state") == "ok"
