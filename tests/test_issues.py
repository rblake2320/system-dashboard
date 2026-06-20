"""Tests for core.issues — detection, registry, and Issue dataclass."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.issues import Issue, IssueRegistry, detect_issues, _make_id, CRITICAL_HYSTERESIS, RESOLVE_HYSTERESIS


# ── Helpers ───────────────────────────────────────────────────────────────────

def _base_snapshot(**overrides) -> dict:
    """Minimal snapshot that produces no issues by default."""
    snap = {
        "system": {
            "cpu_pct": 0,
            "ram_pct": 0,
            "ram_avail_gb": 100,
            "drives": {},
            "gpus": [],
        },
        "processes": {},
        "ports": {},
    }
    snap["system"].update(overrides)
    return snap


# ── detect_issues: CPU critical ───────────────────────────────────────────────

def test_detect_cpu_critical():
    snap = _base_snapshot(cpu_pct=95)
    issues = detect_issues(snap)
    critical = [i for i in issues if i.severity == "critical" and i.category == "system"]
    assert critical, "Expected a critical issue for 95% CPU"
    titles = [i.title for i in critical]
    assert any("CPU" in t for t in titles), f"No CPU issue title found in {titles}"


def test_detect_cpu_critical_fixer_id():
    snap = _base_snapshot(cpu_pct=95)
    issues = detect_issues(snap)
    cpu_issues = [i for i in issues if "CPU" in i.title and i.severity == "critical"]
    assert cpu_issues, "Expected critical CPU issue"
    assert cpu_issues[0].fixer_id == "process_fixer"


# ── detect_issues: failing drive ─────────────────────────────────────────────

def test_detect_failing_drive_critical():
    snap = _base_snapshot()
    snap["system"]["drives"] = {
        "D": {
            "total_gb": 500,
            "used_gb": 400,
            "free_gb": 100,
            "pct": 80,
            "failing": True,
            "warn": True,
        }
    }
    issues = detect_issues(snap)
    storage = [i for i in issues if i.category == "storage" and i.severity == "critical"]
    assert storage, "Expected critical storage issue for failing drive"


def test_detect_failing_drive_fixer_id():
    snap = _base_snapshot()
    snap["system"]["drives"] = {
        "D": {
            "total_gb": 500,
            "used_gb": 400,
            "free_gb": 100,
            "pct": 80,
            "failing": True,
            "warn": True,
        }
    }
    issues = detect_issues(snap)
    storage = [i for i in issues if i.category == "storage" and i.severity == "critical"]
    assert storage, "Expected critical storage issue"
    assert storage[0].fixer_id == "storage_fixer"


# ── detect_issues: drive total_gb==0 is skipped ───────────────────────────────

def test_detect_zero_total_drive_skipped():
    snap = _base_snapshot()
    snap["system"]["drives"] = {
        "Z": {"total_gb": 0, "used_gb": 0, "free_gb": 0, "pct": 0,
              "failing": True, "warn": True}
    }
    issues = detect_issues(snap)
    storage = [i for i in issues if i.category == "storage"]
    assert storage == [], "Drive with total_gb=0 must be skipped even if flagged failing"


# ── Helpers: push an issue through hysteresis so it becomes active ────────────

def _activate(reg: IssueRegistry, issue: Issue) -> None:
    """Call update() CRITICAL_HYSTERESIS times so the issue becomes active."""
    for _ in range(CRITICAL_HYSTERESIS):
        reg.update([issue])


def _resolve(reg: IssueRegistry, issue: Issue) -> None:
    """Call update([]) RESOLVE_HYSTERESIS times so the issue is resolved."""
    for _ in range(RESOLVE_HYSTERESIS):
        reg.update([])


# ── IssueRegistry.update ─────────────────────────────────────────────────────

def test_registry_update_adds_issues():
    reg = IssueRegistry()
    issue = Issue(
        id="test001",
        severity="critical",
        category="system",
        title="Test issue",
        description="A test issue.",
    )
    _activate(reg, issue)
    active = reg.get_active()
    assert any(i.id == "test001" for i in active)


def test_registry_update_resolves_missing():
    reg = IssueRegistry()
    issue = Issue(
        id="test002",
        severity="warning",
        category="system",
        title="Temp issue",
        description="Will be resolved.",
    )
    _activate(reg, issue)
    assert len(reg.get_active()) == 1

    # Update with empty list enough times → issue should be resolved
    _resolve(reg, issue)
    active = reg.get_active()
    assert not any(i.id == "test002" for i in active), "Issue should be resolved after empty updates"


def test_registry_update_resolved_flag():
    reg = IssueRegistry()
    issue = Issue(id="test003", severity="info", category="system",
                  title="X", description="X")
    _activate(reg, issue)
    _resolve(reg, issue)
    all_issues = reg.get_all()
    found = next(i for i in all_issues if i.id == "test003")
    assert found.resolved is True


# ── IssueRegistry deduplication ──────────────────────────────────────────────

def test_registry_deduplication():
    reg = IssueRegistry()
    issue_a = Issue(id="dup01", severity="critical", category="system",
                    title="First", description="First version")
    issue_b = Issue(id="dup01", severity="critical", category="system",
                    title="Updated", description="Second version")

    # Fire enough times to cross hysteresis, then update again
    _activate(reg, issue_a)
    reg.update([issue_b])

    all_issues = reg.get_all()
    with_id = [i for i in all_issues if i.id == "dup01"]
    assert len(with_id) == 1, f"Expected 1 entry for dup01, got {len(with_id)}"


def test_registry_deduplication_updates_title():
    reg = IssueRegistry()
    issue_a = Issue(id="dup02", severity="critical", category="system",
                    title="Old Title", description="d")
    _activate(reg, issue_a)
    # Now send an update with the new title
    issue_b = Issue(id="dup02", severity="critical", category="system",
                    title="New Title", description="d")
    reg.update([issue_b])
    issue = reg.get("dup02")
    assert issue is not None
    assert issue.title == "New Title"


# ── Issue.as_dict ─────────────────────────────────────────────────────────────

def test_issue_as_dict_keys():
    issue = Issue(
        id="ser001",
        severity="warning",
        category="storage",
        title="Low space",
        description="Drive C is almost full.",
        fixer_id="storage_fixer",
        fix_params={"action": "find_large_files", "drive": "C"},
        context={"drive": "C"},
    )
    d = issue.as_dict()
    # Include all keys returned by the actual implementation
    expected_keys = {"id", "severity", "category", "title", "description",
                     "fixer_id", "fix_params", "context", "detected_at", "resolved",
                     "state"}
    # Allow the implementation to add extra keys without breaking this test
    assert expected_keys.issubset(set(d.keys())), \
        f"Missing keys: {expected_keys - set(d.keys())}"


def test_issue_as_dict_values():
    issue = Issue(
        id="ser002",
        severity="critical",
        category="process",
        title="High CPU",
        description="CPU at 99%.",
        fixer_id="process_fixer",
        fix_params={"action": "list_top_cpu"},
    )
    d = issue.as_dict()
    assert d["id"] == "ser002"
    assert d["severity"] == "critical"
    assert d["category"] == "process"
    assert d["fixer_id"] == "process_fixer"
    assert d["fix_params"] == {"action": "list_top_cpu"}
    assert d["resolved"] is False


# ── IssueRegistry state transitions: acknowledge ──────────────────────────────

def test_registry_acknowledge_sets_state():
    reg = IssueRegistry()
    issue = Issue(id="ack001", severity="warning", category="system",
                  title="Ack test", description="Testing acknowledge.")
    _activate(reg, issue)
    reg.acknowledge("ack001")
    found = reg.get("ack001")
    assert found is not None
    assert found.state == "acknowledged", f"Expected 'acknowledged', got '{found.state}'"


def test_registry_acknowledge_keeps_issue_active():
    """Acknowledged issues should not appear as resolved."""
    reg = IssueRegistry()
    issue = Issue(id="ack002", severity="warning", category="system",
                  title="Ack2", description="Ack keeps issue alive.")
    _activate(reg, issue)
    reg.acknowledge("ack002")
    found = reg.get("ack002")
    assert found is not None
    assert found.resolved is False


# ── IssueRegistry state transitions: suppress ────────────────────────────────

def test_registry_suppress_hides_from_get_active():
    """Suppressed issues must not appear in get_active()."""
    reg = IssueRegistry()
    issue = Issue(id="sup001", severity="critical", category="system",
                  title="Suppress test", description="Testing suppress.")
    _activate(reg, issue)
    # Suppress for 1 hour into the future
    import time as _time
    reg.suppress("sup001", until_ts=_time.time() + 3600)
    active = reg.get_active()
    assert not any(i.id == "sup001" for i in active), \
        "Suppressed issue should not appear in get_active()"


def test_registry_suppress_expired_auto_lifts():
    """A suppression with an already-expired timestamp must auto-lift on next get_active()."""
    import time as _time
    reg = IssueRegistry()
    issue = Issue(id="sup002", severity="critical", category="system",
                  title="Expired suppress", description="Testing expired suppress.")
    _activate(reg, issue)
    # Suppress with a timestamp in the past
    reg.suppress("sup002", until_ts=_time.time() - 1)
    active = reg.get_active()
    assert any(i.id == "sup002" for i in active), \
        "Issue with expired suppression should auto-lift and appear in get_active()"


def test_registry_suppress_sets_state():
    """suppress() must set state to 'suppressed'."""
    reg = IssueRegistry()
    issue = Issue(id="sup003", severity="info", category="system",
                  title="S3", description="d")
    _activate(reg, issue)
    import time as _time
    reg.suppress("sup003", until_ts=_time.time() + 60)
    found = reg.get("sup003")
    assert found is not None
    assert found.state == "suppressed"


# ── IssueRegistry state transitions: mark_fixing ─────────────────────────────

def test_registry_mark_fixing_sets_state():
    reg = IssueRegistry()
    issue = Issue(id="fix001", severity="critical", category="system",
                  title="Fix test", description="Testing mark_fixing.")
    _activate(reg, issue)
    reg.mark_fixing("fix001")
    found = reg.get("fix001")
    assert found is not None
    assert found.state == "fixing", f"Expected 'fixing', got '{found.state}'"


def test_registry_mark_fixing_not_resolved():
    """mark_fixing must not mark the issue as resolved."""
    reg = IssueRegistry()
    issue = Issue(id="fix002", severity="warning", category="system",
                  title="Fix2", description="d")
    _activate(reg, issue)
    reg.mark_fixing("fix002")
    found = reg.get("fix002")
    assert found is not None
    assert found.resolved is False


# ── IssueRegistry: resolve() directly ────────────────────────────────────────

def test_registry_resolve_direct_marks_resolved():
    reg = IssueRegistry()
    issue = Issue(id="res001", severity="warning", category="system",
                  title="Resolve direct", description="d")
    _activate(reg, issue)
    reg.resolve("res001")
    found = reg.get("res001")
    assert found is not None
    assert found.resolved is True
    assert found.state == "resolved"


def test_registry_resolve_direct_not_in_active():
    reg = IssueRegistry()
    issue = Issue(id="res002", severity="critical", category="system",
                  title="Resolve2", description="d")
    _activate(reg, issue)
    reg.resolve("res002")
    active = reg.get_active()
    assert not any(i.id == "res002" for i in active)
