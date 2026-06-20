"""Tests for fixers.process_fixer and fixers.service_fixer (StorageFixer)."""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from fixers.process_fixer import ProcessFixer
from fixers.service_fixer import StorageFixer


# ── Helpers ───────────────────────────────────────────────────────────────────

def _issue(fixer_id: str, action: str, **extra_params) -> dict:
    return {
        "fixer_id": fixer_id,
        "fix_params": {"action": action, **extra_params},
    }


def _collect(gen) -> list[str]:
    return list(gen)


# ── ProcessFixer.can_fix ──────────────────────────────────────────────────────

def test_process_fixer_can_fix_true():
    fixer = ProcessFixer()
    assert fixer.can_fix({"fixer_id": "process_fixer"}) is True


def test_process_fixer_can_fix_false_for_other():
    fixer = ProcessFixer()
    assert fixer.can_fix({"fixer_id": "storage_fixer"}) is False


def test_process_fixer_can_fix_false_when_missing():
    fixer = ProcessFixer()
    assert fixer.can_fix({}) is False


# ── ProcessFixer action: list_top_cpu ─────────────────────────────────────────

def test_process_fixer_list_top_cpu_yields_done():
    """list_top_cpu must eventually yield 'DONE'."""
    fixer = ProcessFixer()
    issue = _issue("process_fixer", "list_top_cpu")
    lines = _collect(fixer.fix(issue))
    assert "DONE" in lines, f"Expected 'DONE' in output, got: {lines}"


def test_process_fixer_list_top_cpu_yields_header():
    fixer = ProcessFixer()
    issue = _issue("process_fixer", "list_top_cpu")
    lines = _collect(fixer.fix(issue))
    combined = "\n".join(lines)
    assert "PID" in combined or "Collecting" in combined, \
        "Expected PID table header or collection message"


# ── ProcessFixer action: kill_by_name (non-existent process) ─────────────────

def test_process_fixer_kill_nonexistent_yields_no_instances():
    """Killing a non-existent process should say 'No running instances' and DONE."""
    fixer = ProcessFixer()
    # Use a name that will never match a real process
    issue = _issue("process_fixer", "kill_by_name", name="__nonexistent_proc_xyz__")
    lines = _collect(fixer.fix(issue))
    combined = "\n".join(lines)
    assert any("No running instances" in line or "Nothing to kill" in line
               for line in lines), \
        f"Expected 'No running instances' message. Got:\n{combined}"
    assert "DONE" in lines, "Expected DONE at the end"


def test_process_fixer_kill_nonexistent_does_not_raise():
    fixer = ProcessFixer()
    issue = _issue("process_fixer", "kill_by_name", name="__nonexistent_proc_xyz__")
    # Should not raise
    lines = _collect(fixer.fix(issue))
    assert lines  # non-empty output


# ── ProcessFixer unknown action ───────────────────────────────────────────────

def test_process_fixer_unknown_action_yields_done():
    fixer = ProcessFixer()
    issue = _issue("process_fixer", "totally_unknown_action_xyz")
    lines = _collect(fixer.fix(issue))
    assert "DONE" in lines


# ── StorageFixer.can_fix ──────────────────────────────────────────────────────

def test_storage_fixer_can_fix_true():
    fixer = StorageFixer()
    assert fixer.can_fix({"fixer_id": "storage_fixer"}) is True


def test_storage_fixer_can_fix_false():
    fixer = StorageFixer()
    assert fixer.can_fix({"fixer_id": "process_fixer"}) is False


def test_storage_fixer_can_fix_empty():
    fixer = StorageFixer()
    assert fixer.can_fix({}) is False


# ── StorageFixer: fixer_id attribute ─────────────────────────────────────────

def test_process_fixer_id_attribute():
    assert ProcessFixer.fixer_id == "process_fixer"


def test_storage_fixer_id_attribute():
    assert StorageFixer.fixer_id == "storage_fixer"


# ── StorageFixer unknown action ───────────────────────────────────────────────

def test_storage_fixer_unknown_action_yields_done():
    fixer = StorageFixer()
    issue = _issue("storage_fixer", "totally_unknown_action_xyz")
    lines = _collect(fixer.fix(issue))
    assert "DONE" in lines
