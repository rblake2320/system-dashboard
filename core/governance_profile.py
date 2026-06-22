"""Governance profile selection for Normal / Enterprise / Government modes."""
from __future__ import annotations

from typing import Any

PROFILES = ("normal", "enterprise", "government")

# Runtime session override — set by /api/governance/enable without touching config.yaml.
# Resets to None on process restart (session-scoped by design).
_session_profile: str | None = None


def normalize_profile(value: Any) -> str:
    profile = str(value or "normal").strip().lower()
    return profile if profile in PROFILES else "normal"


def get_profile() -> str:
    if _session_profile is not None:
        return _session_profile
    from core import config as cfg
    gov = cfg.get().get("governance", {})
    return normalize_profile(gov.get("profile", "normal"))


def set_session_profile(profile: str) -> str:
    """Set a runtime profile override (session-scoped, resets on restart)."""
    global _session_profile
    _session_profile = normalize_profile(profile)
    return _session_profile


def governance_enabled(profile: str | None = None) -> bool:
    return normalize_profile(profile or get_profile()) in ("enterprise", "government")


def government_enabled(profile: str | None = None) -> bool:
    return normalize_profile(profile or get_profile()) == "government"


def summary(profile: str | None = None) -> dict[str, Any]:
    resolved = normalize_profile(profile or get_profile())
    return {
        "profile": resolved,
        "enabled": governance_enabled(resolved),
        "government": government_enabled(resolved),
        "visible_panels": {
            "bpc_tsk": governance_enabled(resolved),
            "government_gates": government_enabled(resolved),
        },
    }
