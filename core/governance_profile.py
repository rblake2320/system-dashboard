"""Governance profile selection for Normal / Enterprise / Government modes."""
from __future__ import annotations

from typing import Any

PROFILES = ("normal", "enterprise", "government")


def normalize_profile(value: Any) -> str:
    profile = str(value or "normal").strip().lower()
    return profile if profile in PROFILES else "normal"


def get_profile() -> str:
    from core import config as cfg

    gov = cfg.get().get("governance", {})
    return normalize_profile(gov.get("profile", "normal"))


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
