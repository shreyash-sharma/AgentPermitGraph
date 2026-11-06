"""Deterministic action tiers used as policy metadata and a ceiling gate.

The tiers are ordinal policy categories, not a calibrated probability or a
weighted scientific risk score. Exact resource, parameter, and count checks
remain independent requirements.
"""
from __future__ import annotations

from typing import Any

BASE_ACTION_TIERS = {
    "read_ticket": 0,
    "send_email": 1,
    "read_secret": 3,
    "delete_ticket": 4,
}

AUTHORITY_TIER_CEILINGS = {"broad": 4, "coarse": 2, "task_scoped": 2}


def blast_radius_tier(tool_name: str, arguments: dict[str, Any] | None = None) -> int:
    """Classify a known synthetic action using a small, explicit registry."""
    tier = BASE_ACTION_TIERS[tool_name]
    arguments = arguments or {}
    if tool_name == "send_email" and arguments.get("to") and arguments.get("to") != "support@example.test":
        return 2
    return tier
