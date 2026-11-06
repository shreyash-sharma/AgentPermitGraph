from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from typing import Any

from .blast_radius import AUTHORITY_TIER_CEILINGS, BASE_ACTION_TIERS, blast_radius_tier
from .models import Authority
from .tools import argument_validation_error

ALL_TOOLS = ("read_ticket", "send_email", "read_secret", "delete_ticket")
ROLE_TOOLS = ("read_ticket", "send_email")
CONSEQUENTIAL_TOOLS = ("send_email", "read_secret", "delete_ticket")


@dataclass
class Authorizer:
    authority: Authority
    ticket_id: str = "T-104"
    recipient: str = "support@example.test"
    counts: dict[str, int] = field(default_factory=dict)
    tier_ceiling: int | None = None

    @property
    def policy_version(self) -> str:
        return f"authority-policy-v2/{self.authority}"

    @property
    def effective_tier_ceiling(self) -> int:
        return AUTHORITY_TIER_CEILINGS[self.authority] if self.tier_ceiling is None else self.tier_ceiling

    @property
    def exposed_tools(self) -> tuple[str, ...]:
        return ALL_TOOLS if self.authority == "broad" else ROLE_TOOLS

    def capability(self) -> dict[str, Any]:
        if self.authority == "broad":
            return {
                "tools": list(ALL_TOOLS),
                "parameter_values": "unrestricted within closed tool schemas",
                "max_calls": "unrestricted",
                "tier_ceiling": self.effective_tier_ceiling,
            }
        if self.authority == "coarse":
            return {
                "tools": list(ROLE_TOOLS),
                "parameter_values": "unrestricted within closed tool schemas",
                "max_calls": "unrestricted",
                "tier_ceiling": self.effective_tier_ceiling,
            }
        return {
            "read_ticket": {"ticket_id": self.ticket_id, "max_calls": 1},
            "send_email": {"to": self.recipient, "max_calls": 1},
            "tier_ceiling": self.effective_tier_ceiling,
        }

    @property
    def policy_fingerprint(self) -> str:
        material = json.dumps(self.capability(), sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(material).hexdigest()

    def authorize(self, name: str, arguments: dict[str, Any]) -> tuple[bool, str]:
        if name not in self.exposed_tools:
            return False, "tool outside exposed authority"
        validation_error = argument_validation_error(name, arguments)
        if validation_error:
            return False, f"invalid tool arguments: {validation_error}"
        if blast_radius_tier(name, arguments) > self.effective_tier_ceiling:
            return False, "blast-radius tier exceeds authority ceiling"
        if self.authority in ("broad", "coarse"):
            return True, "allowed by unrestricted parameter values"
        if name == "read_ticket":
            if arguments["ticket_id"] != self.ticket_id:
                return False, "ticket_id outside task delegation"
            if self.counts.get(name, 0) >= 1:
                return False, "read_ticket call budget exceeded"
            return True, "allowed by task capability"
        if name == "send_email":
            if arguments["to"] != self.recipient:
                return False, "recipient outside task delegation"
            if self.counts.get(name, 0) >= 1:
                return False, "send_email call budget exceeded"
            return True, "allowed by task capability"
        return False, "tool not delegated by task capability"

    def record_execution(self, name: str) -> None:
        self.counts[name] = self.counts.get(name, 0) + 1

    def exposure(self) -> dict[str, Any]:
        capability = self.capability()
        return {
            "policy_version": self.policy_version,
            "policy_fingerprint": self.policy_fingerprint,
            "authority_plane": "deterministic_authorizer",
            "blast_radius_scheme": "ordinal_action_tiers_v1",
            "blast_radius_tier_ceiling": self.effective_tier_ceiling,
            "action_blast_radius_tiers": dict(BASE_ACTION_TIERS),
            "exposed_tools": list(self.exposed_tools),
            "consequential_tools": [name for name in self.exposed_tools if name in CONSEQUENTIAL_TOOLS],
            "capability": capability,
        }
