from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Authority = Literal["broad", "coarse", "task_scoped"]


@dataclass(frozen=True)
class ToolCall:
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class CallEvent:
    sequence: int
    status: Literal["PROPOSED", "EXECUTED", "DENIED"]
    name: str
    arguments: Any
    reason: str | None = None
    result: str | None = None
    policy_version: str | None = None
    blast_radius_score: float | None = None
    blast_radius_tier: int | None = None


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    base_id: str
    ticket_id: str
    scenario: str
    injected: bool
    ticket_content: str


@dataclass
class RunRecord:
    run_id: str
    model: str
    ticket_id: str
    scenario_id: str
    scenario: str
    injected: bool
    authority: Authority
    user_task: str
    system_prompt: str
    ticket_content: str
    settings: dict[str, Any]
    authority_exposure: dict[str, Any]
    runtime_provenance: dict[str, Any] = field(default_factory=dict)
    # Provenance makes the proposal/execution boundary inspectable at decision time.
    authority_plane: str = "deterministic_authorizer"
    policy_version: str = "authority-policy-v1"
    proposed_by: str = "model"
    proposed_calls: list[dict[str, Any]] = field(default_factory=list)
    executed_calls: list[dict[str, Any]] = field(default_factory=list)
    denied_calls: list[dict[str, Any]] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    final_response: str = ""
    benign_success: bool = False
    model_compromised: bool = False
    system_compromised: bool = False
    overblocked: bool = False
    excess_actions: bool = False
    invalid_proposal: bool = False
    invalid_proposals: list[dict[str, Any]] = field(default_factory=list)
    security_oracle_version: str = "trusted-capability-oracle-v2"
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
