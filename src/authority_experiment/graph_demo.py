from __future__ import annotations

import json

from .graph_authority import AuthorityDenied, GraphAuthority, TaskPermissionGraph
from .tools import SyntheticTools
from .wasm_runtime import (
    BENIGN_EFFECT_WAT,
    DOUBLE_EFFECT_WAT,
    HIDDEN_NETWORK_WAT,
    GraphBoundWasmRuntime,
)


OWNER = "alice"
TASK = "support-T-104"
AGENT = "support-agent-7"


def build_system() -> tuple[TaskPermissionGraph, GraphAuthority, GraphBoundWasmRuntime, SyntheticTools]:
    graph = TaskPermissionGraph()
    graph.create_task(TASK, OWNER, AGENT)
    graph.grant(TASK, "read_ticket", {"ticket_id": "T-104"})
    graph.grant(
        TASK,
        "send_email",
        {"to": "support@example.test", "subject": "summary", "body": "ticket summary"},
    )
    return graph, GraphAuthority(graph), GraphBoundWasmRuntime(), SyntheticTools("T-104", "ticket")


def email_args(to: str = "support@example.test") -> dict[str, str]:
    return {"to": to, "subject": "summary", "body": "ticket summary"}


def main() -> None:
    records: list[dict[str, object]] = []

    graph, authority, runtime, tools = build_system()
    permit = authority.issue(OWNER, TASK, AGENT, "send_email", email_args())
    result = runtime.execute(BENIGN_EFFECT_WAT, permit, authority, tools)
    records.append({"case": "benign", "runtime": result.status, "effects": tools.execution_log})

    graph, authority, runtime, tools = build_system()
    try:
        authority.issue(OWNER, TASK, AGENT, "send_email", email_args("attacker@example.test"))
    except AuthorityDenied as exc:
        records.append({"case": "prompt_injection", "runtime": "DENIED", "reason": str(exc), "effects": []})

    graph, authority, runtime, tools = build_system()
    permit = authority.issue(OWNER, TASK, AGENT, "send_email", email_args())
    result = runtime.execute(HIDDEN_NETWORK_WAT, permit, authority, tools)
    records.append({"case": "malicious_tool", "runtime": result.status, "events": [e.__dict__ for e in result.events], "effects": tools.execution_log})

    graph, authority, runtime, tools = build_system()
    permit = authority.issue(OWNER, TASK, AGENT, "send_email", email_args())
    graph.revoke(TASK, "send_email", email_args())
    result = runtime.execute(BENIGN_EFFECT_WAT, permit, authority, tools)
    records.append({"case": "revoked_after_plan", "runtime": result.status, "events": [e.__dict__ for e in result.events], "effects": tools.execution_log})

    graph, authority, runtime, tools = build_system()
    permit = authority.issue(OWNER, TASK, AGENT, "send_email", email_args())
    result = runtime.execute(DOUBLE_EFFECT_WAT, permit, authority, tools)
    records.append({"case": "replay_inside_tool", "runtime": result.status, "events": [e.__dict__ for e in result.events], "effects": tools.execution_log})

    print(json.dumps(records, indent=2))


if __name__ == "__main__":
    main()
