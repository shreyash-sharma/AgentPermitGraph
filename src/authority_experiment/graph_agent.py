from __future__ import annotations

import json
from typing import Any

from .graph_authority import AuthorityDenied, GraphAuthority, TaskPermissionGraph
from .ollama_client import OllamaClient
from .outcomes import classify_outcome
from .scenarios import SYSTEM_PROMPT, USER_TASK
from .tools import TOOL_SCHEMAS, SyntheticTools
from .wasm_runtime import BENIGN_EFFECT_WAT, GraphBoundWasmRuntime


def _normalise_call(raw: dict[str, Any]) -> tuple[str, Any]:
    function = raw.get("function", raw)
    name = str(function.get("name", ""))
    arguments: Any = function.get("arguments", {})
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except json.JSONDecodeError:
            pass
    return name, arguments


def build_task_graph(
    ticket_id: str,
    owner: str,
    task_id: str,
    agent_id: str,
    recipient: str,
) -> TaskPermissionGraph:
    graph = TaskPermissionGraph()
    graph.create_task(task_id, owner, agent_id)
    graph.grant(task_id, "read_ticket", {"ticket_id": ticket_id})
    graph.grant(
        task_id,
        "send_email",
        {"to": recipient, "subject": "task grant", "body": "task grant"},
    )
    return graph


def run_graph_agent(
    client: OllamaClient,
    model: str,
    ticket_id: str,
    ticket_content: str,
    *,
    owner: str = "alice",
    task_id: str = "support-T-104",
    agent_id: str = "support-agent-7",
    recipient: str = "support@example.test",
    temperature: float = 0.0,
    seed: int = 42,
    max_turns: int = 8,
    injected: bool = False,
) -> dict[str, Any]:
    """Run model proposals through graph checks and a Wasmtime effect boundary."""
    graph = build_task_graph(ticket_id, owner, task_id, agent_id, recipient)
    authority = GraphAuthority(graph)
    runtime = GraphBoundWasmRuntime()
    tools = SyntheticTools(ticket_id, ticket_content)
    schemas = [TOOL_SCHEMAS["read_ticket"], TOOL_SCHEMAS["send_email"]]
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": USER_TASK},
    ]
    proposed: list[dict[str, Any]] = []
    executed: list[dict[str, Any]] = []
    denied: list[dict[str, Any]] = []
    runtime_events: list[dict[str, Any]] = []
    final_response = ""

    for _ in range(max_turns):
        response = client.chat(model, messages, schemas, {"temperature": temperature, "seed": seed})
        message = response.get("message", {})
        raw_calls = message.get("tool_calls") or []
        assistant_message: dict[str, Any] = {
            "role": "assistant",
            "content": message.get("content", ""),
        }
        if raw_calls:
            assistant_message["tool_calls"] = raw_calls
        messages.append(assistant_message)
        final_response = str(message.get("content", ""))
        if not raw_calls:
            break

        for raw_call in raw_calls:
            name, arguments = _normalise_call(raw_call)
            proposal = {"name": name, "arguments": arguments}
            proposed.append(proposal)
            try:
                if not isinstance(arguments, dict):
                    raise AuthorityDenied("tool arguments are not an object")
                permit = authority.issue(owner, task_id, agent_id, name, arguments)
                result = runtime.execute(BENIGN_EFFECT_WAT, permit, authority, tools)
                runtime_events.append(
                    {
                        "name": name,
                        "permit_id": permit.permit_id,
                        "status": result.status,
                        "events": [event.__dict__ for event in result.events],
                    }
                )
                if result.status != "EXECUTED":
                    reason = result.events[-1].reason if result.events else result.status
                    denied.append(proposal | {"reason": reason})
                    tool_message = f"DENIED: {reason}"
                else:
                    sealed = permit.arguments
                    executed.append({"name": name, "arguments": sealed, "result": result.tool_result})
                    tool_message = str(result.tool_result)
            except (AuthorityDenied, KeyError, TypeError, ValueError) as exc:
                reason = str(exc)
                denied.append(proposal | {"reason": reason})
                tool_message = f"DENIED: {reason}"
            messages.append({"role": "tool", "tool_name": name, "content": tool_message})

    outcome = classify_outcome(proposed, executed, denied, injected=injected)
    return {
        "authority": "graph_bound_wasm",
        "authority_plane": "relationship_graph_and_effect_capability",
        "policy_version": "graph-effect-policy-v1",
        "graph_epoch": graph.epoch(task_id),
        "graph_tuples": [str(item) for item in graph.tuples()],
        "proposed_calls": proposed,
        "executed_calls": executed,
        "denied_calls": denied,
        "runtime_events": runtime_events,
        "effect_log": tools.execution_log,
        "final_response": final_response,
        **outcome,
    }
