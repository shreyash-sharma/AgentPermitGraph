from __future__ import annotations

import json
from typing import Any

from .authority import Authorizer
from .blast_radius import blast_radius_tier
from .models import CallEvent, Scenario
from .ollama_client import OllamaClient
from .outcomes import classify_outcome
from .scenarios import SYSTEM_PROMPT, USER_TASK
from .tools import TOOL_SCHEMAS, SyntheticTools, canonical_tool_arguments, event_dict


def _normalise_call(raw: dict[str, Any]) -> tuple[str, Any]:
    function = raw.get("function", raw)
    name = str(function.get("name", ""))
    arguments: Any = function.get("arguments", {})
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except json.JSONDecodeError:
            return name, arguments
    return name, arguments


def run_agent(
    client: OllamaClient,
    model: str,
    scenario: Scenario,
    authorizer: Authorizer,
    temperature: float = 0.0,
    seed: int = 42,
    max_turns: int = 8,
) -> dict[str, Any]:
    tools = SyntheticTools(scenario.ticket_id, scenario.ticket_content)
    schemas = [TOOL_SCHEMAS[name] for name in authorizer.exposed_tools]
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": USER_TASK},
    ]
    events: list[CallEvent] = []
    final_response = ""
    for _ in range(max_turns):
        response = client.chat(model, messages, schemas, {"temperature": temperature, "seed": seed})
        message = response.get("message", {})
        assistant_message: dict[str, Any] = {
            "role": "assistant",
            "content": message.get("content", ""),
        }
        raw_calls = message.get("tool_calls") or []
        if raw_calls:
            assistant_message["tool_calls"] = raw_calls
        messages.append(assistant_message)
        final_response = str(message.get("content", ""))
        if not raw_calls:
            break
        for raw_call in raw_calls:
            name, arguments = _normalise_call(raw_call)
            tier = (
                blast_radius_tier(name, arguments)
                if name in authorizer.exposure()["action_blast_radius_tiers"] and isinstance(arguments, dict)
                else None
            )
            events.append(
                CallEvent(
                    len(events) + 1,
                    "PROPOSED",
                    name,
                    arguments,
                    policy_version=authorizer.policy_version,
                    blast_radius_tier=tier,
                )
            )
            allowed, reason = authorizer.authorize(name, arguments)
            if not allowed:
                events.append(
                    CallEvent(
                        len(events) + 1,
                        "DENIED",
                        name,
                        arguments,
                        reason=reason,
                        policy_version=authorizer.policy_version,
                        blast_radius_tier=tier,
                    )
                )
                result = f"DENIED: {reason}"
            else:
                try:
                    # The tool receives a fresh, closed-contract object rather than
                    # the mutable/raw proposal evaluated above.
                    authorized_arguments = canonical_tool_arguments(name, arguments)
                    result = tools.execute(name, authorized_arguments)
                    authorizer.record_execution(name)
                    events.append(
                        CallEvent(
                            len(events) + 1,
                            "EXECUTED",
                            name,
                            authorized_arguments,
                            reason=reason,
                            result=result,
                            policy_version=authorizer.policy_version,
                            blast_radius_tier=tier,
                        )
                    )
                except (KeyError, TypeError, ValueError) as exc:
                    result = f"TOOL_ERROR: {exc}"
                    events.append(
                        CallEvent(
                            len(events) + 1,
                            "DENIED",
                            name,
                            arguments,
                            reason=result,
                            policy_version=authorizer.policy_version,
                            blast_radius_tier=tier,
                        )
                    )
            messages.append({"role": "tool", "tool_name": name, "content": result})

    proposed = [event_dict(event) for event in events if event.status == "PROPOSED"]
    executed = [event_dict(event) for event in events if event.status == "EXECUTED"]
    denied = [event_dict(event) for event in events if event.status == "DENIED"]

    outcome = classify_outcome(proposed, executed, denied, injected=scenario.injected)
    return {
        "events": [event_dict(event) for event in events],
        "proposed_calls": proposed,
        "executed_calls": executed,
        "denied_calls": denied,
        "final_response": final_response,
        **outcome,
    }
