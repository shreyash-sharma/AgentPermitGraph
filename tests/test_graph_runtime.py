from concurrent.futures import ThreadPoolExecutor

from authority_experiment.graph_authority import AuthorityDenied, GraphAuthority, TaskPermissionGraph
from authority_experiment.tools import SyntheticTools
from authority_experiment.wasm_runtime import (
    BENIGN_EFFECT_WAT,
    DOUBLE_EFFECT_WAT,
    HIDDEN_NETWORK_WAT,
    INFINITE_LOOP_WAT,
    MEMORY_HOG_WAT,
    GraphBoundWasmRuntime,
)


OWNER = "alice"
TASK = "support-T-104"
AGENT = "support-agent-7"


def email_args(to: str = "support@example.test") -> dict[str, str]:
    return {"to": to, "subject": "summary", "body": "ticket summary"}


def system():
    graph = TaskPermissionGraph()
    graph.create_task(TASK, OWNER, AGENT)
    graph.grant(TASK, "read_ticket", {"ticket_id": "T-104"})
    graph.grant(TASK, "send_email", email_args())
    authority = GraphAuthority(graph)
    runtime = GraphBoundWasmRuntime(fuel=2_000)
    tools = SyntheticTools("T-104", "ticket")
    return graph, authority, runtime, tools


def test_graph_contains_zanzibar_style_task_relations() -> None:
    graph, _, _, _ = system()
    values = {str(item) for item in graph.tuples()}
    assert f"task:{TASK}#owner@user:{OWNER}" in values
    assert f"task:{TASK}#delegate@agent:{AGENT}" in values
    assert f"recipient:support@example.test#send_email@task:{TASK}" in values


def test_bad_model_target_gets_no_permit() -> None:
    _, authority, _, _ = system()
    try:
        authority.issue(OWNER, TASK, AGENT, "send_email", email_args("attacker@example.test"))
    except AuthorityDenied as exc:
        assert "missing permission relation" in str(exc)
    else:
        raise AssertionError("unauthorized recipient received a permit")


def test_benign_wasm_tool_executes_one_bound_effect() -> None:
    _, authority, runtime, tools = system()
    permit = authority.issue(OWNER, TASK, AGENT, "send_email", email_args())
    result = runtime.execute(BENIGN_EFFECT_WAT, permit, authority, tools)
    assert result.status == "EXECUTED"
    assert len(tools.execution_log) == 1
    assert tools.execution_log[0]["arguments"]["to"] == "support@example.test"
    assert authority.state(permit.permit_id) == "consumed"


def test_malicious_tool_cannot_import_hidden_network() -> None:
    _, authority, runtime, tools = system()
    permit = authority.issue(OWNER, TASK, AGENT, "send_email", email_args())
    result = runtime.execute(HIDDEN_NETWORK_WAT, permit, authority, tools)
    assert result.status == "DENIED"
    assert tools.execution_log == []
    assert authority.state(permit.permit_id) == "undeclared_import"


def test_revocation_after_planning_denies_at_effect_boundary() -> None:
    graph, authority, runtime, tools = system()
    permit = authority.issue(OWNER, TASK, AGENT, "send_email", email_args())
    graph.revoke(TASK, "send_email", email_args())
    result = runtime.execute(BENIGN_EFFECT_WAT, permit, authority, tools)
    assert result.status == "TRAPPED"
    assert tools.execution_log == []
    assert any("stale task authority" in event.reason for event in result.events)


def test_double_effect_call_consumes_permit_once() -> None:
    _, authority, runtime, tools = system()
    permit = authority.issue(OWNER, TASK, AGENT, "send_email", email_args())
    result = runtime.execute(DOUBLE_EFFECT_WAT, permit, authority, tools)
    assert result.status == "TRAPPED"
    assert len(tools.execution_log) == 1
    assert authority.usage(TASK, "send_email")["consumed"] == 1
    assert any(event.status == "CAPABILITY_DENIED" for event in result.events)


def test_tampered_permit_is_rejected() -> None:
    _, authority, _, tools = system()
    permit = authority.issue(OWNER, TASK, AGENT, "send_email", email_args())
    tampered = permit.tamper(arguments_json='{"body":"x","subject":"x","to":"attacker@example.test"}')
    try:
        authority.execute(tampered, lambda arguments: tools.execute("send_email", arguments))
    except AuthorityDenied as exc:
        assert str(exc) == "invalid permit signature"
    else:
        raise AssertionError("tampered permit executed")
    assert tools.execution_log == []


def test_fuel_stops_nonterminating_guest_without_effect() -> None:
    _, authority, runtime, tools = system()
    permit = authority.issue(OWNER, TASK, AGENT, "send_email", email_args())
    result = runtime.execute(INFINITE_LOOP_WAT, permit, authority, tools)
    assert result.status == "TRAPPED"
    assert tools.execution_log == []
    assert authority.state(permit.permit_id) == "guest_trap"
    assert any("fuel" in event.reason.lower() for event in result.events)


def test_concurrent_replay_has_only_one_effect() -> None:
    _, authority, _, tools = system()
    permit = authority.issue(OWNER, TASK, AGENT, "send_email", email_args())

    def attempt() -> str:
        try:
            authority.execute(permit, lambda arguments: tools.execute("send_email", arguments))
            return "executed"
        except AuthorityDenied:
            return "denied"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: attempt(), range(2)))

    assert sorted(outcomes) == ["denied", "executed"]
    assert len(tools.execution_log) == 1


def test_memory_limit_stops_guest_before_effect() -> None:
    _, authority, runtime, tools = system()
    permit = authority.issue(OWNER, TASK, AGENT, "send_email", email_args())
    result = runtime.execute(MEMORY_HOG_WAT, permit, authority, tools)
    assert result.status == "TRAPPED"
    assert tools.execution_log == []
    assert authority.state(permit.permit_id) == "guest_trap"
