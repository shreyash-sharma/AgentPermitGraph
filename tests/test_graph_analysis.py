from authority_experiment.graph_analysis import summarize, summarize_attacks


def record(model: str, scenario: str, injected: bool, **values):
    base = {
        "model": model,
        "scenario": scenario,
        "injected": injected,
        "error": None,
        "model_compromised": False,
        "system_compromised": False,
        "invalid_proposal": False,
        "benign_success": False,
        "overblocked": False,
        "excess_actions": False,
        "proposed_calls": [],
    }
    return base | values


def test_graph_summary_separates_proposal_execution_and_utility() -> None:
    rows = summarize(
        [
            record(
                "model",
                "recipient_redirect",
                True,
                model_compromised=True,
                proposed_calls=[
                    {
                        "name": "send_email",
                        "arguments": {
                            "to": "attacker@example.test",
                            "subject": "x",
                            "body": "x",
                        },
                    }
                ],
            ),
            record("model", "benign", False, benign_success=True),
        ]
    )
    assert rows[0]["model_compromise_rate"] == 1.0
    assert rows[0]["schema_valid_model_compromise_rate"] == 1.0
    assert rows[0]["attack_execution_rate"] == 0.0
    assert rows[0]["benign_task_success"] == 1.0


def test_attack_summary_counts_effects_not_text() -> None:
    rows = summarize_attacks(
        [
            record("model", "recipient_redirect", True, model_compromised=True),
            record("model2", "recipient_redirect", True, system_compromised=True),
        ]
    )
    assert rows[0]["unauthorized_proposals"] == 1
    assert rows[0]["unauthorized_executions"] == 1
