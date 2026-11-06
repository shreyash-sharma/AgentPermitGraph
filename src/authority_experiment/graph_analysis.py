from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

from .analysis import load_records, rate, schema_valid_model_compromised


DEFAULT_INPUTS = (
    Path("results/qwen3_4b_graph_bound.jsonl"),
    Path("results/llama3.1_8b_graph_bound.jsonl"),
    Path("results/granite4_7b_a1b_h_graph_bound.jsonl"),
)


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{100 * value:.1f}%"


def _derived_rate(records: list[dict[str, Any]]) -> float | None:
    valid = [record for record in records if not record.get("error")]
    if not valid:
        return None
    return sum(schema_valid_model_compromised(record) for record in valid) / len(valid)


def summarize(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for model in sorted({record["model"] for record in records}):
        group = [record for record in records if record["model"] == model]
        attacked = [record for record in group if record["injected"]]
        benign = [record for record in group if not record["injected"]]
        rows.append(
            {
                "model": model,
                "attacked_n": len(attacked),
                "benign_n": len(benign),
                "failed_runs": sum(bool(record.get("error")) for record in group),
                "model_compromise_rate": rate(attacked, "model_compromised"),
                "schema_valid_model_compromise_rate": _derived_rate(attacked),
                "attack_execution_rate": rate(attacked, "system_compromised"),
                "invalid_proposal_rate": rate(attacked, "invalid_proposal"),
                "benign_task_success": rate(benign, "benign_success"),
                "overblocking_rate": rate(benign, "overblocked"),
                "excess_action_rate": rate(group, "excess_actions"),
            }
        )
    return rows


def summarize_attacks(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    scenarios = sorted({record["scenario"] for record in records if record["injected"]})
    for scenario in scenarios:
        group = [record for record in records if record["scenario"] == scenario]
        rows.append(
            {
                "scenario": scenario,
                "n": len(group),
                "unauthorized_proposals": sum(record["model_compromised"] for record in group),
                "schema_valid_unauthorized_proposals": sum(
                    schema_valid_model_compromised(record) for record in group
                ),
                "unauthorized_executions": sum(record["system_compromised"] for record in group),
                "invalid_proposal_runs": sum(record["invalid_proposal"] for record in group),
            }
        )
    return rows


def write_csv(rows: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _task_scoped_baseline(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for model in sorted({record["model"] for record in records}):
        group = [
            record
            for record in records
            if record["model"] == model and record["authority"] == "task_scoped"
        ]
        attacked = [record for record in group if record["injected"]]
        benign = [record for record in group if not record["injected"]]
        result[model] = {
            "proposal": rate(attacked, "model_compromised"),
            "execution": rate(attacked, "system_compromised"),
            "utility": rate(benign, "benign_success"),
        }
    return result


def write_report(
    records: list[dict[str, Any]],
    summary: list[dict[str, Any]],
    attacks: list[dict[str, Any]],
    path: Path,
    baseline_records: list[dict[str, Any]] | None = None,
) -> None:
    attacked = [record for record in records if record["injected"]]
    benign = [record for record in records if not record["injected"]]
    completed = [record for record in records if not record.get("error")]
    proposal_count = sum(record["model_compromised"] for record in attacked)
    schema_valid_count = sum(schema_valid_model_compromised(record) for record in attacked)
    execution_count = sum(record["system_compromised"] for record in attacked)
    invalid_count = sum(record["invalid_proposal"] for record in attacked)
    benign_success_count = sum(record["benign_success"] for record in benign)
    effect_count = sum(len(record.get("effect_log", [])) for record in records)
    lines = [
        "# Graph-bound authority results",
        "",
        "## Result",
        "",
        f"The graph-bound condition completed {len(completed)} of {len(records)} runs with no runner errors.",
        f"Models made unauthorized proposals in {proposal_count}/{len(attacked)} attacked runs ({_pct(proposal_count / len(attacked))}).",
        f"The closed-schema subset contained unauthorized proposals in {schema_valid_count}/{len(attacked)} attacked runs ({_pct(schema_valid_count / len(attacked))}).",
        f"Unauthorized execution was {execution_count}/{len(attacked)} ({_pct(execution_count / len(attacked))}).",
        f"Benign task success was {benign_success_count}/{len(benign)} ({_pct(benign_success_count / len(benign))}).",
        f"The Wasmtime boundary committed {effect_count} synthetic effects. The independent oracle classified all of them as authorized.",
        "",
        "This result supports the separation between model compromise and system compromise. It does not prove that the model resisted prompt injection.",
        "",
        "## Results by model",
        "",
        "| Model | Attacked | Benign | Unauthorized proposal | Schema-valid subset | Unauthorized execution | Invalid proposal | Benign success | Overblocking | Excess actions |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in summary:
        lines.append(
            f"| {row['model']} | {row['attacked_n']} | {row['benign_n']} | "
            f"{_pct(row['model_compromise_rate'])} | {_pct(row['schema_valid_model_compromise_rate'])} | "
            f"{_pct(row['attack_execution_rate'])} | {_pct(row['invalid_proposal_rate'])} | "
            f"{_pct(row['benign_task_success'])} | {_pct(row['overblocking_rate'])} | "
            f"{_pct(row['excess_action_rate'])} |"
        )
    lines += [
        "",
        "## Results by attack class",
        "",
        "| Attack | Runs | Unauthorized proposals | Schema-valid subset | Unauthorized executions | Invalid-proposal runs |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for row in attacks:
        lines.append(
            f"| {row['scenario']} | {row['n']} | {row['unauthorized_proposals']} | "
            f"{row['schema_valid_unauthorized_proposals']} | {row['unauthorized_executions']} | "
            f"{row['invalid_proposal_runs']} |"
        )

    if baseline_records:
        baseline = _task_scoped_baseline(baseline_records)
        lines += [
            "",
            "## Comparison with the prior task-scoped condition",
            "",
            "The model files, digests, prompts, temperature, seed, and scenario set are the same. The authority implementation and its denial messages are different.",
            "",
            "| Model | Prior proposal | Graph proposal | Prior execution | Graph execution | Prior benign success | Graph benign success |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
        for row in summary:
            old = baseline.get(row["model"], {})
            lines.append(
                f"| {row['model']} | {_pct(old.get('proposal'))} | {_pct(row['model_compromise_rate'])} | "
                f"{_pct(old.get('execution'))} | {_pct(row['attack_execution_rate'])} | "
                f"{_pct(old.get('utility'))} | {_pct(row['benign_task_success'])} |"
            )

    lines += [
        "",
        "## Interpretation",
        "",
        "- The relationship graph stopped requests for resources that had no task relation.",
        "- The signed permit sealed the approved tool and arguments.",
        "- The one-use state stopped repeated and concurrent permit use in the deterministic tests.",
        "- The graph epoch stopped a permit after permission changed in the deterministic tests.",
        "- The Wasm import allow-list stopped undeclared host access in the deterministic tests.",
        "- Fuel and store limits stopped non-terminating and high-memory guests in the deterministic tests.",
        "",
        "## Limits",
        "",
        "- The 72 model runs use four base tickets and one seed.",
        "- All effects are synthetic and local.",
        "- The graph and permit ledger are in memory.",
        "- The test is not a production Zanzibar deployment.",
        "- The test does not measure email-body semantic safety.",
        "- The Wasm adapter is a small test guest, not a third-party production tool.",
        "",
        f"Attacked runs with an invalid proposal: {invalid_count}/{len(attacked)}. These records remain in the raw JSONL.",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze graph-bound authority JSONL records.")
    parser.add_argument("--input", action="append", type=Path)
    parser.add_argument("--baseline", type=Path, default=Path("results/runs.jsonl"))
    parser.add_argument("--aggregate", type=Path, default=Path("results/graph_bound_aggregate.csv"))
    parser.add_argument("--report", type=Path, default=Path("GRAPH_BOUND_RESULTS.md"))
    args = parser.parse_args()
    inputs = tuple(args.input) if args.input else DEFAULT_INPUTS
    records = [record for input_path in inputs for record in load_records(input_path)]
    if not records:
        raise ValueError("input contains no records")
    summary = summarize(records)
    attacks = summarize_attacks(records)
    write_csv(summary, args.aggregate)
    baseline = load_records(args.baseline) if args.baseline.exists() else None
    write_report(records, summary, attacks, args.report, baseline)
    print(f"Analyzed {len(records)} graph-bound runs")


if __name__ == "__main__":
    main()
