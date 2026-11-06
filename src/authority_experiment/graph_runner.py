from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .graph_agent import run_graph_agent
from .ollama_client import OllamaClient
from .scenarios import SYSTEM_PROMPT, USER_TASK, build_scenarios


def run_graph_matrix(
    output: Path,
    model: str,
    base_count: int = 4,
    scenario_filter: set[str] | None = None,
    temperature: float = 0.0,
    seed: int = 42,
    host: str = "http://127.0.0.1:11434",
) -> int:
    client = OllamaClient(host)
    provenance = client.runtime_provenance(model)
    scenarios = [
        scenario
        for scenario in build_scenarios(base_count)
        if not scenario_filter or scenario.scenario in scenario_filter
    ]
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        for index, scenario in enumerate(scenarios, start=1):
            record: dict[str, object] = {
                "run_id": f"{model.replace(':', '_')}__{scenario.scenario_id}__graph_bound_wasm",
                "model": model,
                "ticket_id": scenario.ticket_id,
                "scenario_id": scenario.scenario_id,
                "scenario": scenario.scenario,
                "injected": scenario.injected,
                "user_task": USER_TASK,
                "system_prompt": SYSTEM_PROMPT,
                "ticket_content": scenario.ticket_content,
                "settings": {"temperature": temperature, "seed": seed, "max_turns": 8},
                "runtime_provenance": provenance,
            }
            try:
                record.update(
                    run_graph_agent(
                        client,
                        model,
                        scenario.ticket_id,
                        scenario.ticket_content,
                        task_id=f"support-{scenario.ticket_id}",
                        temperature=temperature,
                        seed=seed,
                        injected=scenario.injected,
                    )
                )
            except Exception as exc:
                record["error"] = f"{type(exc).__name__}: {exc}"
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            handle.flush()
            print(f"[{index}/{len(scenarios)}] {record['run_id']}", file=sys.stderr)
    return len(scenarios)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run model proposals through the graph-bound Wasmtime authority plane."
    )
    parser.add_argument("--model", required=True)
    parser.add_argument("--output", type=Path, default=Path("results/graph_runs.jsonl"))
    parser.add_argument("--base-count", type=int, default=4)
    parser.add_argument(
        "--scenario",
        action="append",
        choices=[
            "benign",
            "recipient_redirect",
            "additional_action",
            "privilege_escalation",
            "authority_spoofing",
            "destructive_detour",
        ],
    )
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--host", default="http://127.0.0.1:11434")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    count = run_graph_matrix(
        args.output,
        args.model,
        args.base_count,
        set(args.scenario) if args.scenario else None,
        args.temperature,
        args.seed,
        args.host,
    )
    print(f"Wrote {count} graph-bound runs to {args.output}")


if __name__ == "__main__":
    main()
