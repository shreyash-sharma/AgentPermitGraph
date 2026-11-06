from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable

from .agent import run_agent
from .authority import Authorizer
from .models import Authority, RunRecord
from .ollama_client import OllamaClient
from .scenarios import SYSTEM_PROMPT, USER_TASK, build_scenarios

AUTHORITIES: tuple[Authority, ...] = ("broad", "coarse", "task_scoped")


def run_matrix(
    output: Path,
    model: str,
    authorities: Iterable[Authority] = AUTHORITIES,
    base_count: int = 10,
    scenario_filter: set[str] | None = None,
    temperature: float = 0.0,
    seed: int = 42,
    host: str = "http://127.0.0.1:11434",
) -> int:
    client = OllamaClient(host)
    runtime_provenance = client.runtime_provenance(model)
    authorities = tuple(authorities)
    scenarios = [s for s in build_scenarios(base_count) if not scenario_filter or s.scenario in scenario_filter]
    output.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with output.open("w", encoding="utf-8") as handle:
        for scenario in scenarios:
            for authority in authorities:
                authorizer = Authorizer(authority)
                record = RunRecord(
                    run_id=f"{model.replace(':', '_')}__{scenario.scenario_id}__{authority}",
                    model=model,
                    ticket_id=scenario.ticket_id,
                    scenario_id=scenario.scenario_id,
                    scenario=scenario.scenario,
                    injected=scenario.injected,
                    authority=authority,
                    user_task=USER_TASK,
                    system_prompt=SYSTEM_PROMPT,
                    ticket_content=scenario.ticket_content,
                    settings={"temperature": temperature, "seed": seed, "max_turns": 8},
                    authority_exposure=authorizer.exposure(),
                    runtime_provenance=runtime_provenance,
                    policy_version=authorizer.policy_version,
                )
                try:
                    outcome = run_agent(client, model, scenario, authorizer, temperature, seed)
                    for key, value in outcome.items():
                        setattr(record, key, value)
                except Exception as exc:  # Preserve failed runs in JSONL.
                    record.error = f"{type(exc).__name__}: {exc}"
                handle.write(json.dumps(record.to_dict(), ensure_ascii=False) + "\n")
                handle.flush()
                count += 1
                print(f"[{count}/{len(scenarios) * len(authorities)}] {record.run_id}", file=sys.stderr)
    return count


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True)
    parser.add_argument("--output", type=Path, default=Path("results/runs.jsonl"))
    parser.add_argument("--base-count", type=int, default=10)
    parser.add_argument("--authority", action="append", choices=AUTHORITIES)
    parser.add_argument("--scenario", action="append", choices=["benign", "recipient_redirect", "additional_action", "privilege_escalation", "authority_spoofing", "destructive_detour"])
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--host", default="http://127.0.0.1:11434")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    count = run_matrix(
        args.output, args.model, args.authority or AUTHORITIES, args.base_count,
        set(args.scenario) if args.scenario else None, args.temperature, args.seed, args.host,
    )
    print(f"Wrote {count} runs to {args.output}")


if __name__ == "__main__":
    main()
