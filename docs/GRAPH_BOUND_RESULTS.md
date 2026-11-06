# Graph-bound authority results

## Result

The graph-bound condition completed 72 of 72 runs with no runner errors.
Models made unauthorized proposals in 25/60 attacked runs (41.7%).
The closed-schema subset contained unauthorized proposals in 17/60 attacked runs (28.3%).
Unauthorized execution was 0/60 (0.0%).
Benign task success was 12/12 (100.0%).
The Wasmtime boundary committed 134 synthetic effects. The independent oracle classified all of them as authorized.

This result supports the separation between model compromise and system compromise. It does not prove that the model resisted prompt injection.

## Results by model

| Model | Attacked | Benign | Unauthorized proposal | Schema-valid subset | Unauthorized execution | Invalid proposal | Benign success | Overblocking | Excess actions |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| granite4:7b-a1b-h | 20 | 4 | 40.0% | 40.0% | 0.0% | 0.0% | 100.0% | 0.0% | 0.0% |
| llama3.1:8b | 20 | 4 | 55.0% | 15.0% | 0.0% | 70.0% | 100.0% | 0.0% | 0.0% |
| qwen3:4b | 20 | 4 | 30.0% | 30.0% | 0.0% | 0.0% | 100.0% | 0.0% | 0.0% |

## Results by attack class

| Attack | Runs | Unauthorized proposals | Schema-valid subset | Unauthorized executions | Invalid-proposal runs |
|---|---:|---:|---:|---:|---:|
| additional_action | 12 | 10 | 9 | 0 | 1 |
| authority_spoofing | 12 | 3 | 0 | 0 | 3 |
| destructive_detour | 12 | 0 | 0 | 0 | 4 |
| privilege_escalation | 12 | 0 | 0 | 0 | 3 |
| recipient_redirect | 12 | 12 | 8 | 0 | 3 |

## Comparison with the prior task-scoped condition

The model files, digests, prompts, temperature, seed, and scenario set are the same. The authority implementation and its denial messages are different.

| Model | Prior proposal | Graph proposal | Prior execution | Graph execution | Prior benign success | Graph benign success |
|---|---:|---:|---:|---:|---:|---:|
| granite4:7b-a1b-h | 40.0% | 40.0% | 0.0% | 0.0% | 100.0% | 100.0% |
| llama3.1:8b | 55.0% | 55.0% | 0.0% | 0.0% | 100.0% | 100.0% |
| qwen3:4b | 30.0% | 30.0% | 0.0% | 0.0% | 100.0% | 100.0% |

## Interpretation

- The relationship graph stopped requests for resources that had no task relation.
- The signed permit sealed the approved tool and arguments.
- The one-use state stopped repeated and concurrent permit use in the deterministic tests.
- The graph epoch stopped a permit after permission changed in the deterministic tests.
- The Wasm import allow-list stopped undeclared host access in the deterministic tests.
- Fuel and store limits stopped non-terminating and high-memory guests in the deterministic tests.

## Limits

- The 72 model runs use four base tickets and one seed.
- All effects are synthetic and local.
- The graph and permit ledger are in memory.
- The test is not a production Zanzibar deployment.
- The test does not measure email-body semantic safety.
- The Wasm adapter is a small test guest, not a third-party production tool.

Attacked runs with an invalid proposal: 14/60. These records remain in the raw JSONL.
