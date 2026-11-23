# Benchmarking and Runtime Smoke Tests

## Scope

The repository contains two separate validation paths:

1. **Synthetic specialist benchmark** — evaluates a configured agent prompt against synthetic fixtures. It runs one case at a time, with no network and no tools.
2. **Claude Code specialist runtime smoke** — asks Claude Code to load one named repository agent and return a constrained response, with tools disabled.

Neither path proves end-to-end orchestration, autonomous Task dispatch, dynamic Skill selection, or real-target testing.

## Synthetic benchmark

Install development dependencies and authenticate the Claude Code CLI, then run:

```bash
python scripts/run_benchmark.py \
  --agent vulnerability-agent \
  --model MODEL_NAME \
  --timeout-seconds 120 \
  --scope-id synthetic-lab-v1 \
  --predictions-out .local/predictions.json \
  --manifest-out .local/benchmark-run.json

python scripts/evaluate_benchmark.py \
  --cases benchmarks/cases \
  --predictions .local/predictions.json \
  --json-out .local/benchmark-results.json
```

The prompt is passed on stdin. Do not append it after `--tools`: the CLI option is variadic and may consume a trailing positional prompt as a tool name.

Positive cases must provide every field named in `required_evidence` under `fixtures`. This prevents a fixture from being counted as a model false negative when the model was never given the evidence required to identify the case. Negative cases may omit fixture payloads when their expected outcome is a safe rejection.

The run manifest records the agent prompt hash, model label, case IDs, corpus hash, per-case elapsed time, and available Claude CLI usage/cost fields. If the CLI does not return usage metadata, the manifest reports it as unavailable. Missing cost data must not be interpreted as zero cost.

## Specialist runtime smoke

```bash
python scripts/runtime_smoke.py --agent vulnerability-agent --model MODEL_NAME
```

This invokes the named custom agent through the Claude Code CLI with tools disabled. It is a bounded smoke test for agent loading and response shape. It does not test Task-based dispatch, a live handoff, dynamic Skill loading, or permissions beyond the explicit no-tools invocation.

## Static agent tool declarations

```bash
python scripts/validate_agent_tools.py
```

This checks repository frontmatter for least-privilege tool declarations: the orchestrator is the only agent permitted to declare Bash, Task, or Write in the current baseline; specialist agents must not declare privileged tools. This is a static repository check, not an enforcement boundary. Claude Code settings, inherited permissions, hooks, and runtime grants must still be inspected in the actual execution environment.

## Model 1 versus hybrid comparison

A fair comparison requires equivalent synthetic cases, equivalent model versions, equivalent budgets, repeated runs, and separate architecture-specific traces. The current specialist runner is not a Model 1-versus-hybrid harness. Do not claim a comparative result until both complete workflows can be executed and measured under the same conditions.

## Live-target assessment

No live-target testing is part of these benchmark commands. A real assessment requires operator-confirmed written authorization, exact in-scope assets, exclusions, permitted methods, test window, request limits, data-handling rules, and human approval. The current workflow runner still requires `execution_enabled=false` and rejects active-testing plans. Do not bypass this control to produce a benchmark result.

## Interpreting results

Precision, recall, F1, false-positive rate, and evidence completeness describe performance against the supplied synthetic corpus only. Report corpus size, positive/negative balance, model identifier, repeated runs, time, and cost alongside metrics. Small fixture sets do not establish production reliability.


## Model 1 versus hybrid pipeline simulation

The repository preserves separate fixed specialist sequences:

- Model 1: Recon → Enumeration → Vulnerability Discovery → Exploitation Analysis → Validation → Reporting.
- Hybrid: Scope → Recon → Technology Profiling → Enumeration → Vulnerability Analysis → Validation → Impact → Deduplication → Reporting.

Run each plan against the same corpus and model:

```bash
python scripts/run_architecture_benchmark.py --architecture model1 --plan templates/examples/plan.model1.passive.example.json --model MODEL_NAME --predictions-out .local/model1-predictions.json --manifest-out .local/model1-manifest.json
python scripts/run_architecture_benchmark.py --architecture hybrid --plan templates/examples/plan.hybrid.passive.example.json --model MODEL_NAME --predictions-out .local/hybrid-predictions.json --manifest-out .local/hybrid-manifest.json
python scripts/compare_architecture_results.py --model1-predictions .local/model1-predictions.json --model1-manifest .local/model1-manifest.json --hybrid-predictions .local/hybrid-predictions.json --hybrid-manifest .local/hybrid-manifest.json
```

The runner enforces the exact sequence associated with each architecture label. The comparator verifies the same model identifier and exact current corpus hash before computing deltas. This measures fixed sequential pipeline simulations, not autonomous Orchestrator planning or Task-tool behavior. Run multiple repetitions and report variance before drawing conclusions.
