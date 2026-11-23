# Model 1 comparison protocol

Run Model 1 and the hybrid architecture against the same authorized lab targets, test accounts, time budget, tool availability, and ground-truth corpus.

Measure:
- True positives and false positives
- Precision and recall
- Coverage of seeded issues
- Duplicate findings
- Time to first validated finding
- Total runtime and token cost
- Scope-policy violations
- Reproducibility

Do not compare runs with different scope, credentials, or time budgets.

## Synthetic agent-runner protocol

For reproducible agent-only smoke comparisons, run the same checked-in synthetic corpus with the same scope-id, exact model, and per-case timeout-seconds. Keep the target agent and agent prompt revision fixed or record the commit SHA alongside results. The runner invokes Claude Code once per case with tools disabled and one turn; it never sees the ground-truth expected_finding field. It writes predictions and a run manifest separately.

Run:

    python scripts/run_benchmark.py --agent vulnerability-agent --model "$CLAUDE_BENCHMARK_MODEL" --timeout-seconds 120 --scope-id synthetic-lab-v1
    python scripts/evaluate_benchmark.py --cases benchmarks/cases --predictions .local/predictions.json --json-out .local/benchmark-results.json

This synthetic runner does not replace the authorized-lab comparison protocol above. The CI agent-benchmark job is optional and non-blocking; it runs only when the repository variable CLAUDE_BENCHMARK_MODEL is configured and requires ANTHROPIC_API_KEY. Missing CLI/authentication fails the runner instead of fabricating predictions.

