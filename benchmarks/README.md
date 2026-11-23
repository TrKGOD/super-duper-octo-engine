# Agent evaluation benchmark

This benchmark measures the quality of **agent-produced finding decisions** against small, explicitly synthetic fixtures. It does not scan targets, execute payloads, or establish real-world detection performance.

## Dataset rules
- Every checked-in case is synthetic and safe to publish.
- Do not add client reports, private bug-bounty submissions, credentials, screenshots, or real target data.
- Positive cases describe the expected class and evidence contract, not a ready-made exploit.
- Negative cases are deliberate false-positive traps.

## Prediction format

Create a JSON file with a `predictions` array:

```json
{
  "predictions": [
    {
      "case_id": "SYN-BOLA-001",
      "detected": true,
      "vulnerability_type": "BOLA",
      "evidence_fields": [
        "request_identity",
        "object_owner_identity",
        "authorization_decision"
      ]
    }
  ]
}
```

Each case must appear exactly once. Unknown and duplicate IDs are errors. Missing cases count as missed predictions (FN for positive cases, TN for negative cases) only when `--allow-missing` is supplied; otherwise evaluation fails closed.

## Run a real agent

Install and authenticate Claude Code, then pin the exact model and per-case timeout used for every comparison:

    python scripts/run_benchmark.py --agent vulnerability-agent --model "$CLAUDE_BENCHMARK_MODEL" --timeout-seconds 120 --scope-id synthetic-lab-v1
    python scripts/evaluate_benchmark.py --cases benchmarks/cases --predictions .local/predictions.json --json-out .local/benchmark-results.json

The runner reads the target agent instructions from .claude/agents, supplies each case description and fixtures, withholds ground truth, disables tools, limits each invocation to one turn, validates output against templates/prediction.schema.json, and writes a run manifest with model, scope, timeout and per-case durations. If Claude Code is missing, unauthenticated, times out, or emits invalid output, the run fails; it never substitutes hand-written or simulated predictions.

The CI agent-benchmark job is separate and non-blocking. Configure the repository variable CLAUDE_BENCHMARK_MODEL and secret ANTHROPIC_API_KEY to enable it. The static predictions.example.json remains only a schema/evaluator fixture and must not be presented as an agent run.

## Evaluate an existing prediction file

    python scripts/evaluate_benchmark.py --cases benchmarks/cases --predictions /path/to/predictions.json --json-out .local/benchmark-results.json

## Metrics
- Precision, recall, F1
- False-positive rate
- Evidence completeness: mean fraction of required evidence fields present on detected positive cases

The evaluator reports counts and percentages. It does **not** claim model accuracy from unit tests or from this synthetic fixture set. The corpus currently contains 19 synthetic cases across SQLi, XSS, IDOR/BOLA, SSRF, authentication and authorization, including near-positive negatives. Compare agent versions on the same cases and treat results as directional until the corpus is independently reviewed and substantially expanded.


## Seven-wave retrieval and capability gates

Run deterministic registry retrieval and agent-contract checks:

```bash
python scripts/retrieval_gate.py --json-out .local/retrieval-gate-results.json
```

The seven synthetic retrieval scenarios cover SSRF, BOLA/IDOR/BAC, authentication/MFA, XSS/CSRF/injection, information disclosure/secrets, HTTP/cache/race conditions, and remaining vulnerability classes. The capability gates verify evidence-bearing handoffs, validator attribution for validated findings, and basic agent contract requirements.

These are routing/schema regression gates, not a test of whether an LLM can discover or exploit a vulnerability. For actual model capability comparisons, run the agent benchmark with a pinned model and identical synthetic cases as described above. Keep deterministic gate results and model-produced benchmark metrics separate.
