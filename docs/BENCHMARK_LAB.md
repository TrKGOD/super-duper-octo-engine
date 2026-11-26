# Benchmark & Regression Lab

**Phase 6 — foundation.** Status: `lab_verified`. A deterministic, CI-safe harness that
measures whether Witherhoard is actually improving, by running synthetic scenarios through
the **real** pipeline — attack graph → adaptive planner → exploit validation engine — and
scoring the validated findings against ground truth.

## Why this is trustworthy

- **No live targets, no model calls.** Every scenario is in-memory synthetic data; the run
  manifest asserts `no_live_targets` and `no_model_calls`. CI never initializes a real
  engagement or contacts a host.
- **Exercises the real components**, not a mock. A scenario seeds the real graph, the real
  `AdaptivePlanner` generates/validates/selects candidates under its real policy, and the
  real `ExploitValidationEngine` oracles decide each disposition. The benchmark therefore
  also serves as the end-to-end integration test for Phases 2–4.
- **Reproducible.** Repeated runs of a scenario yield identical metrics (variance stdev 0),
  checked by the harness and surfaced per run.

## Metrics (directive §11.4)

Per scenario: true/false positives, false negatives, **precision / recall / F1** (recall is
`None` when a scenario has no ground-truth vulnerabilities and precision is `None` when
nothing was reported — never silently 1.0), **endpoint coverage**, **validated-finding
count**, policy-rejection count, inconclusive count, **runtime** and **cost** (`0.0`,
explicitly synthetic). The suite reports macro precision/recall and whether every scenario
was reproducible.

## Scenarios (`core/benchmark/scenarios.py`)

Built-in synthetic scenarios: `web-bola-basic` (IDOR/BOLA), `api-bfla-basic` (function-level
authorization), `web-sqli-basic` (SQLi, on an endpoint that also yields an XSS candidate —
tests that the pipeline distinguishes the class), `clean-negative` (no vulnerabilities — must
produce no false positives), and `mixed-web-api`. A `DetectorProfile` can inject false
positives/negatives to exercise the metrics themselves.

## Running

```
python -m unittest tests.test_benchmark_regression        # the CI-safe smoke
python scripts/run_regression_benchmark.py --repetitions 3 # full report + variance
python scripts/run_regression_benchmark.py --out new.json --baseline old.json  # regression gate
```

`compare_results` (and the `--baseline` flag) flag any scenario whose precision/recall/F1
dropped, returning a non-zero exit code for use as a regression gate.

### Regression gate policy (directive §11.6)

The deterministic smoke (`tests/test_benchmark_regression.py`) runs in the normal CI `test`
job — it is fast and target-free. The **real-agent** benchmark (`scripts/run_benchmark.py`,
`scripts/evaluate_benchmark.py`) stays a **separate, gated** path behind the
`CLAUDE_BENCHMARK_MODEL` repository variable; it is never run against live targets in CI, and
a single successful real-agent run is never reported as reliable capability.

## Tests

`tests/test_benchmark_regression.py` (10): metric edge cases; BOLA/BFLA/SQLi/clean/mixed
scenario detection; same-endpoint class discrimination; noisy-detector precision/recall
drops; reproducibility across repetitions with zero variance; suite aggregation; and the
regression-comparison gate.

## Limitations and follow-ups

- The validation dispositions here are driven by scenario-synthesized evidence (a scripted
  "detector"), not by live tool output; it measures the **pipeline's** selection and
  validation logic, not a scanner's real-world detection rate. Wiring real tool output
  through the Phase 5 workers into this harness is the next step.
- External benchmarks (XBEN and similar) are **not** integrated; licensing, setup and
  cross-model comparability must be verified first (directive §11.3).
- Cost is synthetic (`0.0`). Real cost/latency come from the gated real-agent benchmark.
- Metrics rank within this synthetic corpus; they are not a claim of real-world
  effectiveness.
