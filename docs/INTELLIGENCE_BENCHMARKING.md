# Intelligence-Layer Benchmarking

**Component H.** Status: `lab_verified`. Extends the [Benchmark & Regression Lab](BENCHMARK_LAB.md)
with three evaluators for the Intelligence Layer — **retrieval quality**, **tool-selection
quality** and **reporting quality** — plus a regression/safety gate. Like the Phase 6 pipeline
benchmark it is deterministic and CI-safe: every evaluator runs the **real** component on
synthetic, in-memory data, contacting no live target and calling no model.

## Why this is trustworthy

- **No live targets, no model calls.** The run manifest asserts `no_live_targets` and
  `no_model_calls`; cost is an explicit `0.0`.
- **Exercises the real components, not mocks.** Retrieval runs the real `KnowledgeRetriever`
  (FTS baseline) over a seeded KB; selection runs the real `ToolSelector` + `ProfilePolicy`;
  reporting runs the real `ReportingEngine`. The benchmark measures each component's real
  decision logic.
- **Honest about availability.** The real tool catalog is `requires_operator_configuration`
  until an operator installs the binaries, so it would select nothing in CI. The selection
  benchmark therefore measures the selector's *decision logic* on a controlled, **available**
  synthetic registry (built-in tools) — availability honesty is a separate, already-tested
  property. No decision code is mocked or stubbed.

## Evaluators (`core/benchmark/intelligence.py`)

### Retrieval quality — `evaluate_retrieval(k)`
Seeds a synthetic KB with a small labelled corpus (BOLA, SQLi, SSRF, XSS, SSTI write-ups),
runs the real FTS retriever for a set of labelled queries, and scores **rank-aware** metrics
per query via `retrieval_metrics`: precision@k, recall@k, reciprocal rank, average precision,
nDCG@k. The suite reports mean precision@k / recall@k, **MRR**, **mAP** and mean nDCG@k. When a
query has no relevant items the rank-aware measures are `None`, never coerced to 1.0.

### Tool-selection quality — `evaluate_tool_selection()`
Runs the real selector over labelled capability requests with a known-correct expected
selection, and reports per-case precision/recall/F1 and exact-match plus suite **accuracy**.
It verifies the deterministic policy's invariants as measured outcomes:

| Case | Expected |
|---|---|
| passive discovery | the PASSIVE tool is selected |
| safe probing | both available SAFE tools selected |
| redundant capability already covered | **deferred**, nothing re-selected |
| state-changing ACTIVE_CONTROLLED without approval | withheld |
| **RESTRICTED auto-selected** | **never selected** (safety) |
| RESTRICTED with operator approval, not auto | selected |

### Reporting quality — `evaluate_reporting()`
Builds a synthetic engagement with one sound validated finding, one validated finding whose
evidence is **tampered after validation**, and a scanner **candidate**, then runs the real
reporting engine and checks: the sound finding is the *only* confirmed one, the tampered
finding is excluded at report time, the candidate stays in the separate section, and SARIF
emits results for confirmed findings only.

## Metrics and the safety gate

`run_intelligence_suite()` returns the three evaluator results, a top-line `aggregate`
(`retrieval_map`, `retrieval_mrr`, `selection_accuracy`, `reporting_score`,
`safety_violations`, `all_safe`), a manifest and `cost`.

`compare_intelligence(baseline, candidate)` is the regression gate: a drop in any headline
metric is a regression, **and any safety violation in the candidate is a hard failure
regardless of the baseline**. A safety violation is a RESTRICTED tool auto-selected, or a
scanner candidate / tampered-evidence finding reaching a confirmed report section — exactly the
outcomes the Intelligence Layer's invariants forbid. The runnable script fails non-zero on a
safety violation even with no baseline.

## Running

```
python -m unittest tests.test_intelligence_benchmark            # the CI-safe suite
python scripts/run_intelligence_benchmark.py                    # full report
python scripts/run_intelligence_benchmark.py --out new.json --baseline old.json  # regression gate
```

## Tests

`tests/test_intelligence_benchmark.py` (15): rank-aware metric edge cases (perfect, undefined
when nothing is relevant, interleaved AP/nDCG, miss-outside-k); real FTS retrieval quality;
tool-selection accuracy with every policy invariant (RESTRICTED never auto-selected, operator
override, redundancy deferral, state-change approval); reporting confirmed-only / tampered-
excluded / candidate-separated; suite aggregate + manifest; and the gate (no self-regression, a
metric drop is a regression, a safety violation fails regardless of metrics).

## Limitations and follow-ups

- Retrieval is scored on the FTS baseline; when an embedding backend is configured, add a
  parallel semantic-retrieval score and compare the two.
- The corpus and case sets are small and synthetic — they rank decision logic within this
  fixture, not real-world effectiveness.
- Wire the real tool catalog through the Phase 5 workers so selection can also be scored
  end-to-end once binaries are operator-configured in a lab.
