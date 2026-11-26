# Implementation Status

Tracks the master-roadmap phases against the actual code. Statuses: `NOT_STARTED`,
`IN_PROGRESS`, `IMPLEMENTED`, `TESTED`, `BLOCKED`, `DEFERRED`. An item is `TESTED` only
with real test evidence. Phases map onto the repo's existing Gates 0–6 (see
[`AUTONOMOUS_PLATFORM_ROADMAP.md`](AUTONOMOUS_PLATFORM_ROADMAP.md)); see
[`ROADMAP_IMPLEMENTATION_AUDIT.md`](ROADMAP_IMPLEMENTATION_AUDIT.md) for the full audit.

| Phase | Item | Status | Files | Tests | CI | PR |
|---|---|---|---|---|---|---|
| 0 | Authentication Manager (OIDC crypto, Playwright login, broker transport) | TESTED | `core/auth/*` | `tests/test_oidc_validation.py`, `test_auth_broker_integration.py`, `test_playwright_auth_e2e.py`, `test_authentication_manager.py` | green on `main` | #25 (merged) |
| 0 | Close-out: session cross-engagement isolation test, secret-non-persistence test, expand `AUTHENTICATION_MANAGER.md` | NOT_STARTED | — | — | — | follow-up |
| — | Roadmap implementation audit | TESTED (docs) | `docs/ROADMAP_IMPLEMENTATION_AUDIT.md` | n/a | green | #26 (merged) |
| 1 | Browser Intelligence — normalization, capture, forms, coverage, scope, runner | TESTED | `core/browser/{models,routes,network,forms,coverage,scope,runner}.py` | `tests/test_browser_intelligence.py` (19 deterministic) | green (new PR) | this PR |
| 1 | Browser Intelligence — real Playwright driver | TESTED (local), skip-in-CI | `core/browser/playwright_driver.py` | `PlaywrightBrowserDriverE2ETests` (runs when a browser binary is present) | skipped unless browser present | this PR |
| 1 | Workflow execution of safe flows; in-browser JS bundle route extraction; surface persistence to store | NOT_STARTED | — | — | — | follow-up (PR C) |
| 2 | Attack Graph / Knowledge Graph — typed nodes/edges over SQLite, trust-tiered provenance, ingestion, path reasoning, query interface | TESTED | `core/graph/*`, `database/migrations/009_attack_graph.sql` | `tests/test_attack_graph.py` (20) | green (this PR) | this PR |
| 2 | Graph: findings/evidence lifecycle edges from validation engine; planner wiring | NOT_STARTED | — | — | — | follow-up |
| 3 | Adaptive Testing Planner — hypothesis lifecycle, evidence-driven candidates, deterministic policy, transparent scoring, bounded adaptive loop, observability | TESTED | `core/planner/*`, `database/migrations/010_adaptive_planner.sql` | `tests/test_adaptive_planner.py` (13) | green (this PR) | this PR |
| 3 | Planner: wire real executor through broker + Phase 4 validation | NOT_STARTED | — | — | — | follow-up |
| 4 | Exploit Validation Engine — deterministic oracles, independent dispositions, tamper-evident records, finding-lifecycle integration, safe retest, reporting | TESTED | `core/validation_engine/*`, `database/migrations/011_validation_records.sql` | `tests/test_exploit_validation.py` (18) | green (this PR) | this PR |
| 4 | Validation: wire planner executor to the engine; more oracles (SSRF/open-redirect); graph VALIDATED_BY edges | NOT_STARTED | — | — | — | follow-up |
| 5 | Isolated Execution Workers — tool registry, bounded subprocess backend, hardened container backend, worker manager (isolation/limits/observability/cleanup) | TESTED (orchestration + portable backend) | `core/workers/*`, `database/migrations/012_worker_executions.sql` | `tests/test_isolated_workers.py` (15) | green (this PR) | this PR |
| 5 | Concrete container runtime + CI with Docker; host egress/DNS enforcement; mid-run cancellation | NOT_STARTED | — | — | — | follow-up (container runtime isolation not exercised in CI) |
| 6 | Benchmark & Regression Lab — deterministic CI-safe harness over the real graph→planner→validation pipeline; precision/recall/F1/coverage/cost; reproducibility; regression gate | TESTED | `core/benchmark/*`, `scripts/run_regression_benchmark.py` | `tests/test_benchmark_regression.py` (10) | green (this PR) | this PR |
| 6 | Real-agent benchmark (gated) + external benchmark (XBEN) integration | IN_PROGRESS / NOT_STARTED | `scripts/run_benchmark.py`, `scripts/evaluate_benchmark.py` | `tests/test_benchmark*.py` | gated behind `CLAUDE_BENCHMARK_MODEL` | follow-up |

## Notes
- "green on `main`" / "green (new PR)" refers to the CI `test` job; the `agent-benchmark`
  job is intentionally gated behind the `CLAUDE_BENCHMARK_MODEL` repo variable and is
  reported as skipped, never as passed.
- No phase is marked complete before its roadmap exit criteria are met. Phase 1's
  foundation meets its core exit criterion (discover and describe a synthetic modern app
  through controlled browser interaction, with reproducible results and no scope
  violations); the follow-up items above extend it.

## Intelligence Layer program (Roadmap 2)

See [`INTELLIGENCE_LAYER_AUDIT.md`](INTELLIGENCE_LAYER_AUDIT.md). Components A–H, each a focused PR.

| Component | Item | Status | Files | Tests | CI | PR |
|---|---|---|---|---|---|---|
| — | Intelligence layer audit | TESTED (docs) | `docs/INTELLIGENCE_LAYER_AUDIT.md` | n/a | green | #33 (merged) |
| A | Knowledge Intelligence / RAG — multi-format ingestion, taxonomy (CWE/CVE/OWASP/CAPEC/ATT&CK), FTS retrieval baseline + embedding seam + contextual per-agent retrieval | TESTED | `core/knowledge/*` | `tests/test_knowledge_intelligence.py` (17) | green (this PR) | this PR |
| B | Knowledge Graph integration (KB↔graph bridge, provenance, trust tiers) | NOT_STARTED | — | — | — | next |
| C | Validated Experience Memory | NOT_STARTED | — | — | — | — |
| D | Tool Registry extension (profiles/adapters/parsers over Phase 5 registry) | NOT_STARTED | — | — | — | — |
| E | Initial tool adapters | NOT_STARTED | — | — | — | — |
| F | Agent-to-tool selection + normalized observations | NOT_STARTED | — | — | — | — |
| G | Reporting engine (templates, MD/HTML/PDF/SARIF/JSON, evidence package, Nessus import) | NOT_STARTED | — | — | — | — |
| H | Intelligence-layer benchmarking (retrieval/tool-selection/report metrics) | NOT_STARTED | — | — | — | — |
