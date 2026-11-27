# Implementation Status

Tracks the master-roadmap phases against the actual code. Statuses: `NOT_STARTED`,
`IN_PROGRESS`, `IMPLEMENTED`, `TESTED`, `BLOCKED`, `DEFERRED`. An item is `TESTED` only
with real test evidence. Phases map onto the repo's existing Gates 0–6 (see
[`AUTONOMOUS_PLATFORM_ROADMAP.md`](AUTONOMOUS_PLATFORM_ROADMAP.md)); see
[`ROADMAP_IMPLEMENTATION_AUDIT.md`](ROADMAP_IMPLEMENTATION_AUDIT.md) for the full audit.

| Phase | Item | Status | Files | Tests | CI | PR |
|---|---|---|---|---|---|---|
| 0 | Authentication Manager (OIDC crypto, Playwright login, broker transport) | TESTED | `core/auth/*` | `tests/test_oidc_validation.py`, `test_auth_broker_integration.py`, `test_playwright_auth_e2e.py`, `test_authentication_manager.py` | green on `main` | #25 (merged) |
| 0 | Close-out: session cross-engagement isolation test, secret-non-persistence test, expand `AUTHENTICATION_MANAGER.md` | TESTED | `core/auth/*`, `docs/AUTHENTICATION_MANAGER.md` | `tests/test_auth_hardening.py` | revalidation branch (not yet on `main`) | revalidation branch |
| — | Roadmap implementation audit | TESTED (docs) | `docs/ROADMAP_IMPLEMENTATION_AUDIT.md` | n/a | green | #26 (merged) |
| 1 | Browser Intelligence — normalization, capture, forms, coverage, scope, runner | TESTED | `core/browser/{models,routes,network,forms,coverage,scope,runner}.py` | `tests/test_browser_intelligence.py` (19 deterministic) | green (new PR) | this PR |
| 1 | Browser Intelligence — real Playwright driver | TESTED (local), skip-in-CI | `core/browser/playwright_driver.py` | `PlaywrightBrowserDriverE2ETests` (runs when a browser binary is present) | skipped unless browser present | this PR |
| 1 | Workflow execution of safe flows; in-browser JS bundle route extraction; surface persistence to store | NOT_STARTED | — | — | — | follow-up (PR C) |
| 2 | Attack Graph / Knowledge Graph — typed nodes/edges over SQLite, trust-tiered provenance, ingestion, path reasoning, query interface | TESTED | `core/graph/*`, `database/migrations/009_attack_graph.sql` | `tests/test_attack_graph.py` (20) | green (this PR) | this PR |
| 2 | Graph: findings/evidence lifecycle edges from validation engine; planner wiring | TESTED | `core/pipeline/`, `core/graph/{store,ingest}.py` | `tests/test_pipeline_e2e.py`, `tests/test_graph_trust_merge.py` | revalidation branch | revalidation branch |
| 3 | Adaptive Testing Planner — hypothesis lifecycle, evidence-driven candidates, deterministic policy, transparent scoring, bounded adaptive loop, observability | TESTED | `core/planner/*`, `database/migrations/010_adaptive_planner.sql` | `tests/test_adaptive_planner.py` (13) | green (this PR) | this PR |
| 3 | Planner: wire real executor through broker + Phase 4 validation | TESTED (object-level and function-level authorization only; other classes are recorded as not executed) | `core/pipeline/`, `core/planner/loop.py` | `tests/test_pipeline_e2e.py`, `tests/test_planner_robustness.py`, `tests/test_pipeline_metrics.py` | revalidation branch | revalidation branch |
| 4 | Exploit Validation Engine — deterministic oracles, independent dispositions, tamper-evident records, finding-lifecycle integration, safe retest, reporting | TESTED | `core/validation_engine/*`, `database/migrations/011_validation_records.sql` | `tests/test_exploit_validation.py` (18) | green (this PR) | this PR |
| 4 | Validation: wire planner executor to the engine; graph VALIDATED_BY edges | TESTED | `core/validation_engine/*`, `core/pipeline/` | `tests/test_validation_evidence_chain.py`, `tests/test_pipeline_e2e.py` | revalidation branch | revalidation branch |
| 4 | Validation: more oracles (SSRF, open redirect) | NOT_STARTED — deliberately not implemented; SSRF hypotheses are generated and recorded as not executed | — | — | — | — |
| 5 | Isolated Execution Workers — tool registry, bounded subprocess backend, hardened container backend, worker manager (isolation/limits/observability/cleanup) | TESTED (orchestration + portable backend) | `core/workers/*`, `database/migrations/012_worker_executions.sql` | `tests/test_isolated_workers.py` (15) | green (this PR) | this PR |
| 5 | Mid-run cancellation, tree termination, fail-closed container backend, container lifecycle (against a fake runtime) | TESTED | `core/workers/*` | `tests/test_worker_hardening.py` (49) | revalidation branch | revalidation branch |
| 5 | Container isolation on a real runtime (non-root, no capabilities, read-only root, no network, cgroup limits, kill-and-remove) | TESTED in CI on one runtime (Docker 28.0.4, cgroup v2); not runnable on the development machine | `core/workers/backends.py` | `tests/test_container_integration.py` (14, gated by `WITHERHOARD_CONTAINER_TESTS=1`) | `container-isolation` green on its first run | PR #42 |
| 5 | Host egress / DNS enforcement | IMPLEMENTED (ruleset renderer) — never applied to a host | `core/netpolicy.render_egress_firewall` | rendering only | — | follow-up |
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
| B | Knowledge Graph integration — KB patterns→graph as inferred knowledge nodes/edges, provenance, graph-assisted queries, authorization boundary preserved | TESTED | `core/knowledge/graph_bridge.py`, `core/graph/schema.py` (knowledge types) | `tests/test_knowledge_graph_integration.py` (6) | green (this PR) | this PR |
| C | Validated Experience Memory — promotion gate (only validation-confirmed findings), sanitized records (no secrets), similarity retrieval, versioning/deprecation | TESTED | `core/experience/*` (dedicated reusable store) | `tests/test_experience_memory.py` (9) | green (this PR) | this PR |
| D | Tool Registry & Adapter Framework — extended ToolDefinition/registry over Phase 5 ToolSpec, four execution profiles + policy (RESTRICTED never auto-selected), brokered adapter contract, honest availability | TESTED | `core/tools/*` | `tests/test_tool_registry.py` (14) | green (this PR) | this PR |
| E | Initial tool adapters — real catalog (subfinder/dnsx/httpx/katana/ffuf/nuclei/dalfox) with real tested parsers, correct profiles, and honest availability (binaries not bundled) | TESTED (adapters+parsers; binaries require operator config) | `core/tools/{parsers,catalog}.py` | `tests/test_tool_adapters.py` (12) | green (this PR) | this PR |
| F | Agent-to-tool capability requests + deterministic selection (non-redundant, RESTRICTED never auto-selected) + normalized observation model (migration 013) with dispositions, correlated into the graph | TESTED | `core/tools/{selection,observations}.py`, `database/migrations/013_tool_observations.sql` | `tests/test_observations_selection.py` (7) | green (this PR) | this PR |
| G | Reporting engine — versioned templates (executive/technical/attack-surface/tool-execution/evidence-package), renderers (Markdown/HTML/JSON/SARIF; PDF via printed HTML), confirmed-only gate with report-time evidence integrity re-verification, Nessus import (hypotheses only) | TESTED | `core/reporting/*`, `core/evidence_adapters.py` (Nessus) | `tests/test_reporting_engine.py` (9) | green (this PR) | this PR |
| H | Intelligence-layer benchmarking — rank-aware retrieval metrics (precision@k/recall@k/MRR/mAP/nDCG), tool-selection accuracy with policy-invariant checks, reporting confirmed-only/integrity checks, safety-aware regression gate; runs the real retriever/selector/reporting engine on synthetic data | TESTED | `core/benchmark/{intelligence,metrics}.py`, `scripts/run_intelligence_benchmark.py` | `tests/test_intelligence_benchmark.py` (15) | green (this PR) | this PR |

## Revalidation program (branch `feature/architecture-revalidation`)

Full register, verification basis and limitations: [`REVALIDATION_STATUS.md`](REVALIDATION_STATUS.md).
"Tested" means passing on the development machine (Windows, Python 3.13); the Linux and
multi-version CI jobs defined on this branch have **not yet run**.

| Item | Status | Files | Tests |
|---|---|---|---|
| Unified pipeline: observation → hypothesis → policy → tool → broker → evidence → validation → graph/coverage → next cycle | TESTED (two authorization classes) | `core/pipeline/*` | `tests/test_pipeline_e2e.py` (9), `tests/test_pipeline_metrics.py` (4) |
| Execution ledger, crash reconciliation, evidence↔execution link | TESTED | `core/execution_ledger.py`, migration `014` | `tests/test_execution_ledger.py` (28) |
| Migration runner: checksums, gaps, staged upgrade, upgrade with historical data | TESTED | `scripts/migrate.py` | `tests/test_migrations.py` (10) |
| Destination policy, redirects, DNS pinning, multipart framing | TESTED | `core/netpolicy.py`, `core/active_executor.py` | `tests/test_netpolicy.py` (17), `tests/test_broker_hardening.py` (12) |
| Central redaction; path/link/junction confinement | TESTED | `core/redaction.py`, `core/pathsafe.py` | `tests/test_redaction.py` (15), `tests/test_pathsafe.py` (7) |
| Authentication hardening, vault rotation, browser-login guards | TESTED | `core/auth/*`, `scripts/auth.py` | `tests/test_auth_hardening.py` (28) |
| Verified-evidence validation chain; retest refusal without vault evidence | TESTED | `core/validation_engine/*` | `tests/test_validation_evidence_chain.py` (27) |
| Planner robustness: failure containment, crash recovery, change-driven retry, honest coverage | TESTED | `core/planner/*` | `tests/test_planner_robustness.py` (14) |
| Graph trust merge (weaker trust cannot overwrite stronger) | TESTED | `core/graph/*` | `tests/test_graph_trust_merge.py` (6) |
| Experience memory: promotion ticket, proposals as leads | TESTED | `core/experience/*` | `tests/test_experience_proposals.py` (10), `tests/test_experience_memory.py` (9) |
| Report depth and honesty (scope, methodology, coverage, unresolved hypotheses, limitations) | TESTED | `core/reporting/*` | `tests/test_report_depth.py` (8) |
| KB ingestion bounds, atomic ingest, untrusted semantic retrieval, feed discovery | TESTED | `core/knowledge/*`, `scripts/kb_sources.py` | `tests/test_kb_ingestion_safety.py` (26), `tests/test_kb_sources.py` (10) |
| Skill version + content-hash pinning; agent contracts validated against code | TESTED | `.claude/skills/registry.json`, `config/agent-contracts.json`, `scripts/validate_agent_contracts.py` | `tests/test_agent_contracts.py` (17: 12 contract checks + 5 skill-pinning checks), `tests/test_skill_registry.py` (8) |
| Worker hardening (tree kill, cancel, flood, fail-closed container backend, relative process limit) | TESTED against a fake runtime | `core/workers/*` | `tests/test_worker_hardening.py` (49) |
| Command-guard hook: junction-aware link checks (self-contained, pinned to `core.pathsafe`) | TESTED | `hooks/command_guard.py` | `tests/test_command_guard.py` (17) |
| Shared helpers: executable lookup, child encoding, request-manifest loader, evidence check/use race | TESTED | `core/runtime.py`, `core/manifests.py`, `core/evidence.py` | `tests/test_runtime.py` (10), `tests/test_manifests.py` (8), `tests/test_evidence.py` (6) |
| Container isolation on a real runtime | TESTED in CI (Docker 28.0.4, cgroup v2) | `tests/test_container_integration.py` (2 always run, 14 gated) | `container-isolation` CI job |
| CI: Windows and Python 3.11–3.13 matrix, agent-contract check, advisory `pip-audit` | TESTED on Linux (3.11 `test`, 3.12/3.13 `compatibility`: 730 tests); Windows matrix pending at the time of writing | `.github/workflows/ci.yml` | first run on PR #42 |
| Pipeline executors that send SQLi / XSS / SSRF tests, and an SSRF oracle | NOT_STARTED — deliberately not implemented. (The SQLi and reflected-XSS *oracles* pre-exist and judge evidence they are given; no executor in the pipeline produces that evidence, so those hypotheses stay `INCONCLUSIVE`, counted as not executed. The operator-driven `scripts/active_ssrf_probe.py` analyzer also pre-exists and is not wired into the pipeline or the validation engine.) | — | — |
