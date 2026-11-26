# Changelog

## Unreleased
- Added intelligence-layer benchmarking (`core/benchmark/intelligence.py`, rank-aware metrics
  in `core/benchmark/metrics.py`, `scripts/run_intelligence_benchmark.py`) — Intelligence Layer
  Component H: deterministic, CI-safe evaluators that run the **real** retriever, tool selector +
  profile policy, and reporting engine on synthetic data and score retrieval quality
  (precision@k/recall@k/MRR/mAP/nDCG), tool-selection accuracy with the policy invariants as
  measured outcomes (RESTRICTED never auto-selected, redundancy deferral, state-change approval),
  and reporting quality (confirmed-only, tampered evidence excluded, candidates kept separate).
  A regression gate flags any headline-metric drop and **fails hard on any safety violation**
  regardless of baseline. No live targets, no model calls, cost 0.0; availability honesty is
  preserved (the real catalog stays operator-configured, so selection logic is measured on a
  controlled available registry). Lab-verified by `tests/test_intelligence_benchmark.py`.
  Completes Roadmap 2 (Intelligence Layer, Components A–H).
- Added the reporting engine (`core/reporting/*`) and Nessus import — Intelligence Layer
  Component G: versioned templates (executive/technical/attack-surface/tool-execution/
  evidence-package) rendered to Markdown/HTML/JSON/SARIF, built over a `ReportContext` that
  reuses the existing validated-findings gate and evidence vault. Only independently validated
  findings whose evidence integrity is **re-verified at report time** appear in confirmed
  sections (tampered/missing evidence is excluded, not downgraded silently); unvalidated findings
  and scanner candidates are kept separate and never presented as confirmed, and SARIF emits
  results for confirmed findings only. PDF is produced by printing the HTML — no renderer is
  faked. Adds `import_nessus` to the evidence adapters (requires redaction; items land as
  hypotheses, never validated). Lab-verified by `tests/test_reporting_engine.py`.
- Added agent-to-tool intelligence and the normalized observation model
  (`core/tools/selection.py`, `core/tools/observations.py`, migration
  `013_tool_observations.sql`) — Intelligence Layer Component F: capability-based deterministic
  tool selection (authorized, available, non-redundant; RESTRICTED never auto-selected), and a
  single observation schema with explicit dispositions (DETECTED/CANDIDATE/SUPPORTED/REFUTED/
  INCONCLUSIVE/ERROR) traceable to tool/task/engagement/execution, secret-redacted, and
  correlated into the graph as observed structure (candidates stay leads, never confirmed
  findings or authorization). Lab-verified by `tests/test_observations_selection.py`.
- Added the initial tool adapters (`core/tools/parsers.py`, `core/tools/catalog.py`) —
  Intelligence Layer Component E: real adapters for subfinder/dnsx/httpx/katana/ffuf/nuclei/
  dalfox with real, tested output parsers (nuclei/dalfox results marked CANDIDATE, never
  confirmed), correct execution profiles, and honest availability — binaries are not bundled,
  so each reports `requires_operator_configuration` until installed. No fake integrations; the
  end-to-end path is proven through the Phase 5 broker with a synthetic stand-in. Lab-verified
  by `tests/test_tool_adapters.py`.
- Added the Tool Registry & Adapter Framework (`core/tools/`) — Intelligence Layer Component D:
  an extended ToolDefinition/registry over the Phase 5 worker ToolSpec (capabilities,
  vulnerability classes, honest availability), the four execution profiles
  (PASSIVE/SAFE/ACTIVE_CONTROLLED/RESTRICTED) with a deterministic policy (RESTRICTED never
  auto-selected; approvals for state-changing/restricted), and a brokered adapter contract
  that executes tools only through the Phase 5 worker broker — no raw shell, no bypass. Lab-
  verified by `tests/test_tool_registry.py`.
- Added Validated Experience Memory (`core/experience/`) — Intelligence Layer Component C: a
  dedicated, reusable-across-engagements store whose promotion gate accepts **only**
  independently validated findings (a SUPPORTED Phase 4 validation record) — never a
  hypothesis, refuted or inconclusive test. Records are sanitized (secrets redacted; evidence
  by reference id only), retrieval is similarity-based and advisory (past success is not
  evidence and not authorization), with versioning/confidence-recalculation/deprecation. Lab-
  verified by `tests/test_experience_memory.py`.
- Added Knowledge Graph integration (`core/knowledge/graph_bridge.py`) — Intelligence Layer
  Component B: projects KB patterns and their CWE/CVE/OWASP/CAPEC/ATT&CK references into the
  existing engagement attack graph as inferred knowledge nodes/edges with provenance, plus
  graph-assisted queries (patterns for an endpoint/technology/class, tools for a class,
  weaknesses of a pattern). Extends `core/graph/schema.py` with knowledge node/edge types; the
  authorization trust boundary is preserved — KB content can never create identities, roles,
  permissions or authorization edges (tested). Lab-verified by
  `tests/test_knowledge_graph_integration.py`.
- Added Knowledge Intelligence / RAG (`core/knowledge/`) — Intelligence Layer Component A:
  multi-format KB ingestion (HTML/JSON/JSONL/XML, with safe tag-stripping — no XXE), taxonomy
  reference extraction (CWE/CVE/OWASP/CAPEC/ATT&CK), and a retrieval API with an always-
  functional FTS baseline, an optional embedding seam, and per-agent contextual retrieval.
  Extends the existing KB (provenance, dedup, untrusted-content handling) rather than
  replacing it; retrieval provides knowledge, never authorization. Lab-verified by
  `tests/test_knowledge_intelligence.py`.
- Added the Benchmark & Regression Lab (`core/benchmark/`, `scripts/run_regression_benchmark.py`):
  a deterministic, CI-safe harness that runs synthetic scenarios through the real
  graph→planner→validation pipeline and reports precision/recall/F1, endpoint coverage,
  validated-finding counts, runtime and (synthetic) cost, with a reproducible run manifest
  and a regression-comparison gate. Contacts no live target and calls no model; the
  real-agent benchmark stays separate and gated. Lab-verified by
  `tests/test_benchmark_regression.py`.
- Added Isolated Execution Workers (`core/workers/`, migration `012_worker_executions.sql`):
  a tool registry with injection-safe argument validation, a portable bounded subprocess
  backend (timeout/output/POSIX-rlimit bounds — explicitly not a sandbox), a hardened
  container backend (read-only, cap-drop, no-new-privileges, pids/memory/cpu limits, no
  privileged, no docker socket), and a worker manager with per-engagement artifact
  isolation, resource budgets, observability and cleanup. Lab-verified by
  `tests/test_isolated_workers.py`; see docs/ISOLATED_EXECUTION.md for the threat model.
- Renamed the project to **Witherhoard** (was "Pentest Agent Framework" / "Hackbot"),
  including the GitHub repository (`super-duper-octo-engine` → `witherhoard`).
- Added the Exploit Validation Engine (`core/validation_engine/`, migration
  `011_validation_records.sql`): deterministic oracles that map evidence to SUPPORTED/
  REFUTED/INCONCLUSIVE independently of the proposer, tamper-evident validation records,
  finding-lifecycle integration over the existing state machine, safe retesting
  (FIX_VERIFIED/STILL_PRESENT, no unapproved state-changing retest), and confirmed-only
  reporting. Lab-verified by `tests/test_exploit_validation.py`.
- Added the Adaptive Testing Planner (`core/planner/`, migration `010_adaptive_planner.sql`):
  typed hypothesis lifecycle, evidence-driven candidate generation from the attack graph,
  a deterministic policy layer that gates scope/identity/test-class/state-change (an LLM
  proposal cannot widen authorization), transparent prioritization scoring, a bounded
  adaptive loop whose results change subsequent selection, and per-decision observability.
  Lab-verified by `tests/test_adaptive_planner.py`.
- Added the Attack / Knowledge Graph (`core/graph/`, migration `009_attack_graph.sql`):
  engagement-scoped typed nodes/edges over SQLite with trust-tiered provenance, a control-
  plane-only authorization boundary (untrusted data cannot grant authorization or invent
  identities), Browser-report ingestion, BOLA/BFLA attack-path reasoning, and a planner
  query interface. Lab-verified by `tests/test_attack_graph.py`.
- Added the Browser Intelligence Engine (`core/browser/`): scope-bounded SPA route,
  network and form discovery with normalization/deduplication, coverage accounting,
  secret-safe capture, human-challenge pause, and an injectable driver with an optional
  Playwright backend. Lab-verified by `tests/test_browser_intelligence.py`.
- Added `docs/BROWSER_INTELLIGENCE.md`, `docs/IMPLEMENTATION_STATUS.md` and
  `docs/ROADMAP_IMPLEMENTATION_AUDIT.md` (roadmap audit and phase/capability status).

## 0.1.0 — Bootstrap
- Added hybrid architecture specification.
- Preserved Model 1 baseline.
- Added Claude Code agent, skill, and command scaffolds.
- Added default-deny engagement configuration and Bash tripwire.
- Added SQLite schema, finding/handoff schemas, and bootstrap tests.
