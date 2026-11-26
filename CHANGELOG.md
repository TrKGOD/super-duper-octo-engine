# Changelog

## Unreleased
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
