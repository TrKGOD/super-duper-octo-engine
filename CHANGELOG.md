# Changelog

## Unreleased
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
