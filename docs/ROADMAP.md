# Roadmap

## Phase 0 — Bootstrap (complete)
- [x] Repository layout, technical specification and Model 1 baseline
- [x] Hybrid architecture and safe default configuration
- [x] Initial agent and skill contracts

## Phase 1 — Deterministic core (implemented baseline)
- [x] Independent finding validation and evidence requirements
- [x] SQLite state store for engagements, tasks, agent runs, findings and audit events
- [x] Versioned, idempotent schema migrations
- [x] CI, Gitleaks hook configuration and schema examples
- [x] Workflow runner for plan validation, scope subsets, dependency gates and handoff persistence
- [x] Orchestrator contract wired to persisted task lifecycle
- [ ] Runtime integration test in a real Claude Code session
- [ ] Validate hook compatibility across supported operating systems
- [ ] Review agent frontmatter and permissions against Claude Code runtime behavior

## Phase 2 — Initial Web/API vertical
- [ ] Passive recon and enumeration workflows using supplied artifacts
- [ ] Vulnerability-specific analysis and independent validation loops
- [ ] Duplicate detection, evidence scoring and report generation from persisted findings

## Phase 3 — Other domains
- [ ] Mobile Android/iOS
- [ ] Cloud provider modules
- [ ] Active Directory / Windows
- [ ] Domain-specific lab tests

## Phase 4 — Runtime hardening
- [ ] Isolated execution container and network egress allowlisting
- [ ] Per-tool approval broker for explicitly authorized active tests
- [ ] Encrypted evidence store, redaction and retention controls
- [ ] Concurrency and resource budgets

## Phase 5 — Benchmark
- [ ] Fixed lab corpus with known ground truth
- [ ] Baseline Model 1 and hybrid runs
- [ ] Compare precision, recall, duplicate rate, time and cost
- [ ] Publish benchmark report

Do not label a release production-ready until runtime hardening and benchmark gates pass.
