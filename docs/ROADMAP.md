# Roadmap

## Phase 0 — Bootstrap (complete)
- [x] Repository layout and technical specification
- [x] Model 1 baseline preserved
- [x] Hybrid architecture documented
- [x] Safe default configuration
- [x] Initial agent and skill contracts
- [x] Finding schema and SQLite schema

## Phase 1 — Deterministic core (implemented baseline)
- [x] Enforce independent finding validation in Python
- [x] Require evidence references for validated/reported findings
- [x] SQLite state store for engagements, tasks, agent runs, findings, and audit events
- [x] Versioned, idempotent schema migration runner
- [x] CI for config validation, migrations, unit tests, and JSON contracts
- [x] Gitleaks pre-commit hook configuration
- [x] Validated handoff example
- [ ] Review agent frontmatter against Claude Code runtime behavior
- [ ] Differentiate agent permissions and completion criteria; consolidate redundant roles

## Phase 2 — Initial Web/API vertical
- [ ] Recon and enumeration workflows using supplied/authorized targets
- [ ] Skills: authentication, authorization/IDOR, XSS, SQLi, SSRF, OAuth/OIDC, JWT, business logic
- [ ] Independent validation workflow integrated with persisted findings
- [ ] Duplicate detection and evidence scoring

## Phase 3 — Other domains
- [ ] Mobile Android/iOS
- [ ] Cloud provider modules
- [ ] Active Directory / Windows
- [ ] Domain-specific lab tests

## Phase 4 — Runtime hardening
- [ ] Isolated execution container
- [ ] Network egress allowlisting outside the model
- [ ] Per-tool approval policy
- [ ] Secret redaction and encrypted evidence store
- [ ] Concurrency and resource budgets

## Phase 5 — Benchmark
- [ ] Fixed lab corpus with known ground truth
- [ ] Baseline Model 1 run
- [ ] Hybrid model run
- [ ] Compare precision, recall, duplicate rate, time, and cost
- [ ] Publish internal benchmark report

## Release policy
Do not label a release production-ready until runtime hardening and benchmark gates pass.
