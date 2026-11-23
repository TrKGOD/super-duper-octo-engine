# Roadmap

## Phase 0 — Bootstrap (current)
- [x] Repository layout and technical specification
- [x] Model 1 baseline preserved
- [x] Hybrid architecture documented
- [x] Safe default configuration
- [x] Initial agent and skill contracts
- [x] Finding schema and SQLite schema
- [x] Basic validation tests

## Phase 1 — Core contracts
- [ ] Validate agent frontmatter against Claude Code behavior
- [ ] Finalize handoff JSON schema and examples
- [ ] Implement engagement/task state manager
- [ ] Add migrations and repository layer
- [ ] Add audit event writer

## Phase 2 — Initial Web/API vertical
- [ ] Recon and enumeration workflows using supplied/authorized targets
- [ ] Skills: authentication, authorization/IDOR, XSS, SQLi, SSRF, OAuth/OIDC, JWT, business logic
- [ ] Independent validation workflow
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
