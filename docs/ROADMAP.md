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
- [x] Bounded one-task Claude Code specialist dispatch with validated persisted handoff (tools disabled)
- [x] Sequential dependency-aware multi-specialist plan runner with persisted handoffs
- [x] LLM-assisted passive plan generation with exact-scope validation and deterministic sequential dispatch
- [ ] Native Claude Task-tool delegation with live subagent handoffs and runtime permission verification
- [x] Add bounded single-specialist Claude Code runtime smoke harness (real credentials/runtime execution still required)
- [x] Correct benchmark CLI prompt transport and reject incomplete positive fixtures
- [x] Benchmark CLI prompt transport via stdin and positive-fixture completeness checks
- [x] Per-case duration and available Claude CLI usage/cost metadata capture
- [ ] Validate hook compatibility across supported operating systems
- [ ] Review agent frontmatter and permissions against Claude Code runtime behavior
- [x] Runtime Skill context selection from registry by task domain, tags and compatible agent
- [ ] Verify actual Claude Code orchestrator/planner and specialist invocations with configured credentials
- [ ] Verify native Task-tool delegation and dynamic Skill loading in a real Claude Code session

## Phase 2 — Initial Web/API vertical
- [x] Program policy reader for operator-supplied bug bounty text with quoted provenance and ambiguity flags
- [ ] Passive recon and enumeration workflows using supplied artifacts
- [ ] Formal Web/API vulnerability-specific task templates and independent validation loops (specialist dispatch is generic; finding lifecycle remains operator-mediated)
- [x] Non-destructive duplicate candidate detection from persisted findings
- [x] Evidence-readiness scoring with explicit non-validity semantics
- [x] Deterministic report renderer limited to validated/reported findings with fresh evidence integrity checks

## Phase 3 — Other domains
- [x] Passive plan templates for Mobile Android/iOS, Cloud and Active Directory/Windows (supplied artifacts only)
- [ ] Domain-specific artifact parsers, vulnerability workflows and lab validation for Mobile Android/iOS
- [ ] Cloud provider modules with provider-specific evidence schemas
- [ ] Active Directory / Windows modules with directory-export normalization and lab validation
- [ ] Domain-specific lab tests

## Phase 4 — Runtime hardening
- [ ] Isolated execution container and network egress allowlisting
- [ ] Runtime permission broker and auditable operator approval for any future active-test tool
- [ ] Per-tool approval broker for explicitly authorized active tests
- [x] Best-effort text redaction helper with mandatory manual review
- [x] Optional AES-256-GCM evidence encryption with external key and ciphertext integrity checks
- [ ] KMS integration, key rotation/multi-key support, automated redaction review and retention/deletion controls
- [ ] Concurrency and resource budgets

## Phase 5 — Benchmark
- [ ] Expand fixed lab corpus with known ground truth, including adversarial/prompt-injection cases
- [x] Require complete fixture payloads for positive cases
- [x] Fixed Model 1 and hybrid specialist pipeline simulation plans
- [x] Same-corpus/model guard and comparison of precision, recall, F1, false-positive rate, evidence completeness, time and cost
- [ ] Execute repeated real Claude runs and publish variance-aware comparison report
- [ ] Publish benchmark report

Do not label a release production-ready until runtime hardening and benchmark gates pass.
