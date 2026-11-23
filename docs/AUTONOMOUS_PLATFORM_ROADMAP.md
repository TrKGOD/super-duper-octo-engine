# Autonomous Pentest Platform — Execution Roadmap

This roadmap turns the platform objective into independently verifiable engineering milestones. It is deliberately capability-based: agent prompts, Skill files, deterministic unit tests and real target-testing capability are different maturity levels and must never be conflated.

## Architecture invariants

- Preserve **Model 1** as an immutable comparison baseline: Recon → Enumeration → Vulnerability Discovery → Exploitation Analysis → Validation → Reporting.
- Develop the hybrid architecture separately; do not silently replace or mutate the baseline.
- Keep scope, engagement authorization, execution policy and broker enforcement outside LLM control.
- Treat target responses, imported research, code comments, files and tool output as untrusted data, never instructions.
- Every finding must have traceable evidence; hypotheses and candidates are not confirmed vulnerabilities.
- Framework QA and CI remain separate from pentest tasks. The Orchestrator must never stop a live assessment to run framework self-tests.
- Do not grant an agent general-purpose shell or unrestricted network access as a shortcut.

## Delivery gates

### Gate 0 — Measurement baseline (in progress)
**Deliverables**
- Expand the synthetic benchmark across Web/API, OAuth/OIDC, mobile, cloud and Active Directory.
- Keep positive and negative cases balanced where possible and require explicit evidence fields.
- Run the same pinned model, agent prompt, corpus hash and timeout across comparisons.
- Report precision, recall, F1, false-positive rate, evidence completeness, latency and available cost metadata.
- Preserve raw predictions and run manifests for reproducibility.

**Acceptance**
- Every case has a unique ID, synthetic provenance, expected label, evidence contract and meaningful false-positive rationale.
- No benchmark result is described as real-world effectiveness.
- Model 1 and hybrid comparisons use identical corpus and model hashes; repeat runs report variance.

### Gate 1 — Adaptive orchestration
**Deliverables**
- Add a bounded investigation cycle: observe → hypothesize → choose next action → execute specialist task → inspect evidence → continue/stop.
- Permit specialists to propose typed follow-up tasks, not arbitrary shell commands or network actions.
- Validate every proposed task against agent allowlists, domain/Skill registry, dependency graph, exact engagement scope, active approval and execution policy before persistence.
- Add loop budgets, per-engagement task limits, duplicate-action detection, maximum investigation depth and explicit stop reasons.
- Resume interrupted work from persisted state; do not silently replay active tasks or pinned request IDs.
- Keep parallel execution behind explicit resource leases and broker concurrency controls.

**Acceptance**
- Synthetic tests prove valid follow-ups are queued, invalid scope/agent/method requests are rejected, cycles and repeated tasks are bounded, and independent DAG branches continue.
- A failed or inconclusive branch does not block unrelated work.
- The LLM cannot approve engagements, broaden scope, change manifests or bypass broker policy.
- Until native Task delegation and its runtime behavior are tested, describe execution as validated adaptive dispatch, not native autonomous subagent delegation.

### Gate 2 — Web/API investigation depth
**Deliverables**
- Contextual vulnerability hypotheses from observed application behavior, route/parameter/JS evidence, authentication state and business-object relationships.
- Brokered, read-only or synthetic-data test modules for authorization, authentication, OAuth/OIDC, JWT policy, SSRF and SQLi.
- Browser automation isolated behind the same engagement/task policy, with scoped navigation and request interception.
- Correlate browser actions with HTTP evidence and application routes.
- Separate passive artifact analyzers from active executors and independent validators.

**Acceptance**
- Each active module has positive, negative and blocked-path lab tests.
- Active execution uses synthetic identities/data, exact scope, approved manifests or explicitly defined bounded discovery, request ceilings and evidence capture.
- No SQLi data extraction, destructive query, blind resource exhaustion, credential attack, cache poisoning or unbounded race traffic.
- OAuth/JWT candidates require policy-aware cryptographic validation before confirmation; parsing claims is not signature verification.

### Gate 3 — Execution isolation and secrets
**Deliverables**
- Per-engagement isolated process/container and filesystem boundaries.
- Network egress allowlisting enforced outside the LLM and application process.
- Secret broker with scoped references, least privilege, rotation and redaction.
- CPU, memory, process, wall-clock, request and output quotas.
- Crash/restart reconciliation for task state, evidence and request logs.
- Evidence retention, deletion, integrity verification and operator export controls.

**Acceptance**
- Escape, symlink, cross-engagement read/write, secret leakage, DNS rebinding, redirect, egress and resource exhaustion tests fail closed.
- Pause/kill switch blocks new active work and records audit events.
- Document explicitly that the HTTP broker and command guard alone are not a sandbox.

### Gate 4 — Knowledge and investigation memory
**Deliverables**
- Context-aware retrieval by asset technology, feature, trust boundary, vulnerability hypothesis and evidence state.
- Source provenance, disclosure/license status, freshness, confidence and analyst review.
- Pattern deduplication and retrieval-quality benchmark.
- Engagement-local investigation memory that stores observations and decisions without leaking data across clients.
- Prompt-injection-resistant ingestion and retrieval.

**Acceptance**
- KB references never count as current-target evidence.
- Every retrieved pattern has source provenance and an explicit untrusted-data boundary.
- Cross-engagement isolation tests prevent retrieval of another client's artifacts or secrets.

### Gate 5 — Mobile, Cloud and Active Directory execution
**Deliverables**
- Mobile: Android/iOS static and dynamic lab workflows, storage, IPC/deep links, network trust, platform permissions and API correlation.
- Cloud: provider-specific IAM, storage, workload identity, metadata boundaries and configuration analysis.
- Active Directory: LDAP/Kerberos inventory, effective ACL analysis, AD CS and delegation review, with lab-only validation of privilege paths.
- Shared scope, evidence, audit and independent-validation contracts.

**Acceptance**
- Each domain has intentionally vulnerable local/lab targets, safe positive/negative fixtures and broker or tool adapters with explicit allowlists.
- Skills and agent descriptions alone do not qualify as implementation.
- No credential dumping, persistence, stealth/evasion, uncontrolled lateral movement or testing of third-party tenants.

### Gate 6 — Impact, deduplication and reporting
**Deliverables**
- Impact assessment tied to validated technical evidence and affected business capability.
- Cross-endpoint/root-cause deduplication without deleting source findings.
- Reproducible report with asset, preconditions, steps, evidence, severity rationale, impact and remediation.
- Separate confirmed findings, candidates, rejected hypotheses and coverage gaps.

**Acceptance**
- Report generation consumes only persisted validated findings in the confirmed section.
- Evidence hashes are re-verified at report time.
- Unsupported severity, impact and exploit claims are rejected or explicitly qualified.

## Benchmark protocol

For every model/architecture comparison, pin:
- model identifier and relevant model settings;
- agent prompt hashes;
- Skill registry and selected Skill hashes;
- benchmark corpus hash;
- runtime/CLI version;
- timeout and tool permissions;
- number of repetitions.

Report per-class and aggregate precision/recall/F1, false-positive rate, evidence completeness, latency and available cost. Include confidence intervals or run-to-run variance when the sample size permits. Never compare results from different corpus/model hashes as if they were controlled.

## Immediate next sequence

1. Complete and run Gate 0 on the expanded corpus.
2. Implement Gate 1 as a bounded, typed follow-up queue layered over persisted DAG tasks; keep Model 1 unchanged.
3. Build a local intentionally vulnerable Web/API lab and prove discovery → reproduction → independent validation → report.
4. Add brokered OAuth/JWT and SQLi validation only after synthetic manifests, cryptographic verification strategy and negative-path controls are designed.
5. Add browser, container/egress and secret isolation before expanding active tool surface.
6. Implement Mobile, Cloud and Active Directory as separate domain adapters with lab acceptance tests.
7. Expand KB and reporting based on observed investigation failures and validated finding requirements.

## Status vocabulary

- `documented`: methodology or contract exists.
- `implemented_unverified`: code exists but lacks controlled end-to-end proof.
- `lab_verified`: demonstrated against controlled synthetic/local targets with positive and negative tests.
- `production_ready`: security review, operational isolation, recovery, audit and deployment controls independently assessed.

Never promote a capability based only on unit tests, static checks, agent prompt text or a successful plan-generation run.
