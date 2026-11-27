# Threat Model

## Assets to protect
- Client systems and data
- Engagement authorization and scope
- Credentials, cookies, tokens, and secrets
- Raw requests/responses and screenshots
- Findings and reports
- Local machine and GitHub repository

## Threats
- Out-of-scope requests caused by prompt ambiguity
- Shell command injection or unsafe tool invocation
- Agent hallucination or fabricated evidence
- False positives promoted to confirmed findings
- Secret leakage into Git, logs, or model context
- Concurrent agents changing shared state
- Malicious content in target pages or downloaded artifacts (prompt injection)
- Excessive request volume or operational impact

## Controls
- Default-deny execution configuration with explicit operator approval before active engagement activation
- Broker-only Bash exception for active-testing-agent; arbitrary shell and raw network clients remain denied
- SHA-256-pinned request manifests checked at plan creation and execution time
- Exact engagement and task scope checks, DNS/IP pinning, private-address restrictions, redirect revalidation, one-request concurrency, and per-engagement rate limiting
- Request/response evidence capture with best-effort secret redaction and audit records
- Engagement pause command as active-execution kill switch
- Explicit asset allowlist and exclusions
- External network egress controls and disposable test environment
- Least-privilege tools
- Human approval for risky actions
- Treat target content as untrusted data, never as instructions
- Independent finding validation
- Secret redaction and evidence access controls
- Git ignore rules and pre-commit secret scanning
- Task concurrency limits and per-engagement budgets

## Residual risk
Prompt instructions and Claude Code hooks cannot guarantee containment of arbitrary shell commands. The operator must use OS/container/network controls for any active testing. Do not run this framework against production assets without an approved test plan and appropriate safeguards.


## Additional runtime controls added in the bounded dispatcher

- **LLM-generated scope expansion:** planner output is validated against the plan schema and exact engagement asset allowlist. Active plans require an already approved engagement and pinned request manifests.
- **Untrusted evidence/Skill prompt injection:** evidence and Skill contents are explicitly delimited as data; specialist invocations have tools disabled; handoffs are schema- and identity-validated.
- **Fabricated evidence references:** handoffs may reference only evidence IDs supplied by the task or completed dependencies; each reference is checked against the same engagement and on-disk SHA-256.
- **False collected-artifact claims:** collected/redacted-copy claims must match a registered evidence record by path and digest, and the file is reverified.
- **Specialist runtime failure:** bounded timeouts and fail-closed task/run state transitions prevent an invalid handoff from completing a task.
- **Sensitive content in model context:** only operator-asserted redacted text files are inlined, with a 64 KiB per-artifact cap; binary and unredacted artifacts are not inlined.
- **Orchestrator overreach:** plan generation runs with tools disabled; Python, not the model, persists and executes the plan.

These controls reduce risk but do not provide a process sandbox, egress isolation, complete PII/secret detection, or protection against a compromised model provider/runtime. Authorization approval is an operator attestation, not document verification. The broker supports HTTP only; scanner and non-HTTP tool integrations are not implemented. Human review and external isolation remain required.

## Controls added by the architecture revalidation

Each control names its verification. "Lab" means a passing test against a local synthetic fixture on the development machine; it is not evidence of production readiness. See [`REVALIDATION_STATUS.md`](REVALIDATION_STATUS.md).

| Threat | Control | Verification |
|---|---|---|
| Request to an internal or metadata address (SSRF-style) through an in-scope name, DNS rebinding, odd IP notation | `core/netpolicy.py`: fixed blocked-network table incl. cloud metadata addresses, IPv6-wrapped IPv4, rejection of non-canonical notation (`2130706433`, `0x7f.1`), one lookup, connection to the validated address | Lab: `test_netpolicy.py`, `test_broker_hardening.py` |
| State-changing request replayed by a redirect or after a crash | Redirects never re-send non-idempotent methods; execution ledger with leases; a possibly-dispatched state-changing request becomes `RECONCILIATION_REQUIRED` and is never re-sent automatically | Lab: `test_broker_hardening.py`, `test_execution_ledger.py` |
| Fabricated or tampered evidence confirms a finding | Validation resolves evidence from the vault, re-hashes it and checks engagement ownership; only verified records move a finding; reports re-verify at report time | Lab: `test_validation_evidence_chain.py`, `test_reporting_engine.py` |
| Proposer validates its own finding | Proposer ≠ validator enforced in the finding state machine; agent contracts forbid an agent that both proposes and validates | Lab: `test_exploit_validation.py`, `test_agent_contracts.py` |
| Untrusted data raises its own trust (graph, knowledge, memory) | Weaker-trust upserts cannot overwrite stronger facts; authorization edges only at control-plane trust; knowledge enters as `inferred`; experience is promoted only from a verified validation record and proposals are leads | Lab: `test_graph_trust_merge.py`, `test_knowledge_graph_integration.py`, `test_experience_proposals.py` |
| Prompt injection through imported knowledge or Skills | Bounded, fail-closed ingestion; imported text reaches an agent only inside an untrusted block with directives escaped (both retrieval paths); Skills are version- and SHA-256-pinned and verified at load | Lab: `test_kb_ingestion_safety.py`, `test_agent_contracts.py` |
| Credential or secret leakage into audit, evidence, errors or reports | One key-aware redaction implementation (`core/redaction.py`) applied to audit events, ledger records, planner decisions, worker output, observations and experience records (best effort — it cannot prove a text is free of secrets); encrypted vault with rotation and ciphertext binding; no credentials from parked sessions; errors drop the exception chain | Lab: `test_redaction.py`, `test_auth_hardening.py` |
| Path escape through links or junctions | `core/pathsafe.py` (reparse-point aware) at every vault/worker read and write | Lab: `test_pathsafe.py`, `test_worker_hardening.py` |
| Malicious tool escapes its worker | Container backend: fails closed, read-only root, no capabilities, no new privileges, non-root, no network by default, cgroup limits, kill-and-remove on timeout/cancel | Verified on **one real runtime** in CI (Docker 28.0.4, cgroup v2, GitHub-hosted Ubuntu 24.04): `test_container_integration.py`, 14 tests, plus lifecycle tests against a fake `docker`. Rootless Docker, Podman and cgroup v1 are untested |
| Worker egress reaches unintended hosts | Default `--network none`; allow-list mode requires an operator-provisioned network; `render_egress_firewall()` default-deny ruleset | **Not verified** — ruleset never applied to a host |
| Resource exhaustion by a tool (time, output, processes) | Wall-clock limit, output-flood kill, whole-process-tree termination, cancellation, rlimits / Job Object limits | Lab on Windows (local) and Linux (CI, Python 3.12/3.13) |

Known gaps, stated plainly: the subprocess worker backend is not a sandbox; SQL injection, XSS and SSRF tests are not automated (hypotheses are recorded as not executed); the control plane (scope, authorization, test window) is the operator's attestation; tool binaries are not version-probed; GitHub Actions and the CI container test image are pinned by commit and digest (enforced by a test), but the tools installed in CI (`pip-audit`, the agent-benchmark npm package) and the Python dependencies are not pinned by hash.
