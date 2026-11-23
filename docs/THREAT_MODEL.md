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
