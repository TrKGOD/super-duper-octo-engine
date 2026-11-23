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
- Default-deny execution configuration
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
