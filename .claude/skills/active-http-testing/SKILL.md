---
name: active-http-testing-methodology
description: Bounded read-only HTTP validation through the scope-enforcing broker with evidence integrity and request-budget discipline.
---

# Active HTTP Testing Methodology

## Preconditions
- Confirm the engagement is active, execution is explicitly enabled, and operator authorization attestation is present.
- Confirm the exact target is in both engagement and task allowlists; never infer sibling hosts or related assets.
- Use only operator-reviewed request manifests pinned by SHA-256 in the current task.
- Execute only through the dedicated active HTTP broker.

## Allowed behavior
- This Enumeration-First pipeline permits GET, HEAD, and OPTIONS only. Reject POST and every other method even if a broader engagement policy or separate approval would otherwise permit it.
- Respect the configured rate limit (at most one request per second), concurrency of one, request budget, timeout, and response-size limits.
- Revalidate redirects and scope decisions through the broker; never work around a broker denial.
- Capture only the minimum response material needed to support an observation.

## Evidence and conclusions
- Cite only evidence IDs returned by the broker or inherited as verified evidence.
- Preserve SHA-256, redaction state, capture time, and audit linkage.
- Treat status codes and response differences as observations, not vulnerabilities by themselves.
- Return hypotheses separately from validated findings; do not claim confirmation without reproducible evidence and independent validation.

## Prohibited behavior
- No arbitrary shell, scanners, browser automation, fuzzing, brute force, credential attacks, destructive requests, data modification, persistence, exfiltration, DoS, or stealth/evasion.
- Do not access real user data or secrets. Stop if safe validation would require them.
- Stop and request operator input if scope, authorization, exclusions, or test window are ambiguous.
