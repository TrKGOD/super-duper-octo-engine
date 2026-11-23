# Active Web/API surface discovery

## Purpose
Perform bounded reconnaissance, same-origin crawling, endpoint discovery, static JavaScript inspection and low-impact HTTP configuration observations.

## Authorization
- Require a written authorization reference, active engagement approval, exact allowlist and task scope subset.
- Stop on scope ambiguity, expired testing window, exhausted request budget or broker denial.
- Never infer authorization from a hostname, program name or third-party source.

## Execution
Use only `scripts/active_surface.py` from an active task. The tool:
- Performs GET-only requests through the existing scope-enforcing broker.
- Pins DNS/IP, revalidates redirects and captures request/response evidence.
- Crawls only same-origin links with hard page/depth limits.
- Extracts observed forms, parameter names, JavaScript assets and API route patterns.
- Statically identifies risky JavaScript sinks without executing scripts.
- Observes security headers, cookie flags and CORS behavior without credentials.

## Interpretation
- Separate directly observed endpoints from inferred JavaScript routes.
- A static sink, missing header, cookie flag or HTTP status is an observation/candidate, not a confirmed vulnerability.
- Require a separate validation-agent task and fresh evidence for confirmation.
- Never use destructive requests, state changes, brute force, DoS, persistence, stealth/evasion, bulk extraction or real-user data.
