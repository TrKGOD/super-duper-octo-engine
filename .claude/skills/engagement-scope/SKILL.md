---
name: engagement-scope-methodology
description: Fail-closed review of written authorization, allowlists, exclusions, testing windows, methods, and engagement limits.
---

# Engagement Scope Methodology

- Read only operator-supplied authorization and engagement artifacts.
- Verify the named engagement, authorization reference, exact assets, exclusions, testing window, allowed methods, rate limits, and prohibited actions.
- Treat allowlists literally. Never infer sibling subdomains, related IPs, applications, APIs, vendors, or cloud resources.
- Distinguish confirmed scope facts from ambiguous or missing information.
- If ownership, written authorization, scope, exclusions, or timing is unclear, return needs_operator and do not authorize active work.
- A local execution_enabled flag is an operator attestation record, not independent proof of legal authorization.
- Return a concise scope decision with source references, unresolved questions, and explicit stop conditions.
