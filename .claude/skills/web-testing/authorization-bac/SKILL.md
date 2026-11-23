---
name: web-testing-authorization-bac
description: Broken access control, BOLA/IDOR and function-level authorization.
---

# Broken access control, BOLA/IDOR and function-level authorization

## Investigation workflow
Build a role/tenant/object matrix from documented policy and synthetic identities. Compare equivalent read-only operations through the broker; test object and function authorization separately. Do not enumerate IDs, access customer records, change roles, or perform writes. Treat success as a candidate until ownership, sharing and policy are proven. Preserve both identities, request equivalence, object ownership facts and broker evidence.

## Required handoff
- Candidate class and concrete application feature/route.
- Source, sink, trust boundary and expected security invariant.
- Observed facts separated from assumptions.
- Exact scope and authorization basis for any active check.
- Evidence references, redaction status and reproducibility notes.
- False-positive explanations and safest next validation step.

## Guardrails
All active requests must use the approved broker and task-pinned manifests. Follow engagement scope, exclusions, test windows and allowed test classes. Stop when the required authorization, synthetic fixture, or safe validation environment is unavailable. A technique description or public KB pattern is not authorization or evidence.
