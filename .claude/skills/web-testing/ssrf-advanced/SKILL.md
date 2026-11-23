---
name: web-testing-ssrf-advanced
description: SSRF discovery and controlled validation across URL fetchers, parsers, redirects and egress controls.
---

# SSRF discovery and controlled validation across URL fetchers, parsers, redirects and egress controls

## Investigation workflow
Identify URL-consuming features from evidence; map parser and resolver boundaries; inspect scheme/host/port/IP normalization, redirects, DNS resolution, allowlists and response handling. Use only an operator-controlled callback or isolated sink designed for testing. Never probe cloud metadata, internal networks, localhost, or third-party services unless explicitly represented by an approved lab fixture. Validate with harmless unique markers and brokered requests; distinguish blind callback evidence from response disclosure. Record source input, sink, resolution/redirect behavior, callback evidence, scope and remediation.

## Required handoff
- Candidate class and concrete application feature/route.
- Source, sink, trust boundary and expected security invariant.
- Observed facts separated from assumptions.
- Exact scope and authorization basis for any active check.
- Evidence references, redaction status and reproducibility notes.
- False-positive explanations and safest next validation step.

## Guardrails
All active requests must use the approved broker and task-pinned manifests. Follow engagement scope, exclusions, test windows and allowed test classes. Stop when the required authorization, synthetic fixture, or safe validation environment is unavailable. A technique description or public KB pattern is not authorization or evidence.
