---
name: web-testing-injection-csrf
description: XSS, CSRF and injection discovery with non-destructive validation.
---

# XSS, CSRF and injection discovery with non-destructive validation

## Investigation workflow
Trace input sources to interpreters and browser sinks; identify context, encoding, parameterization, CSRF token and origin checks. Prefer static analysis, supplied captures and harmless canary markers. Do not execute destructive commands, extract database contents, persist payloads, or target other users. Validate only in isolated fixtures or explicitly approved test accounts. Record exact source, sink, context, control behavior and evidence; reflection alone is not XSS.

## Required handoff
- Candidate class and concrete application feature/route.
- Source, sink, trust boundary and expected security invariant.
- Observed facts separated from assumptions.
- Exact scope and authorization basis for any active check.
- Evidence references, redaction status and reproducibility notes.
- False-positive explanations and safest next validation step.

## Guardrails
All active requests must use the approved broker and task-pinned manifests. Follow engagement scope, exclusions, test windows and allowed test classes. Stop when the required authorization, synthetic fixture, or safe validation environment is unavailable. A technique description or public KB pattern is not authorization or evidence.
