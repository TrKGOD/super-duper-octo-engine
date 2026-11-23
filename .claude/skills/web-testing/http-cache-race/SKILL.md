---
name: web-http-cache-race
description: HTTP request desynchronization, cache behavior and race conditions.
---

# HTTP request desynchronization, cache behavior and race conditions

## Investigation workflow
Analyze proxy/origin framing, normalization, cache keys, Vary behavior, authorization partitioning and state transitions. Begin with passive evidence and controlled lab fixtures. Do not send ambiguous framing, cache-poisoning payloads or concurrent state-changing requests to production without explicit dedicated approval and safe isolation. For race tests use synthetic records, bounded concurrency and reversible fixtures. Capture intermediary/origin evidence and rule out ordinary caching or timing noise.

## Required handoff
- Candidate class and concrete application feature/route.
- Source, sink, trust boundary and expected security invariant.
- Observed facts separated from assumptions.
- Exact scope and authorization basis for any active check.
- Evidence references, redaction status and reproducibility notes.
- False-positive explanations and safest next validation step.

## Guardrails
All active requests must use the approved broker and task-pinned manifests. Follow engagement scope, exclusions, test windows and allowed test classes. Stop when the required authorization, synthetic fixture, or safe validation environment is unavailable. A technique description or public KB pattern is not authorization or evidence.
