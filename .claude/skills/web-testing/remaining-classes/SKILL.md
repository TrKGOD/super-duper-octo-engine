---
name: web-remaining-vulnerability-classes
description: Structured coverage for remaining web and API vulnerability classes.
---

# Structured coverage for remaining web and API vulnerability classes

## Investigation workflow
Use application-specific evidence to select relevant classes rather than running a universal checklist. Map trust boundaries, parsers, file handling, redirects, CORS, business invariants and serialization formats. Prefer static/configuration review and safe canaries. Avoid reading arbitrary files, executing deserialization gadgets, uploading active content or changing business state outside a dedicated approved lab. Every hypothesis needs a concrete source, sink, expected security invariant and falsifiable validation plan.

## Required handoff
- Candidate class and concrete application feature/route.
- Source, sink, trust boundary and expected security invariant.
- Observed facts separated from assumptions.
- Exact scope and authorization basis for any active check.
- Evidence references, redaction status and reproducibility notes.
- False-positive explanations and safest next validation step.

## Guardrails
All active requests must use the approved broker and task-pinned manifests. Follow engagement scope, exclusions, test windows and allowed test classes. Stop when the required authorization, synthetic fixture, or safe validation environment is unavailable. A technique description or public KB pattern is not authorization or evidence.
