---
name: web-information-disclosure
description: Information disclosure, exposed secrets, debug artifacts and sourcemaps.
---

# Information disclosure, exposed secrets, debug artifacts and sourcemaps

## Investigation workflow
Inspect public responses, headers, error pages, source maps, manifests, build artifacts and repository references for unintended disclosure. Do not authenticate with discovered secrets, access third-party accounts, download bulk data or expand scope. Redact secret values immediately; retain only type, location, fingerprint and minimum proof. Distinguish public configuration from credentials and prove impact without using the secret.

## Required handoff
- Candidate class and concrete application feature/route.
- Source, sink, trust boundary and expected security invariant.
- Observed facts separated from assumptions.
- Exact scope and authorization basis for any active check.
- Evidence references, redaction status and reproducibility notes.
- False-positive explanations and safest next validation step.

## Guardrails
All active requests must use the approved broker and task-pinned manifests. Follow engagement scope, exclusions, test windows and allowed test classes. Stop when the required authorization, synthetic fixture, or safe validation environment is unavailable. A technique description or public KB pattern is not authorization or evidence.
