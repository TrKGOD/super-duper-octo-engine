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


## Brokered cache-isolation check
For two synthetic identities with distinct private marker values, prepare equivalent GET manifests using different broker-managed secret references and run:
```bash
python3 scripts/active_cache_check.py --db .local/state.sqlite3 --engagement-id ENGAGEMENT_ID --task-id TASK_ID --first-request-file .local/requests/cache-a.json --second-request-file .local/requests/cache-b.json --first-private-marker SYNTHETIC_PRIVATE_A --second-private-marker SYNTHETIC_PRIVATE_B
```
The runner performs sequential requests only. It compares marker leakage, Cache-Control, Vary, Age and common cache-status headers. Cache directives alone are a lead, not proof of cross-user disclosure.

HTTP framing review is passive-only:
```bash
python3 scripts/analyze_http_framing.py --input .local/http-request-capture.json
```
No request-smuggling payloads, ambiguous framing, cache poisoning, concurrent race traffic or state-changing requests are sent. Active desynchronization and race-condition validation requires an isolated lab and a dedicated approved harness; the current broker's single-concurrency/read-only constraints intentionally remain intact.
