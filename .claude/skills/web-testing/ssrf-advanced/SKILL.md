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


## Brokered canary workflow
For an approved target-side URL-fetch feature, use one operator-reviewed, SHA-256-pinned GET/HEAD/OPTIONS manifest that contains both the exact unique marker and the exact callback URL:
```bash
python3 scripts/active_ssrf_probe.py --db .local/state.sqlite3 --engagement-id ENGAGEMENT_ID --task-id TASK_ID --request-file .local/requests/ssrf-canary.json --callback-url https://CALLBACK_HOST/unique-path --marker UNIQUE_MARKER
```
The callback host must be HTTPS and explicitly present in engagement `allowed_domains`; the target request itself is still sent only by the broker. If callback logs are available, provide a sanitized JSON array via `--callback-events .local/ssrf-callback-events.json`; only events containing the unique marker are retained, with a minimal allowlist of event fields. A callback match is a candidate requiring independent provenance verification, not automatic confirmation.

Do not target metadata services, private/loopback/link-local addresses, internal hosts, or third-party callback infrastructure. DNS rebinding, redirect chains and parser differential work remain manual/lab-only unless a dedicated safe fixture and approved scope are provided.
