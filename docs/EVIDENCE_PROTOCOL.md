# Evidence Collection Protocol

## Purpose
Every candidate finding should have an evidence package that lets another tester understand the claim, reproduce it safely where authorized, and distinguish observed behavior from a proposed test. Evidence quality is part of the finding's acceptance criteria, not a report-writing afterthought.

## Storage layout
Store engagement artifacts locally, never in Git:

```text
.local/evidence/<finding-id>/
├── screenshots/
├── requests/
├── responses/
├── reproduction.md
└── manifest.json
```

Use `templates/evidence-manifest.schema.json`. Reference artifacts by stable relative path and artifact_id. Preserve originals; create separate sanitized report copies.

## Required evidence categories
- **Screenshots:** capture the relevant application state and result, with enough surrounding context to identify the behavior. Use numbered names such as `01-request-context.png` and `02-observed-impact.png`. Do not crop away context needed to interpret the result.
- **HTTP request:** save a minimal sanitized raw request suitable for Burp Repeater when applicable.
- **curl command:** save a minimal command-line reproduction when applicable. Quote shell values safely and use placeholders for secrets; do not include live credentials.
- **HTTP response:** preserve status, relevant headers, and the smallest body excerpt that substantiates the claim. Retain raw originals in approved local storage and redact report copies.
- **Reproduction notes:** list prerequisites, exact steps, expected behavior, observed behavior, cleanup (if applicable), and environment details.

## Evidence state vocabulary
- `collected`: authentic artifact exists and was supplied/collected.
- `proposed_not_executed`: a request or procedure was drafted but not run.
- `missing`: evidence is required but has not been collected.
- `redacted_copy`: sanitized derivative of a retained original.

Never label a proposed request as collected. Never invent screenshots, responses, timestamps, or successful reproduction outcomes. If collection status cannot be established, use `missing` and explain the limitation.

## Reproduction package
The exploitation-agent should provide:
1. Sanitized curl command, if applicable.
2. Raw HTTP request suitable for Burp Repeater, if applicable.
3. Prerequisites and numbered reproduction steps.
4. Expected versus observed behavior, with observed behavior grounded only in authentic artifacts.
5. Screenshot capture plan: filename, capture point, and what must be visible.
6. Evidence manifest entries and outstanding gaps.

Use synthetic test data and the least intrusive proof that demonstrates the issue. Do not include destructive, persistent, stealthy, denial-of-service, bulk-extraction, or real-user-data actions.

## Independent validation
The validation-agent checks the evidence independently:
- Confirm the target/asset and request context are within the exact assigned scope.
- Compare request, response, and screenshots for consistency.
- Check that the evidence demonstrates the claimed condition and impact, not merely that a request was sent.
- Flag missing context, altered/cropped images, unsupported claims, unredacted secrets, and contradictory artifacts.
- A request template without authentic execution evidence cannot validate a finding.

## Current runtime limitation
This repository bootstrap runs with `execution_enabled=false` and rejects active-testing tasks. Agents can draft curl/Burp request files and specify screenshot capture requirements, but they cannot send requests or automatically capture browser screenshots. Authentic artifacts must be supplied from an explicitly authorized lab workflow. Automated browser/network evidence capture is a separate future implementation and must include operator approval, scope enforcement, isolation, secret redaction, and audit logging.

## Report requirements
The reporting-agent includes only approved evidence references, labels unexecuted request templates, adds screenshot captions, and discloses evidence gaps. Keep evidence and manifests in `.local/`, which is ignored by Git.
