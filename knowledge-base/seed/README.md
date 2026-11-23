# Curated Security Knowledge Seed Collection

Status: seed corpus v0.1 — analyst-authored patterns, not ingested third-party reports.

This directory contains original concise pattern cards derived from public primary references. It deliberately does not redistribute full write-ups, screenshots, exploit code, client evidence, or private bug-bounty submissions.

## Coverage
- Web: 5 patterns
- API: 4 patterns
- Mobile: 4 patterns
- Cloud: 4 patterns
- Active Directory: 4 patterns

## Agent usage contract
1. Search by domain, weakness, precondition, and trust boundary.
2. Treat a card as a hypothesis generator and test-planning aid only.
3. Verify the exact technology, version, identity model, and control flow in the current engagement.
4. Obtain authorization and scope approval independently. This corpus never grants permission.
5. Validation agents must collect fresh evidence from the current engagement. A source URL or pattern ID is never target evidence.
6. Preserve uncertainty. If a precondition or impact is not demonstrated, label it unknown or conditional.

## Provenance and licensing
The cards are independently written summaries. Each includes source URLs and a statement of what the reference supports. Public accessibility is not treated as permission to copy a report. Consult each source license before reproducing material beyond links and brief factual summaries.

## Limits
- Manually curated starter pack, not a comprehensive vulnerability database.
- No verified target-specific findings and no executable exploit payloads.
- No automatic refresh when upstream guidance changes.
- Cloud cards are provider-neutral; use the applicable provider's current service documentation.
- AD cards are defensive assessment themes. Do not perform credential attacks, replication abuse, ticket manipulation, or directory changes without explicit written authorization and a controlled test plan.

## Files
- patterns-web-api.md
- patterns-mobile-cloud.md
- patterns-active-directory.md
- manifest.json

Review source links and version labels before relying on a card.