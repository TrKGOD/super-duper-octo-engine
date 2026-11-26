# Validated Experience Memory

**Component C.** Status: `lab_verified`. A persistent, reusable-across-engagements store of
**independently validated** security experience, so agents can recall "similar validated
patterns" before planning new tests — without ever treating a past success as proof or as
permission.

## The promotion gate (the whole point)

`core/experience/promotion.promote_finding` is the **only** way in, and it refuses anything
that is not an independently confirmed finding:

- the finding's status must be a confirmed state (`validated` / `reported` / `resolved`), and
- there must be a **SUPPORTED validation record** from the Phase 4 validation engine.

A hypothesis, an observed behavior, a refuted or inconclusive test, or a scanner candidate is
rejected (`PromotionError`). A failed test can never become a "successful technique"
(`test_unvalidated_finding_is_refused`, `test_refuted_finding_is_refused`,
`test_validated_without_supported_record_is_refused`).

## Records (`core/experience/store.py`)

Each experience captures the directive's fields: vulnerability category, technology (+version),
attack surface, prerequisites, required identity/privilege, endpoint characteristics, tooling,
execution and validation methodology, evidence **reference ids**, expected/actual behavior,
final disposition (`validated`), confidence, false-positive conditions, remediation, related
graph entities and knowledge patterns, source-engagement provenance, and timestamps.

**No secrets.** Free-text fields are redacted on write (reusing the broker's `_redact_text`),
and evidence is stored **by id only** — raw response bodies, cookies, tokens and PII are never
copied (`test_no_secrets_are_persisted`). Because records are sanitized, the store is safe to
reuse across engagements while carrying each record's source-engagement provenance.

## Retrieval and lifecycle

- **Similarity retrieval** (`ExperienceStore.search`): deterministic ranking by category match,
  technology match and methodology token overlap — relevance, not blind reuse. Every result
  carries an **advisory** note: a past success is not evidence the current target is vulnerable
  and confers no authorization. A `retrieval_count` is tracked.
- **Lifecycle**: a repeat validation of the same signature creates a **new version**,
  deprecates the prior one, and **recalculates confidence** upward (capped). `deprecate` and
  `mark_under_review` support operator review; deprecated records drop out of active search.

## Security boundary

Experience Memory **never turns previous success into permission**: it stores knowledge, not
authorization; retrieval is advisory and read-only; nothing it returns enters the control plane
or the graph's authorization tier. Records are sanitized and engagement-isolated by content
(no cross-engagement data leakage beyond sanitized methodology + provenance).

## Tests

`tests/test_experience_memory.py` (9): the promotion gate (validated promotes; hypothesis/
refuted/no-record refused), no-secret persistence, advisory similarity retrieval, cross-
engagement provenance, and versioning/confidence/deprecation.

## Follow-ups

Add an optional embedding-based similarity seam (mirroring Component A); let the planner query
experience memory before generating candidates; operator review UI for `under_review` records.
