---
name: web-testing-authorization-idor
description: Compare object-level and function-level authorization across explicitly approved synthetic identities and objects.
---

# Authorization, IDOR and BOLA

## Objective
Find broken object-level authorization (BOLA/IDOR) and function-level authorization gaps by comparing equivalent, read-only requests across approved identities and roles. This is evidence-led testing, not a checklist applied to every route.

## Preconditions
- Written authorization, exact target scope, test window and exclusions are verified.
- Use only operator-provided synthetic test accounts and synthetic objects.
- Record the documented ownership and role expectations for each test object.
- Obtain equivalent request templates for both identities. Credentials must be supplied through broker-managed secret environment references, never copied into manifests or handoffs.
- Only GET, HEAD and OPTIONS are in scope for this workflow. Any state-changing test requires a separate explicit operator decision and is not part of this skill.

## Object-level comparison workflow
1. Identify a high-value object route from observed traffic, OpenAPI metadata, application functionality or enumeration evidence.
2. Establish a baseline: identity A owns a synthetic object A and can read it through the normal application flow.
3. Establish the negative control: identity B is a distinct approved account and is not the owner, collaborator, tenant member or otherwise entitled to object A.
4. Replay the exact same read-only request and object reference once as A and once as B through the scope-enforcing HTTP broker. Keep method, path, query, non-secret headers and request context equivalent; vary only the approved identity credential.
5. Compare status, content type, normalized response representation and broker evidence references. A 2xx response to B is a lead, not proof. Identical owner/non-owner representations are a stronger candidate signal, but public/shared access, caching and policy exceptions must be ruled out.
6. Repeat only with another known synthetic object/identity pair when it materially reduces ambiguity. Do not enumerate identifiers, scrape collections or access customer data.
7. Record both request and response evidence IDs and the ownership/role facts that make the comparison meaningful.

## Function-level comparison workflow
1. Identify a sensitive read-only function from observed routes or application role documentation.
2. Capture the expected privileged-role response as a baseline.
3. Replay the equivalent request using an approved lower-privilege identity.
4. A successful response is a candidate only. Confirm the function is not intentionally available to that role and inspect whether sensitive data or privileged functionality was actually exposed.
5. Do not test state-changing admin actions under this workflow.

## Comparison interpretation
- potential_bola_same_object_representation: both identities received successful responses with the same normalized representation; high-priority candidate, not a confirmed finding.
- potential_bola_access_granted: the non-owner received a successful response, but the representation differs; investigate object ownership and intended sharing.
- access_denial_observed: the non-owner received 401/403/404; this is an observation, not proof that all objects/routes are protected.
- inconclusive_truncated_response: at least one response was truncated; do not infer equality or denial.
- potential_function_level_authorization_gap: the lower-privilege identity received a successful response to a function expected to be privileged; candidate only.
- inconclusive / inconclusive_response_difference: evidence does not establish the authorization decision.

The reusable comparison logic is in core/authorization_testing.py. It consumes broker result objects and does not perform network I/O; all requests must still go through ActiveHTTPExecutor.

## Required evidence and output
- Exact route and method
- Synthetic object reference (not a real customer identifier)
- Owner and comparison identity labels and expected policy
- Equivalent request-context confirmation
- Both HTTP status codes and relevant redacted response excerpts
- Both broker evidence reference lists
- Comparison classification and limitations
- Independent validation recommendation

## False-positive checks
- Public or intentionally shared objects
- Same tenant, group, team, or delegated access
- Cached response or stale authorization state
- Application returning a generic shell/placeholder rather than object data
- Different request parameters, headers, API versions or feature flags
- Truncated or redacted bodies that make responses appear equal
- Role policy allowing the operation

## Safety
Never use credential guessing, account takeover, bulk ID enumeration, destructive actions, writes, privilege changes, or real customer data. Stop if the test identities, ownership model, or authorization expectations are unclear.


## Brokered paired runner
The executable CLI is `scripts/active_authorization_pair.py` (implemented by `core/authorization_execution.py`):
```bash
python3 scripts/active_authorization_pair.py \\
  --db {engagement.state_db_path} \\
  --engagement-id ENGAGEMENT_ID --task-id TASK_ID \\
  --owner-request-file .local/requests/idor-owner.json \\
  --other-request-file .local/requests/idor-non-owner.json \\
  --owner-identity synthetic-owner --other-identity synthetic-non-owner \\
  --object-reference synthetic-object-1
```
Pin both manifests with SHA-256 in the approved task before dispatch. The manifests must target the same URL with the same method and request context; only the unique request ID and broker-managed secret environment references may differ. Use distinct secret references for the same authentication header. The helper rejects POST/body requests and never resolves credentials itself. Each execution is performed independently by `ActiveHTTPExecutor`, so engagement approval, task scope, pinned-manifest integrity, request-ID replay protection, rate limiting and evidence capture remain enforced by the broker.

If the second request fails after the owner request completes, the helper returns `partial_execution` and the owner evidence references. This is not a comparison, must not be reported as a finding, and must not be automatically replayed. A completed comparison remains candidate-only until synthetic ownership and the comparison identity's lack of entitlement are independently established.
