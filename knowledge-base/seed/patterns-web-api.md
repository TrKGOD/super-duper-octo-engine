# Web and API Pattern Cards

Original analyst-written summaries. These are not copied vulnerability reports and do not assert that any target is vulnerable.

## WEB-001 — Broken object-level authorization (IDOR/BOLA)
- **Root cause:** Server accepts a caller-controlled object identifier without authorizing the authenticated principal for that object and action.
- **Preconditions:** Endpoint reads, updates, deletes, or exports an object selected by caller-controlled ID; two test identities or a defined role boundary are available.
- **Signals:** Object IDs in routes/bodies; ownership fields; nested resources; export/download endpoints.
- **Safe validation:** In an authorized test environment, use two test identities and two test-owned objects. Compare access only to those objects. Do not enumerate real users' identifiers or access third-party data.
- **Evidence:** Redacted request/response pairs, object ownership setup, operation attempted, and authorization outcome.
- **Impact:** Unauthorized read or modification only if cross-boundary access is demonstrated.
- **Remediation:** Enforce server-side object authorization on every operation; derive ownership from trusted session context; add negative authorization tests.
- **False positives:** Public/shared objects or tenant-wide roles with documented access.
- **Sources:** OWASP API1:2023; WSTG authorization testing.
- **References:** https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/ ; https://wstg.owasp.org/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/

## WEB-002 — Broken function-level authorization
- **Root cause:** Authorization depends on UI visibility, route obscurity, HTTP method, or incomplete role checks instead of an explicit server-side permission decision.
- **Preconditions:** Distinct roles exist and a sensitive function can be invoked independently of the normal UI.
- **Signals:** Admin/support routes; hidden controls; bulk actions; alternate HTTP methods; endpoints used by privileged screens.
- **Safe validation:** Use owner-provided test accounts. Invoke only documented in-scope functions and compare expected role permissions. Prefer read-only or reversible actions.
- **Evidence:** Role definitions, endpoint/action, response, and proof the test identity lacks permission.
- **Impact:** Unauthorized administrative action or access limited to the tested function.
- **Remediation:** Deny by default; enforce server-side permissions per function and resource; regression-test every role.
- **False positives:** Documented support or service roles.
- **Sources:** OWASP API5:2023; WSTG authorization testing.
- **References:** https://api-security.owasp.org/editions/2023/en/0xa5-broken-function-level-authorization/ ; https://wstg.owasp.org/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/

## WEB-003 — Authentication and session lifecycle weakness
- **Root cause:** Authentication state is not consistently bound to the user, session lifecycle, or security-sensitive transitions.
- **Preconditions:** App issues or accepts sessions, bearer tokens, reset links, or MFA challenges.
- **Signals:** Session not rotated after login/privilege change; logout fails to invalidate server state; reusable reset tokens; weak recovery; inconsistent MFA.
- **Safe validation:** Dedicated test accounts only. Test login, logout, password change, recovery, and privilege-change flows. No credential stuffing or attacks on real users.
- **Evidence:** Redacted before/after session identifiers, relevant token metadata, and observed server behavior.
- **Impact:** Session fixation, account takeover, or post-logout persistence only where demonstrated.
- **Remediation:** Rotate session IDs after authentication and privilege changes; enforce server-side expiry/revocation; protect recovery; secure cookies.
- **False positives:** Short-lived tokens with documented refresh/revocation behavior.
- **Sources:** OWASP WSTG authentication/session categories; ASVS.
- **References:** https://wstg.owasp.org/stable/4-Web_Application_Security_Testing/04-Authentication_Testing/ ; https://wstg.owasp.org/stable/4-Web_Application_Security_Testing/06-Session_Management_Testing/ ; https://owasp.org/www-project-application-security-verification-standard/

## WEB-004 — Server-side request forgery (SSRF)
- **Root cause:** Backend fetches a caller-influenced URL/host/redirect without validating the final network destination and protocol.
- **Preconditions:** URL preview, webhook, import, renderer, image fetcher, or another server-side fetch feature exists.
- **Signals:** URL parameters; webhook registration; redirect following; DNS resolution at request time; multiple accepted schemes.
- **Safe validation:** Use an owner-controlled callback endpoint or approved lab listener. Test only authorized destinations. Do not probe metadata services, internal networks, or third parties without explicit written permission.
- **Evidence:** Submitted destination, controlled listener logs, redirect/DNS behavior, and exact application response. A timeout alone is not proof.
- **Impact:** Access to unintended resources/network zones only to the extent demonstrated.
- **Remediation:** Allowlist destinations; restrict schemes; validate resolved addresses at connection time; revalidate redirects; enforce egress controls.
- **False positives:** Client-side fetches or validation without a backend request.
- **Sources:** OWASP API7:2023; WSTG input validation.
- **References:** https://api-security.owasp.org/editions/2023/en/0xa7-server-side-request-forgery/ ; https://wstg.owasp.org/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/

## WEB-005 — Injection and unsafe input interpretation
- **Root cause:** Untrusted input is concatenated into SQL/NoSQL, OS commands, templates, LDAP filters, or browser output instead of safe APIs and context-aware encoding.
- **Preconditions:** User-controlled value reaches a parser, query engine, command interpreter, template engine, or browser sink.
- **Signals:** Search/filter/sort fields; report builders; exports; template customization; diagnostics; reflected/stored content.
- **Safe validation:** Use non-destructive probes in a lab or approved test account. Demonstrate controlled parsing/output behavior; never run destructive statements or OS commands against production.
- **Evidence:** Input location, sink/context, minimal differential response, and reproducible behavior.
- **Impact:** Data disclosure/modification, server execution, or client script execution only when that boundary crossing is proven.
- **Remediation:** Parameterized queries; safe APIs; context-aware output encoding; allowlisted arguments; least privilege.
- **False positives:** Error messages, reflected strings, or scanner signatures without proof of interpreter execution.
- **Sources:** OWASP WSTG input validation; OWASP Cheat Sheet Series.
- **References:** https://wstg.owasp.org/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/ ; https://cheatsheetseries.owasp.org/


## API-001 — Broken object property-level authorization (BOPLA)
- **Root cause:** API responses or update operations expose or accept object properties without enforcing property-level authorization and data minimization.
- **Preconditions:** API serializes structured objects or accepts writable JSON properties; fields have different visibility or mutability by role/owner.
- **Signals:** Excessive response fields; mass-assignment behavior; client-supplied role, owner, price, status, or permission properties.
- **Safe validation:** Use synthetic records and test roles. Compare allowed response fields and attempt only harmless changes to test-owned objects. Never modify real account roles, balances, or other users' data.
- **Evidence:** Redacted before/after JSON, role context, field classification, and server-side persistence result for a test-owned record.
- **Impact:** Sensitive property disclosure or unauthorized property modification only where demonstrated.
- **Remediation:** Explicit response DTOs/field allowlists; per-property read/write authorization; reject unknown or immutable fields; server-side ownership of sensitive attributes.
- **False positives:** Fields intentionally public or writable under documented business rules.
- **References:** https://api-security.owasp.org/editions/2023/en/0xa3-broken-object-property-level-authorization/

## API-002 — Unrestricted resource consumption
- **Root cause:** API does not adequately constrain request size, execution cost, concurrency, pagination, or expensive business operations.
- **Preconditions:** Caller can trigger resource-intensive operations or control parameters that influence processing cost.
- **Signals:** Unbounded page sizes; expensive search/report/export; no per-user quotas; large uploads; high-cost GraphQL queries; missing concurrency controls.
- **Safe validation:** Review configuration and use a controlled test account with a written request/rate ceiling. Prefer static policy review and low-volume test cases; never conduct load or denial-of-service testing without a separately approved plan.
- **Evidence:** Configured limits, request parameters, measured behavior under the approved ceiling, and relevant logs/metrics.
- **Impact:** Service degradation, cost amplification, or resource exhaustion only if safely demonstrated within the approved test limits.
- **Remediation:** Enforce quotas and rate limits; cap payload/page/query complexity; apply timeouts and concurrency controls; monitor cost and resource anomalies.
- **False positives:** Effective gateway, WAF, or platform quotas outside the application that are included in the tested architecture.
- **References:** https://api-security.owasp.org/editions/2023/en/0xa4-unrestricted-resource-consumption/

## API-003 — Sensitive business flow abuse
- **Root cause:** A business-critical workflow relies on client-side friction or assumes legitimate intent without enforcing eligibility, sequencing, uniqueness, or velocity constraints server-side.
- **Preconditions:** API exposes a sensitive workflow such as coupon redemption, ticket reservation, referral, voting, purchasing, or account recovery.
- **Signals:** Repeatable one-time actions; race-sensitive state transitions; missing idempotency; trust in client-calculated eligibility; automation controls absent.
- **Safe validation:** Use dedicated test accounts and synthetic objects. Validate only reversible, non-financial test flows and agreed request limits. Do not purchase, reserve real inventory, generate costs, or affect real users.
- **Evidence:** Workflow rules, test identity, controlled sequence, server responses, and audit/log state proving whether a business invariant was violated.
- **Impact:** Abuse of the specific business process only when a prohibited state transition or benefit is demonstrated.
- **Remediation:** Enforce business invariants server-side; idempotency keys; per-principal limits; atomic state transitions; abuse monitoring and risk-based friction.
- **False positives:** Intended repeat actions, documented promotional rules, or controls enforced by an external system.
- **References:** https://api-security.owasp.org/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/

## API-004 — Improper API inventory management
- **Root cause:** API assets, versions, environments, and data flows are not inventoried and governed through their lifecycle.
- **Preconditions:** Organization operates multiple API versions, gateways, environments, or third-party integrations.
- **Signals:** Deprecated versions reachable; undocumented hosts/routes; inconsistent authentication; staging/debug APIs exposed; unknown data flows.
- **Safe validation:** Compare approved API inventory and owner-provided documentation against passive DNS, gateway exports, source configuration, and explicitly in-scope endpoint lists. Do not probe unknown hosts until scope is confirmed.
- **Evidence:** Inventory source/date, endpoint/version, owner status, environment classification, and confirmation that the endpoint is reachable within approved scope.
- **Impact:** Exposure of unsupported or less-protected API surfaces; state the actual data/action exposure separately.
- **Remediation:** Maintain an API catalog; assign owners; version and decommission endpoints; enforce consistent gateway controls; monitor external exposure.
- **False positives:** Documented compatibility versions with equivalent security controls or endpoints intentionally public.
- **References:** https://api-security.owasp.org/editions/2023/en/0xa9-improper-inventory-management/
\n## API-specific review notes
For API assessments, additionally map each endpoint to API1 BOLA, API2 authentication, API3 object-property authorization, API4 resource consumption, API5 function authorization, API6 sensitive business flows, API7 SSRF, API8 misconfiguration, API9 inventory management, and API10 unsafe consumption of upstream APIs. Do not perform load or cost-impact tests without a written limit and an approved test window.
Reference: https://api-security.owasp.org/editions/2023/en/0x00-header/