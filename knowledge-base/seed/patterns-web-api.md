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

## API-specific review notes
For API assessments, additionally map each endpoint to API1 BOLA, API2 authentication, API3 object-property authorization, API4 resource consumption, API5 function authorization, API6 sensitive business flows, API7 SSRF, API8 misconfiguration, API9 inventory management, and API10 unsafe consumption of upstream APIs. Do not perform load or cost-impact tests without a written limit and an approved test window.
Reference: https://api-security.owasp.org/editions/2023/en/0x00-header/