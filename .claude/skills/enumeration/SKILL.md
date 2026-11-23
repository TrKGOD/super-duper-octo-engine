---
name: enumeration-methodology
description: Practical Web/API attack-surface enumeration that maps routes, inputs, API contracts, authentication contexts and high-value functionality for vulnerability discovery.
---

# Enumeration Methodology — Web and API

## Mission

Find and describe the reachable application surface so the vulnerability specialist can investigate concrete security hypotheses. Enumeration is not a checklist-completion exercise. Follow evidence: expand where new routes, inputs, identities or trust boundaries appear; do not blindly probe every possible test class.

## Operating rules

- Work only within the engagement and task scope. Active discovery is allowed only when the task is explicitly active and the engagement has been approved.
- Prefer supplied HAR/Burp captures, API specifications, source maps and application artifacts before sending requests.
- Active discovery uses only the guarded scripts/active_surface.py runner. It performs same-origin GET/OPTIONS requests through the broker. Never use raw curl, arbitrary shell networking, external scanners, off-scope hosts or directory brute-force wordlists.
- Respect requests-per-second, single concurrency, testing window, response-size and crawl-depth controls. There is no cumulative per-engagement request quota; this is not permission to generate unnecessary traffic.
- Never replay state-changing links, logout/reset/delete/checkout/payment/transfer actions, or submit forms. Do not enumerate real users or access real customer data.
- Record evidence provenance and confidence. Separate observed, inferred and unverified data.

## Technique set

### 1. Route and content discovery

- Normalize URLs and deduplicate by origin, path and meaningful query-key set; redact sensitive query values.
- Extract links, forms, action URLs, script assets, iframe/resource references and canonical URLs from HTML.
- Inspect robots.txt and sitemap.xml when present. Treat disallowed paths as discovery clues, not permission to access excluded or prohibited functionality.
- Check a small fixed set of public metadata documents on the exact in-scope origin: OpenAPI/Swagger documents and /.well-known/openid-configuration. Do not run directory brute force.
- Record status codes, content types, redirects, authentication redirects and access-control differences.

### 2. API surface mapping

- Parse supplied OpenAPI/Swagger specs and observed JSON responses. Extract paths, methods, parameter names/locations, request-body fields, response schemas and security schemes.
- Identify REST version prefixes, GraphQL endpoints, WebSocket references and RPC-style routes only when observed in artifacts, HTML or JavaScript.
- Use OPTIONS only on observed endpoints to record Allow/CORS capabilities; OPTIONS output is not proof that a method is exploitable.
- Map path IDs, tenant/workspace/org/project/account identifiers, pagination, filters, sort keys, export/download references and nested object IDs.
- Preserve method and content-type only when actually observed. Never infer that a GET route supports POST/PUT/DELETE.

### 3. Input and parameter inventory

- Collect query parameters, form fields, JSON keys (including nested keys), path variables, headers and multipart field names from supplied captures and observed forms.
- Note hidden fields, client-controlled role/ownership/price/status fields, URL/callback/redirect parameters, file names and object references as investigation leads.
- Keep parameter names separate from example values. Redact credentials, tokens, session identifiers and personal data.

### 4. JavaScript and client-side surface

- Inventory same-origin JavaScript bundles and source maps when directly referenced or explicitly advertised.
- Extract hardcoded API paths, base URLs, GraphQL paths, feature flags, route names and references to privileged operations.
- Flag DOM HTML sinks, dynamic code execution, unsafe navigation and message handlers as static indicators only.
- Do not treat minified strings or source-map presence as vulnerabilities.

### 5. Authentication and role context

- Build an endpoint matrix by available authorized test identity and role: anonymous, standard user, elevated/test-admin and tenant context where supplied.
- Compare route visibility, response status, redirect behavior and field/schema differences across those identities using only approved test accounts.
- Inventory login, logout, registration, password reset, MFA, session refresh/revocation, OAuth/OIDC callback and account-linking flows.
- Never guess credentials, brute-force accounts, bypass MFA or enumerate real account existence.

### 6. Business-function and trust-boundary mapping

Tag endpoints and features involving object ownership and tenant boundaries; role/permission changes and administrative actions; money, credits, subscriptions, invoices or refunds; invitations, sharing, approvals and workflow state transitions; file upload/import/export/download; URL fetching, webhooks, callbacks and integrations; search/filter/reporting/bulk operations; and account recovery, identity linking and token lifecycle.

## Hypothesis handoff to Vulnerability Discovery

- Object IDs plus multiple authorized identities → IDOR/BOLA and tenant isolation.
- Client-controlled role/owner/price/status fields → mass assignment and business-logic review.
- Redirect/callback/return URLs → redirect and OAuth redirect validation.
- URL-fetch/import/webhook fields → SSRF review.
- Reflected or DOM-rendered inputs plus JS sinks → XSS review.
- Upload/import/export paths → file handling and access-control review.
- Admin/workflow/approval endpoints → function-level authorization and state-transition review.
- Filters/sort/search/template fields → injection review appropriate to the observed sink.

Prioritize by impact potential, evidence strength, reachability and distinct trust boundaries. Do not ask the Vulnerability Agent to test every category on every endpoint.

## Required output

1. Observed endpoints (source evidence, method if observed, status/content type).
2. Inferred endpoints (source file/line or artifact and confidence).
3. API operations and schema details.
4. Input inventory grouped by query/path/header/form/JSON/multipart.
5. Authentication/role matrix, using test identity labels only (never secrets).
6. High-value business functions and trust boundaries.
7. Vulnerability hypotheses with rationale and suggested next specialist.
8. Coverage gaps, blocked paths, crawl limits and untested assumptions.
9. Evidence references and redaction notes.

## Completion criteria

Complete when the discovered surface is normalized, high-value functions and identity contexts are mapped, evidence is linked, and prioritized leads are handed to vulnerability discovery. Continue targeted enumeration when new evidence reveals an unmapped dependency or trust boundary. A task is not complete merely because a fixed number of pages was reached.