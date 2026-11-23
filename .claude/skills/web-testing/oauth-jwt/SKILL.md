---
name: web-testing-oauth-jwt
description: Analyze OAuth 2.0, OIDC and JWT artifacts for flow integrity, issuer/audience boundaries, key selection and token lifecycle weaknesses.
---

# OAuth 2.0 / OpenID Connect / JWT specialist workflow

## Trigger from application context
Select this pack when observed routes, JavaScript, API schemas, redirects, identity-provider metadata, token handling, federation, account linking or role/tenant claims indicate an OAuth/OIDC trust boundary. Do not run it as a checklist when the application does not use these protocols.

## Evidence collection and analysis
1. Map the relying party, authorization server, client type (confidential/public), registered redirect URIs, response types, grant types, scopes, resource audiences and account/tenant boundary.
2. Identify whether the flow is Authorization Code + PKCE, confidential-client code flow, device flow, client credentials or another documented grant. Record observed values separately from assumptions.
3. Review operator-supplied OIDC discovery and JWKS captures. Check issuer consistency, HTTPS endpoints, signing algorithm declarations, kid uniqueness, key use/alg consistency and key-rotation context. Do not fetch metadata from arbitrary destinations.
4. Review redacted authorization/callback/token captures for exact redirect URI matching, unpredictable state, nonce binding, PKCE S256, response-mode behavior, code single-use/expiry, and whether the client binds the response to the initiating browser session.
5. Review redacted JWT header/claims for alg, kid, iss, aud, azp, exp, nbf, iat, scopes and tenant/role claims. Compare against the relying party's documented trust policy.
6. Review refresh-token rotation/reuse, logout/revocation, scope downscoping and claim-to-authorization mapping only when the supplied evidence documents those lifecycle transitions.
7. Correlate the finding with an actual application function. A token claim or provider configuration difference alone is not proof of broken authorization.

## Deterministic offline analyzer
Place sanitized JSON artifacts under .local/ (never commit tokens or secrets). Run:
~~~bash
python3 scripts/analyze_protocol_artifacts.py oidc-discovery --input .local/oidc-discovery.json --expected-issuer https://idp.example.test
python3 scripts/analyze_protocol_artifacts.py oauth-flow --input .local/oauth-flow.json
python3 scripts/analyze_protocol_artifacts.py jwt --input .local/jwt-review.json --expected-issuer https://idp.example.test --expected-audience api
~~~
The JWT input is a JSON object with a token field and optional captured jwks. Use short-lived synthetic tokens only; never paste production bearer tokens into chat, logs or findings. The analyzer parses header and claims, checks selected policy relationships and supplied JWKS metadata, but **does not verify JWT signatures** or cryptographic key material. OIDC metadata checks are descriptive, not endpoint tests. A missing field in an incomplete capture is not proof the control is absent.

## Active validation boundary
The current workflow is artifact-driven. It does not redeem authorization codes, generate tokens, mutate client registrations, replay refresh tokens, test account takeover, brute-force credentials/OTP, bypass MFA, or send requests to identity providers. If a safe live check is necessary, prepare a minimal read-only request manifest for operator review and the existing HTTP broker; do not create an unreviewed active workflow. Use synthetic accounts/clients and explicit engagement scope. Never use real user tokens or cross-tenant customer data.

## Finding standard
For each candidate, include the relying party and flow, exact invariant, observed values (redacted), expected policy source, evidence references, affected application capability, false-positive explanations, and a minimal independent validation plan. Treat every analyzer output as a candidate, not a confirmed vulnerability.
