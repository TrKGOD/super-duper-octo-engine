# Autonomous Authentication Manager (AAM)

## Scope
AAM provides engagement-scoped identities, encrypted session persistence, adapter contracts, expiry handling and controlled recovery. Agents receive only an opaque `session_id`; session material is retrieved inside the broker through `material_for_broker` and must never be included in an LLM prompt, handoff, finding, or audit event.

## Three implementation layers
1. **Session manager:** Cookie/JWT/API-key/form adapters, encrypted vault, state lifecycle and bounded recovery.
2. **OAuth2/OIDC and identities:** token exchange/refresh adapters and separate identity namespaces per engagement (for example user/admin/test account). Never silently substitute identities.
3. **Browser authentication:** optional isolated Playwright runner. The runner is injected by the operator; this core does not create an unrestricted browser or network path.

## Configuration and key management
- Set `HACKBOT_AUTH_VAULT_KEY` to a Fernet key provisioned outside the repository and process arguments. Generate one with `python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'`.
- Keep credentials in environment variables or an external secret manager. Identity configuration stores environment-variable names only.
- The SQLite session payload is encrypted at rest. Back up and rotate the vault key under operator control; loss of the key makes sessions unrecoverable.
- Do not commit local DBs, vault keys, cookies, tokens, or credentials.

## Recovery policy
- A 401 may trigger refresh, then an explicitly configured login flow.
- A 403 is an access-denied response and is never treated as session expiry.
- Only GET/HEAD/OPTIONS may be retried, at most once, after successful recovery.
- POST/PUT/PATCH/DELETE are never automatically replayed. Reconcile possible side effects manually.
- MFA, CAPTCHA, passkeys, consent screens and external approvals pause for a human; no bypass is attempted.
- Identity selection is explicit per task; there is no automatic privilege escalation or identity switching.

## Adapters and transport
Network adapters receive `BrokerAuthTransport`, which is bound to the configured base origin, task scope subset, engagement allowlist, DNS-pinned destination, response-size ceiling, no-redirect policy and engagement rate-limit lease. It permits only GET discovery/JWKS and POST form/token exchanges. Token response bodies remain in memory and are never captured as evidence or written to audit logs. The engagement must explicitly include `authentication-http` in `allowed_test_classes`; the normal active HTTP class remains separately required for target testing.

OIDC requires an operator-supplied expected nonce and an explicit broker-routed `jwks_path`. It validates the compact ID Token signature (RS256 or ES256), `kid`, issuer, audience, authorized party for multiple audiences, nonce, expiration, issued-at and not-before claims. Unsupported algorithms and ambiguous/missing keys fail closed. Discovery metadata's issuer and JWKS origin are checked against the configured issuer.

Browser authentication uses the built-in optional Playwright runner. It launches an isolated headless Chromium context, blocks downloads and service workers, restricts every browser request to the exact configured origin, uses environment-variable credentials, and returns only origin-scoped session cookies. MFA/CAPTCHA/passkey challenges are surfaced as `challenge_required`; automation stops and an operator must complete the challenge through an approved manual workflow. It does not bypass challenges or export browser profiles/storage state.

## Operator CLI
Generate a vault key and provision it out-of-band:

```bash
python scripts/auth.py genkey
export HACKBOT_AUTH_VAULT_KEY='...'
```

Register an identity using a local JSON config containing environment-variable references only:

```bash
python scripts/auth.py --db .local/state.sqlite3 register --engagement-id ENG-ID --identity-id tester --adapter form --config .local/auth-tester.json
python scripts/auth.py --db .local/state.sqlite3 authenticate --engagement-id ENG-ID --identity-id tester --scope-asset app.example.test
python scripts/auth.py --db .local/state.sqlite3 list --engagement-id ENG-ID --identity-id tester
python scripts/auth.py --db .local/state.sqlite3 revoke --engagement-id ENG-ID --identity-id tester --session-id sess_...
```

The engagement must be active, explicitly approved, and allow `authentication-http` for network-backed form/OAuth exchanges. Its operator-authored `rules_of_engagement.authorized_identity_ids` list is the source of truth for which identities tasks may select; a task cannot authorize itself by populating its own identity list. The config's `base_url` must be an exact in-scope origin. Keep local config files, vault keys and environment values out of Git.

For browser auth, install the CI-tested Playwright dependency and Chromium runtime with `python -m pip install -r requirements-dev.txt && python -m playwright install chromium`.

## Current validation status
The branch adds cryptographic OIDC claim/signature tests, a local HTTP integration test crossing the broker transport and encrypted session store, and a real local Playwright login test executed in CI with Chromium. These are synthetic-lab checks; they do not prove compatibility with every identity provider or production browser flow. OAuth2/OIDC provider-specific authorization-code bootstrap and operator-mediated interactive challenge completion remain provider/operator responsibilities. Authenticated active-task propagation is validated at plan creation and consumed inside the HTTP broker; end-to-end execution against an external target remains intentionally untested.
