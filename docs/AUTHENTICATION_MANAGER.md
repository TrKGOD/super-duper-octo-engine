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
Adapters receive a transport callback supplied by the authorized execution layer. They do not perform arbitrary HTTP requests themselves. OAuth2/OIDC endpoints and browser flows must be in engagement scope and use the broker. Browser runner must use an isolated Playwright context and return only required session headers and expiry metadata.

## Current integration status
The AAM core and adapters are implemented as a separate module. The existing active HTTP executor has not yet been wired to select an identity from task metadata; do not describe authenticated requests as operational until that integration and local synthetic tests pass. The browser adapter is an integration seam and requires an operator-supplied Playwright runner; it is not a turnkey browser login feature.
