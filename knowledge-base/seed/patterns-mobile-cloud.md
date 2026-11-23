# Mobile and Cloud Pattern Cards

Original analyst-written summaries based on the public references listed below. Not copied reports and not target-specific evidence.

## MOB-001 — Sensitive data stored outside intended protection boundary
- **Root cause:** Data classification and storage controls are inconsistent across app components, logs, backups, caches, and platform storage.
- **Preconditions:** App stores authentication material, personal/business data, or cryptographic material locally.
- **Signals:** Preferences/UserDefaults; SQLite/Realm; sandbox files; logs; crash reports; clipboard; cached responses; backup configuration.
- **Safe validation:** Dedicated test device/emulator and synthetic data. Inspect only the app's own sandbox and artifacts from the test session.
- **Evidence:** File/key location, data classification, access conditions, device state, and recoverability under the stated threat model.
- **Impact:** Local disclosure/session compromise depending on access assumptions and sensitivity.
- **Remediation:** Minimize retention; use platform secure storage for secrets; encrypt with managed keys; restrict backups/logging; clear transient data.
- **False positives:** Non-sensitive values or encrypted blobs whose keys are adequately protected.
- **References:** https://mas.owasp.org/MASVS/ ; https://mas.owasp.org/MASTG/

## MOB-002 — Weak local authentication or biometric gating
- **Root cause:** Local UI state or biometric callback is treated as sufficient authorization for a sensitive server-side operation.
- **Preconditions:** Sensitive actions and local authentication/biometric gating exist.
- **Signals:** Sensitive screens unlocked by local boolean; biometric check not bound to cryptographic operation; backend accepts action without fresh authorization.
- **Safe validation:** Test accounts/devices only. Assess local gate resistance and independently verify backend authorization.
- **Evidence:** Local gate behavior, platform API usage, and server response for an unauthorized test action.
- **Impact:** Unauthorized sensitive function use if relevant controls are bypassed.
- **Remediation:** Bind sensitive operations to platform cryptographic authentication where appropriate; enforce backend authorization; require re-authentication for high-risk actions.
- **False positives:** Biometrics used only as convenience while backend authorization remains enforced.
- **References:** https://mas.owasp.org/MASVS/ ; https://mas.owasp.org/MASTG/

## MOB-003 — Insecure platform communication/trust configuration
- **Root cause:** TLS validation, trust anchors, certificate pinning strategy, or cleartext policy is missing or incorrectly implemented.
- **Preconditions:** App communicates with remote services and platform/network settings can be inspected.
- **Signals:** Cleartext HTTP; permissive trust managers; custom certificate validation; debug trust overrides; broad network exceptions.
- **Safe validation:** Controlled test endpoint and test build/device. Verify normal TLS validation and authorized proxy behavior. Do not intercept third-party users' traffic.
- **Evidence:** Platform configuration, endpoint ownership, certificate chain behavior, controlled results.
- **Impact:** Interception/manipulation under the demonstrated network threat model.
- **Remediation:** Enforce TLS defaults; remove permissive overrides; restrict cleartext; maintain pin rotation and backup pins if pinning is used.
- **False positives:** Debug-only settings excluded from release builds.
- **References:** https://mas.owasp.org/MASVS/ ; https://mas.owasp.org/MASTG/

## MOB-004 — Exported component or deep-link trust-boundary failure
- **Root cause:** Inter-app entry points are treated as internal navigation and lack caller checks, input validation, or safe routing.
- **Preconditions:** App exposes components or handlers callable externally.
- **Signals:** Exported activities/services/receivers/providers; custom URI schemes; deep-link parameters controlling object IDs or privileged actions.
- **Safe validation:** Test device/app; invoke only the app's own declared entry points with benign values. Avoid payments, account changes, or destructive actions.
- **Evidence:** Manifest/configuration, entry point, caller context, parameters, authorization outcome.
- **Impact:** Unauthorized app actions/data exposure if a boundary crossing is demonstrated.
- **Remediation:** Export only required components; apply permissions; validate incoming data; require backend authorization for sensitive actions; use verified links.
- **False positives:** Public components protected by robust authorization and validation.
- **References:** https://mas.owasp.org/MASTG/ ; https://mas.owasp.org/MASWE/

## CLOUD-001 — Excessive identity permissions and privilege paths
- **Root cause:** Broad policies, permissive trust relationships, long-lived credentials, or missing access reviews.
- **Preconditions:** Cloud IAM identities, roles, service principals, workload identities, or federation are in scope.
- **Signals:** Wildcard actions/resources; cross-account trust; unused privileged roles; long-lived keys; role chaining; stale grants.
- **Safe validation:** Read-only policy/configuration review and provider policy simulators. Never assume roles or exercise privileges beyond written scope.
- **Evidence:** Principal, policy statement, resource scope, trust relationship, effective permission analysis, owner-approved test result.
- **Impact:** Expanded blast radius/unauthorized access only if an exploitable path is demonstrated.
- **Remediation:** Least privilege; short-lived credentials; conditional trust; separation of duties; periodic reviews; remove stale identities/keys.
- **False positives:** Wildcards constrained by conditions, permission boundaries, or explicit organization controls.
- **References:** https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html ; https://learn.microsoft.com/en-us/azure/well-architected/security/

## CLOUD-002 — Public or cross-account data exposure
- **Root cause:** Public access settings, resource policies, ACLs, cross-account grants, or inherited permissions exceed intended audience.
- **Preconditions:** Cloud data resource and effective access policy are in scope.
- **Signals:** Public principals; anonymous access; broad organization/account grants; public snapshots/artifacts.
- **Safe validation:** Inspect configuration and provider access analysis. Do not download or enumerate data not explicitly designated as a test object.
- **Evidence:** Resource identifier, policy statement, effective exposure result, and approved synthetic-object test if permitted.
- **Impact:** Unauthorized data access/disclosure only if effective access is established.
- **Remediation:** Block public access by default; constrain policies; organization guardrails; continuous detection; data classification.
- **False positives:** Intentionally public non-sensitive content or effective explicit-deny controls.
- **Reference:** https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/a-security.html

## CLOUD-003 — Secrets exposed through workload configuration/build artifacts
- **Root cause:** Credentials/signing material are handled as ordinary configuration and persist beyond intended lifecycle.
- **Preconditions:** Workload definitions, build pipelines, images, or deployment configuration are in scope.
- **Signals:** Static access keys; tokens in environment dumps; secrets in image layers; verbose build output; broad secret-reader roles.
- **Safe validation:** Scan authorized repositories/artifacts only. Use synthetic canaries or metadata checks; never test discovered credentials by logging in unless explicitly authorized.
- **Evidence:** Artifact/layer reference, secret type (never value), exposure path, access scope, owner confirmation of active status.
- **Impact:** Unauthorized cloud/application access only if a live credential is confirmed usable through an approved process.
- **Remediation:** Secret manager; short-lived identity; rotation/revocation; log redaction; artifact scanning; least privilege.
- **False positives:** Placeholders, revoked credentials, or non-privileged test fixtures.
- **References:** https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html ; https://learn.microsoft.com/en-us/azure/well-architected/security/

## CLOUD-004 — Insufficient logging and detection coverage
- **Root cause:** Control-plane/data-plane activity is not captured, retained, centralized, or protected from alteration.
- **Preconditions:** Cloud audit and workload logging configuration is in scope.
- **Signals:** Missing account/region trails; short retention; unprotected log storage; no alerts on privilege changes/public exposure.
- **Safe validation:** Read configuration and verify one harmless, approved test event. Do not disable controls or generate disruptive activity.
- **Evidence:** Logging configuration, coverage, retention, integrity protections, and event correlation.
- **Impact:** Reduced detection/investigation capability; do not report this as a confirmed breach.
- **Remediation:** Centralize/protect audit logs; define retention; monitor privileged changes/data access; test alert pipelines.
- **False positives:** Equivalent centralized monitoring outside the reviewed account.
- **References:** https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html ; https://learn.microsoft.com/en-us/azure/well-architected/security/