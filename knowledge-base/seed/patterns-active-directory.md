# Active Directory Pattern Cards

Original defensive assessment summaries based on Microsoft and government guidance. These cards are not exploit instructions and do not authorize credential attacks, replication abuse, ticket manipulation, or directory changes.

## AD-001 — Kerberoastable service account / weak credential hygiene
- **Root cause:** Service accounts use human-managed, weak, non-rotating, or overprivileged credentials.
- **Preconditions:** Authorized directory review identifies SPN-bearing accounts and permits configuration assessment.
- **Signals:** SPN on user account; privileged group membership; stale account; password never expires; weak service-account lifecycle.
- **Safe validation:** Start with read-only directory review. If ticket-request testing is explicitly approved, use a designated lab account and agreed rate limits. Do not request tickets for production accounts or crack organizational credentials without explicit written authorization.
- **Evidence:** Account classification, SPN presence, privilege memberships, password policy metadata (not password material), owner-approved review.
- **Impact:** Potential service-account compromise/privilege escalation if weak credentials are actually recovered. Configuration alone is not proof of compromise.
- **Remediation:** Prefer gMSA; use long random managed secrets; rotate; remove unnecessary privileges; prevent interactive logon; monitor unusual service-ticket activity.
- **False positives:** Strong managed credentials, constrained service scope, compensating monitoring.
- **References:** https://www.cyber.gc.ca/en/news-events/joint-guidance-detecting-and-mitigating-active-directory-compromises ; https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory

## AD-002 — Kerberos pre-authentication disabled
- **Root cause:** Legacy/exceptional account configuration remains enabled without a documented business need.
- **Preconditions:** Authorized read-only directory configuration review.
- **Signals:** User objects with DONT_REQUIRE_PREAUTH or equivalent account-control configuration.
- **Safe validation:** Read-only directory queries. Do not collect/crack authentication material from production identities. Use a dedicated lab account for any end-to-end test.
- **Evidence:** Redacted account identifier, account-control flag, exception/owner, test environment.
- **Impact:** Offline password-guessing exposure may exist; do not claim account compromise without independent proof.
- **Remediation:** Require Kerberos pre-authentication; investigate legacy dependencies; use strong managed credentials; monitor authentication anomalies.
- **False positives:** Documented interoperability exception with compensating controls.
- **References:** https://www.cyber.gc.ca/en/news-events/joint-guidance-detecting-and-mitigating-active-directory-compromises ; https://www.cyber.gc.ca/en/guidance/practitioner-guidance-securing-microsoft-active-directory-services-your-organization-itsp60100

## AD-003 — Excessive directory replication rights (DCSync-capable principal)
- **Root cause:** Replication extended rights are granted directly or through group nesting without tight ownership and review.
- **Preconditions:** Explicit authorization for read-only ACL and group-membership review of the domain naming context.
- **Signals:** Non-admin principals with Replicating Directory Changes / All rights; unexpected nested groups.
- **Safe validation:** Inspect ACLs and effective group membership only. Never execute DCSync against production as proof. Use approved offline analysis or a lab for effective-access validation.
- **Evidence:** Object ACL, principal SID/name, inherited/direct grant, nested group path, business requirement.
- **Impact:** Principal may be able to replicate sensitive directory secrets. Report permission exposure, not credential theft, unless separately and safely demonstrated.
- **Remediation:** Minimize replication principals; review grants; isolate Tier 0 identities; prevent privileged identities logging into lower-trust systems; monitor replication events.
- **False positives:** Required domain controllers and documented synchronization/backup services.
- **References:** https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/accounts ; https://media.defense.gov/2024/sep/25/2003553985/-1/-1/0/ctr-detecting-and-mitigating-ad-compromises.pdf

## AD-004 — Unconstrained or overly broad Kerberos delegation
- **Root cause:** Delegation settings trust a service/host too broadly and sensitive identities can authenticate to it.
- **Preconditions:** Authorized review of delegation attributes, service ownership, and authentication architecture.
- **Signals:** Unconstrained delegation on non-DC hosts; broad constrained delegation targets; unexpected resource-based constrained delegation entries.
- **Safe validation:** Read-only review of delegation configuration and privileged identity exposure. Do not coerce authentication, impersonate users, or abuse tickets in production.
- **Evidence:** Host/account, delegation type, allowed service targets, privileged identity exposure, owner, documented need.
- **Impact:** Potential user impersonation to delegated services depending on delegation type and authentication flow.
- **Remediation:** Remove unnecessary delegation; prefer constrained/RBCD with explicit service boundaries; use gMSA where suitable; restrict privileged logon paths.
- **False positives:** Required constrained delegation with tightly scoped services and compensating controls.
- **References:** https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/accounts ; https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory ; https://www.cyber.gc.ca/en/guidance/practitioner-guidance-securing-microsoft-active-directory-services-your-organization-itsp60100

## AD assessment guardrails
- Prefer read-only inventory, ACL review, policy review, and event-log analysis.
- Keep privileged credentials out of workstations and lower-trust tiers.
- Never place real hashes, tickets, passwords, NTDS data, or secrets in the repository/KB.
- Do not infer domain compromise from a risky setting alone.
- Distinguish misconfiguration observed, attack path modeled, and impact demonstrated as separate evidence states.