---
name: web-testing-authentication-advanced
description: Authentication, session, recovery, MFA and OTP control testing.
---

# Authentication, session, recovery, MFA and OTP control testing

## Investigation workflow
Map login, enrollment, challenge, recovery, device trust, session rotation and logout states. Compare documented expected state transitions with synthetic accounts. Check lockout and throttling using a small operator-approved test budget; never brute force, spray credentials, enumerate real users or bypass MFA on real accounts. Validate OTP replay, expiry and binding only with generated test secrets and a lab or explicitly approved account. Preserve pre/post state and distinguish missing controls from inconclusive evidence.

## Required handoff
- Candidate class and concrete application feature/route.
- Source, sink, trust boundary and expected security invariant.
- Observed facts separated from assumptions.
- Exact scope and authorization basis for any active check.
- Evidence references, redaction status and reproducibility notes.
- False-positive explanations and safest next validation step.

## Guardrails
All active requests must use the approved broker and task-pinned manifests. Follow engagement scope, exclusions, test windows and allowed test classes. Stop when the required authorization, synthetic fixture, or safe validation environment is unavailable. A technique description or public KB pattern is not authorization or evidence.


## Brokered authentication-boundary check
For a documented protected read-only resource, prepare two equivalent GET/HEAD/OPTIONS manifests: one with a broker-managed synthetic authenticated secret reference, and one anonymous (no `secret_headers`). Pin both manifests in the same active task, then run:
```bash
python3 scripts/active_authentication_check.py --db .local/state.sqlite3 --engagement-id ENGAGEMENT_ID --task-id TASK_ID --authenticated-request-file .local/requests/authenticated.json --anonymous-request-file .local/requests/anonymous.json --protected-resource /account
```
Only request ID and secret headers may differ. The tool compares status and captured cookie security flags; it does not attempt login, OTP replay, MFA bypass, recovery abuse, rate-limit stress or credential guessing. A 2xx anonymous response is a candidate until the route's access policy is independently established.
