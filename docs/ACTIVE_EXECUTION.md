# Active Web/API Assessment Execution

## Scope of this implementation

The active Web/API vertical now includes bounded same-origin reconnaissance, HTML crawling, endpoint/form discovery, static JavaScript route and sink analysis, low-impact HTTP configuration checks, brokered reproduction, and independent validation. These capabilities are exposed through `scripts/active_surface.py` and `scripts/active_http.py`.

Recon, enumeration and vulnerability specialists receive Bash only for active tasks. The PreToolUse guard permits only the exact discovery runner or HTTP broker command, and verifies the engagement state, running task and exact target scope before discovery. Exploitation-agent and validation-agent can execute only separately SHA-256-pinned GET/HEAD/OPTIONS manifests. No specialist receives general shell or unrestricted network access.

The discovery runner performs same-origin GET crawling with a maximum of 25 pages and depth 3, statically parses downloaded JavaScript, records observed and inferred endpoints separately, and checks response security headers, cookie attributes, CORS behavior and OPTIONS capabilities. It does not execute JavaScript in a browser or invoke third-party scanners. All network requests are brokered, rate-limited and evidence-captured.

The per-engagement path mapping is:
- Default: `config/engagement.local.json` with `.local/state.sqlite3`.
- Isolated: `config/engagement.SLUG.local.json` with `.local/engagements/SLUG/state.sqlite3`.
The command guard resolves only these strict path patterns and fails closed on symlinks or mismatched engagement IDs.

The general broker supports GET, HEAD, OPTIONS, and individually approved POST requests. The Enumeration-First pipeline applies a stricter policy and dispatches only GET, HEAD, and OPTIONS; POST and all other methods are rejected for that pipeline even if separately approved. PUT, PATCH, DELETE, TRACE, CONNECT, uploads, arbitrary shell, Nmap, Nuclei, sqlmap, browser automation, brute force, DoS, persistence, stealth/evasion, bulk extraction, and real customer-data access are not supported.

## Engagement activation

The engagement configuration defaults to execution_mode=active. This is the default planning preference only; initialization still forces execution_enabled=false and status=draft.

Initialize from a local config with:
- a non-placeholder written authorization reference;
- explicit allowlisted domains, IPs, CIDRs, or applications;
- explicit http-read-only in allowed_test_classes;
- max_concurrency: 1;
- requests_per_second from 0 to 1;
- max_requests_per_engagement from 1 to 50 (default 20);
- execution_enabled: false and authorization_verified: false.

Initialization always creates a draft engagement and does not enable execution.

After manually reviewing the authorization document, scope, exclusions, and rules, the operator must attest to all three:
- written authorization is valid for the named engagement;
- the allowlist and exclusions exactly reflect the program scope;
- permitted methods, test classes, time window, rate, and prohibited actions have been reviewed.

Run:

~~~bash
python scripts/workflow.py --db .local/state.sqlite3 approve \
  --engagement-id ENG-ID \
  --operator "Your Name" \
  --authorization-reference "WRITTEN-AUTHORIZATION-REFERENCE" \
  --confirm-written-authorization --confirm-scope --confirm-rules
~~~

This records operator attestation in SQLite. It does not independently verify the underlying Bugcrowd policy, contract, or authorization document. The engagement becomes active and execution_enabled=true only after this explicit command.

Pause active execution immediately with:

~~~bash
python scripts/workflow.py --db .local/state.sqlite3 pause \
  --engagement-id ENG-ID --operator "Your Name" --reason "Stop testing"
~~~

The broker checks the active status before every request. Pause blocks new requests; an in-flight request may take up to its configured timeout to finish.

## Request manifest

Create a JSON manifest under .local/requests/. Example:

~~~json
{
  "request_id": "planet-health-check-001",
  "method": "GET",
  "url": "https://EXACT-IN-SCOPE-HOST.example/health",
  "purpose": "Check the authorized health endpoint response",
  "headers": {
    "Accept": "application/json"
  },
  "secret_headers": {
    "Authorization": "PLANETHOSTER_TEST_AUTH"
  },
  "timeout_seconds": 8,
  "max_response_bytes": 131072,
  "follow_redirects": true
}
~~~

Do not use the example hostname as a target. Replace it only with an exact target listed in the engagement allowlist. Never store credentials, cookies, or API keys as literal values in a request manifest. Use secret_headers to reference environment variables set in the operator's shell before launching the dispatcher. Active agents do not receive secret values; the broker resolves environment variables at execution time and redacts sensitive headers from captured evidence. Request and response body redaction is best-effort; review evidence manually. Do not put secrets in URLs or request bodies.

The task plan must pin the manifest by SHA-256:

~~~python
import hashlib
from pathlib import Path

path = Path(".local/requests/planet-health-check-001.json")
print(hashlib.sha256(path.read_bytes()).hexdigest())
~~~

Then include this in the active task:

~~~json
{
  "task_key": "active-http-health-check",
  "agent": "active-testing-agent",
  "objective": "Execute the reviewed HTTP request manifest and analyze the response",
  "completion_criteria": ["Capture authentic request/response evidence"],
  "scope_subset": ["EXACT-IN-SCOPE-HOST.example"],
  "domain": "web",
  "skill_tags": ["http-read-only"],
  "active_testing": true,
  "request_files": [
    {
      "path": ".local/requests/planet-health-check-001.json",
      "sha256": "REPLACE-WITH-64-CHARACTER-SHA256"
    }
  ]
}
~~~

Workflow.create_plan verifies that the manifest exists, is under .local/requests/, is no larger than 64 KiB, matches the pinned SHA-256, and matches the request schema. The broker rechecks the hash at execution time. The active agent cannot modify manifests.

## State-changing POST

POST is denied unless all of these are true:
- the engagement includes state-changing-http in allowed_test_classes;
- human_approval_required_for_state_changes is true;
- the individual request manifest includes operator_approval with approved: true, a named operator, a timezone-aware timestamp, and a reason;
- the operator has reviewed and pinned the exact manifest before plan creation.

Example approval fragment:

~~~json
{
  "operator_approval": {
    "approved": true,
    "approved_by": "Your Name",
    "approved_at": "2026-11-23T12:00:00Z",
    "reason": "Approved this single non-destructive test request"
  }
}
~~~

Do not approve destructive or irreversible operations. The broker does not support PUT/PATCH/DELETE or file uploads.

## Offline HAR import

The operator can import a browser HAR without any network activity:

~~~bash
python -I scripts/ingest_har.py --db .local/state.sqlite3 \
  --engagement-id ENG-ID --har .local/input/session.har
~~~

The importer reads only HAR entries whose hostname is explicitly covered by the engagement's \`allowed_domains\` list (or the optional exact \`--scope-host\` filter). It writes endpoint and identifier inventories under \`.local/engagements/ENG-ID/\`, with restrictive file permissions. It records parameter/header names, not header values; authorization, cookie and CSRF header names are marked secret. Request/response bodies and secret values are not copied into the inventory. HAR content is untrusted input and is parsed as JSON only; no HAR script or request is executed. The importer does not send requests.

## Optional authenticated surface discovery

For an explicitly authorized active discovery task, \`active_surface.py\` accepts repeated environment-backed header references and an optional browser-matched User-Agent:

~~~bash
python scripts/active_surface.py --db .local/state.sqlite3 \
  --engagement-id ENG-ID --task-id TASK-ID --target-url https://EXACT-IN-SCOPE-HOST/ \
  --secret-header 'Cookie=VINTED_TEST_COOKIE' --user-agent 'RESEARCHER_BROWSER_UA'
~~~

Set the environment variable in the operator shell before dispatch. Never pass secret values on the command line or put them in manifests. The generated manifest contains only the header name and environment-variable reference. This mode remains same-origin and GET/OPTIONS-only; all requests still pass through the broker, scope checks, rate limits, evidence redaction and audit logging. Authenticated discovery is optional and disabled when no \`--secret-header\` is supplied.

## State-changing requests and uploads

The general broker supports POST/PUT/PATCH/DELETE only when the engagement allows \`state-changing-http\`, \`human_approval_required_for_state_changes=true\`, and the exact manifest contains timestamped per-request operator approval. The request manifest is SHA-256-pinned to the task, so changing method, URL, headers or body invalidates the approved pin. Redirects for state-changing requests are blocked.

Multipart upload is separately disabled by default. It requires all of:
- \`upload-http\` in the engagement's \`allowed_test_classes\`;
- \`uploads_enabled=true\` in engagement rules;
- \`human_approval_required_for_state_changes=true\`;
- a timestamped per-request operator approval;
- an upload fixture no larger than 256 KiB, with a restricted filename and content-type allowlist.

The upload payload is base64 in the locally pinned manifest and is not copied into evidence; evidence records upload metadata only. The broker is not a sandbox: use synthetic files and isolated test targets. Enumeration-First discovery remains GET/OPTIONS-only and does not gain write methods from this general broker capability.

## Enforcement

The broker:
- requires an active engagement with operator attestation;
- requires an allowlisted scoped assessment specialist to be running the exact task;
- requires the request manifest to be pinned in that task;
- checks both engagement-wide scope and task scope;
- supports exact domain entries and explicit *.domain entries; it does not infer wildcard scope from a base domain;
- checks exclusions and resolved IP addresses;
- blocks private, loopback, link-local, and reserved DNS answers unless the IP/CIDR is explicitly listed in scope;
- pins the resolved IP for the socket connection while preserving the original Host header and TLS SNI;
- revalidates every redirect, blocks HTTPS-to-HTTP downgrade, and strips credentials when origin changes;
- permits only ports 80/443 unless a custom port is explicitly listed in allowed_http_ports or the exact application origin is allowlisted;
- enforces one concurrent request (until multi-worker lease and budget reservation are implemented), an engagement-configurable rate of up to 5 requests per second (default 1), and an engagement-configurable budget of up to 500 requests (default 20); request timeout, body and response size remain separately bounded;
- stores best-effort redacted request/response evidence with SHA-256 and audit events;
- prevents replay of a request ID within the same engagement.

The command guard denies all other Bash commands. The active broker is not a sandbox or a replacement for OS/container network controls. Run it in an isolated environment with outbound network egress restricted to the approved scope. Static JavaScript sink matches and missing headers/cookie flags are observations, not proof of exploitability. The exploitation-agent requires operator-pinned reproduction requests, and active validation requires a different validator with a separate request manifest. If no independent reproduction is available, the finding remains a hypothesis or needs_more_evidence.

## Local regression tests

The active executor tests use a local HTTP server and synthetic scope only:

~~~bash
python -m unittest tests.test_active_executor -v
~~~

Never run these tests against a production target. The CI suite does not contact external targets.
