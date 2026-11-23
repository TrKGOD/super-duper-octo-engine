# Enumeration-First Multi-Agent Pipeline

## Purpose

This pipeline exercises the existing DAG and handoff mechanism as one ordered methodology. Each task is a specialist agent. The dispatcher injects the selected Skill text, verified evidence referenced by the task and its completed dependencies, and the direct dependency handoffs.

## Required order

| Task key | Agent | Dependency | Responsibility |
|---|---|---|---|
| `scope` | `scope-analyst` | none | Written authorization, exact allowlist, exclusions, test window and rules; fail closed |
| `recon` | `recon-agent` | `scope` | Bounded same-origin HTTP reconnaissance through the guarded discovery runner when active; passive artifacts otherwise |
| `enumeration` | `enumeration-agent` | `recon` | HTML/routes/forms, robots/sitemap, OpenAPI/Swagger and OIDC metadata, JavaScript route extraction, input inventory, role/business-function mapping and prioritized vulnerability leads |
| `vulnerability` | `vulnerability-agent` | `enumeration` | Automated read-only checks for security headers, cookie flags, CORS/OPTIONS behavior and static JS sinks; candidates only |
| `exploitation` | `exploitation-agent` | `vulnerability` | Execute only separately reviewed, SHA-256-pinned GET/HEAD/OPTIONS reproduction manifests |
| `validation` | `validation-agent` | `exploitation` | Independent review and, when separately pinned, fresh brokered reproduction; proposer cannot validate itself |
| `impact` | `impact-analyst` | `validation` | Impact only for independently validated findings |
| `dedupe` | `duplicate-checker` | `impact` | Non-destructive duplicate analysis |
| `reporting` | `reporting-agent` | `dedupe` | Report only validated findings as confirmed; preserve hypotheses and rejected items separately |

Every task must set a valid `domain` and at least one `skill_tags` value that matches a Skill compatible with that agent and domain. Plan generation checks this before persistence; dispatch repeats the check and refuses to run with an empty Skill selection. The selected Skill IDs are returned and recorded in audit telemetry.

## Running

1. Review the official written authorization, scope, exclusions, permitted test classes, test window and limits. A local active flag is an operator attestation record, not independent proof of authorization.
2. Ensure the engagement is explicitly active and approved. If it is not, run only the passive prefix and stop at the active-testing preflight gate; do not claim active validation.
3. Supply operator-reviewed artifacts (for example HAR/Burp exports or API specifications) under the engagement's local evidence workflow. The active discovery runner can crawl a single explicitly scoped origin without prebuilt manifests; exploitation and fresh active validation still require separate request manifests under `.local/requests/`, each pinned by SHA-256. There is no cumulative per-engagement request quota; request rate, single-worker concurrency, scope, testing window and response bounds remain enforced.
4. Generate and dispatch the persisted DAG with `python3 scripts/run_orchestrator.py --db DB_PATH --engagement-id ENG-ID --model MODEL`. Use the exact engagement-isolated DB path supplied by the workflow. For an already persisted plan, `scripts/run_plan.py` remains available.
5. Inspect each returned stage: selected Skills, direct prior handoffs, inherited evidence IDs, evidence hashes and task status. A blocked branch must not stop independent branches.

The active example at `templates/examples/plan.enumeration-first.active.example.json` is a template only. `app.example.test`, the all-zero manifest digest and the placeholder manifest path are not real scope or authorization. Replace them only with exact operator-approved values; never run the example unchanged.

## Evidence and safety invariants

- Evidence is loaded from the engagement project root, integrity-verified by SHA-256, and only redacted text artifacts are inlined into agent context.
- Handoffs may reference only evidence registered to the same engagement and verified by the evidence vault.
- The dispatcher passes only direct dependency handoffs, while inherited evidence references are deduplicated across dependencies.
- Validation is independent; impact requires a completed validation handoff.
- Active tasks require `status=active`, `execution_enabled=true`, `authorization_verified=true`, and exact task/engagement scope. Discovery tasks generate and pin bounded GET/OPTIONS manifests internally; exploitation and active validation require separately operator-reviewed SHA-256-pinned manifests.
- The HTTP broker remains a narrow request primitive. `scripts/active_surface.py` layers bounded same-origin crawling, route extraction and safe configuration checks on top of it; it does not invoke Nmap/Nuclei/SQLMap or browser automation. Brute force, DoS, persistence, stealth/evasion, bulk extraction and real-user-data access remain prohibited.
- CI and the nine-stage integration test use synthetic fixtures only. They do not contact external targets or establish authorization for a live engagement.


## Enumeration techniques and handoff

The enumeration Skill defines the baseline Web/API techniques: HTML route and form extraction; robots/sitemap metadata; fixed-path OpenAPI/Swagger and OIDC discovery; REST/GraphQL/RPC inventory from observed artifacts; query/path/header/form/JSON/multipart parameter mapping; JavaScript bundle and source-map analysis; authorized identity/role comparison; and high-value business-function/trust-boundary mapping.

Enumeration hands off prioritized leads (object IDs → IDOR/BOLA, client-controlled role fields → mass assignment, callback URLs → OAuth/redirect review, URL-fetch inputs → SSRF review, uploads/exports → file/access-control review). It does not trigger every vulnerability class against every endpoint. Observations and inferred routes remain distinct.

## Request throughput policy

The cumulative `max_requests_per_engagement` quota has been removed. The broker still enforces requests-per-second (hard maximum 5), single-request concurrency, explicit engagement/task scope, active approval, test windows, allowed HTTP methods, response-size limits, redirect validation and evidence logging. The crawler retains explicit per-run page/depth bounds to prevent accidental unbounded crawling.
