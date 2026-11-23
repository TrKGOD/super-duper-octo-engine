# Enumeration-First Multi-Agent Pipeline

## Purpose

This pipeline exercises the existing DAG and handoff mechanism as one ordered methodology. Each task is a specialist agent. The dispatcher injects the selected Skill text, verified evidence referenced by the task and its completed dependencies, and the direct dependency handoffs.

## Required order

| Task key | Agent | Dependency | Responsibility |
|---|---|---|---|
| `scope` | `scope-analyst` | none | Written authorization, exact allowlist, exclusions, test window and rules; fail closed |
| `recon` | `recon-agent` | `scope` | Surface from explicit scope and operator-supplied artifacts |
| `enumeration` | `enumeration-agent` | `recon` | Routes, endpoints, parameters, auth flows and technology from artifacts; bounded broker GETs only when explicitly approved and pinned |
| `vulnerability` | `vulnerability-agent` | `enumeration` | Evidence-backed hypotheses, not confirmations |
| `active-testing` | `active-testing-agent` | `vulnerability` | Hypothesis validation through the scoped HTTP broker and reviewed SHA-256-pinned manifests |
| `validation` | `validation-agent` | `active-testing` | Independent review; the proposer is not the validator |
| `impact` | `impact-analyst` | `validation` | Impact only for independently validated findings |
| `dedupe` | `duplicate-checker` | `impact` | Non-destructive duplicate analysis |
| `reporting` | `reporting-agent` | `dedupe` | Report only validated findings as confirmed; preserve hypotheses and rejected items separately |

Every task must set a valid `domain` and at least one `skill_tags` value that matches a Skill compatible with that agent and domain. Plan generation checks this before persistence; dispatch repeats the check and refuses to run with an empty Skill selection. The selected Skill IDs are returned and recorded in audit telemetry.

## Running

1. Review the official written authorization, scope, exclusions, permitted test classes, test window and limits. A local active flag is an operator attestation record, not independent proof of authorization.
2. Ensure the engagement is explicitly active and approved. If it is not, run only the passive prefix and stop at the active-testing preflight gate; do not claim active validation.
3. Supply operator-reviewed artifacts (for example HAR/Burp exports or API specifications) under the engagement's local evidence workflow. For active HTTP, create request manifests under `.local/requests/`, verify exact scope, and pin each manifest SHA-256 in the active task.
4. Validate the plan against `templates/plan.schema.json`, then execute the persisted DAG with `python scripts/run_plan.py --engagement-id ENG-ID --model MODEL`.
5. Inspect each returned stage: selected Skills, direct prior handoffs, inherited evidence IDs, evidence hashes and task status. Stop on the first blocked, partial or needs-operator handoff.

The active example at `templates/examples/plan.enumeration-first.active.example.json` is a template only. `app.example.test`, the all-zero manifest digest and the placeholder manifest path are not real scope or authorization. Replace them only with exact operator-approved values; never run the example unchanged.

## Evidence and safety invariants

- Evidence is loaded from the engagement project root, integrity-verified by SHA-256, and only redacted text artifacts are inlined into agent context.
- Handoffs may reference only evidence registered to the same engagement and verified by the evidence vault.
- The dispatcher passes only direct dependency handoffs, while inherited evidence references are deduplicated across dependencies.
- Validation is independent; impact requires a completed validation handoff.
- Active tasks require `status=active`, `execution_enabled=true`, `authorization_verified=true`, exact task and engagement scope, and operator-reviewed SHA-256-pinned manifests.
- The broker is bounded HTTP, not a crawler or scanner. It does not provide automatic site crawling, Nmap/Nuclei/sqlmap, browser automation, brute force, DoS, persistence, stealth/evasion, bulk extraction or access to real user data.
- CI and the nine-stage integration test use synthetic fixtures only. They do not contact external targets or establish authorization for a live engagement.
