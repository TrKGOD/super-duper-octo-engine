# Agent specialization contracts

This directory defines distinct responsibilities, not interchangeable personas. The orchestrator owns task ordering and persisted state; specialists produce bounded outputs and never self-assign work.

## Specialist boundaries

| Agent | Owns | Must not do |
|---|---|---|
| scope-analyst | Authorization, allowlist, exclusions, time window, permitted methods | Discover or contact assets; infer authorization |
| recon-agent | Passive asset inventory and source correlation from supplied data | Route enumeration or vulnerability claims |
| technology-profiler | Technology/version fingerprints with confidence and evidence | Treat fingerprints as vulnerabilities |
| enumeration-agent | Routes, API operations, parameters, auth context from supplied captures/specs | Vulnerability severity or exploitation |
| vulnerability-agent | Evidence-backed candidate hypotheses and safe validation requirements | Mark findings validated or reported |
| exploitation-agent | Non-destructive reproduction package drafts | Execute requests, exploit targets, fabricate results |
| validation-agent | Independent review of current-engagement evidence | Validate own candidate or fill evidence gaps |
| impact-analyst | Demonstrated versus conditional technical/business impact | Validate, change severity, or invent business context |
| duplicate-checker | Finding correlation and duplicate likelihood | Merge/reject records or discard provenance |
| reporting-agent | Client-facing report from validated records | Report hypotheses as confirmed |

## Common task contract

Every task should carry: engagement ID, task ID/key, assigned agent, objective, exact scope subset, dependencies, supplied evidence IDs, expected outputs, completion criteria, prohibited actions, and explicit execution mode. The current runtime remains passive-only.

Every handoff should include:
- task and engagement identity;
- status and concise result;
- evidence IDs (never invented paths or IDs);
- observations separated from hypotheses;
- limitations, unresolved questions, and next-step recommendation;
- explicit statement of any proposed-but-not-executed action.

## Lifecycle boundaries

- Recon, technology profiling, enumeration, and vulnerability analysis may produce observations or candidate hypotheses.
- Exploitation agent drafts reproduction artifacts only; proposed requests are not proof.
- Only validation-agent may provide an independent validation decision, and it must not be the original proposer.
- Impact analysis consumes validated findings and cannot upgrade their state.
- Reporting consumes validated findings or explicitly approved reportable records.
- Duplicate checking recommends human disposition; it never mutates findings.

## Design rule

A specialist's completion criteria are part of its contract. Do not replace a specialist with a generic prompt or grant it additional tools to compensate for unclear responsibilities. Add capability only with tests for scope, evidence provenance, and lifecycle behavior.
