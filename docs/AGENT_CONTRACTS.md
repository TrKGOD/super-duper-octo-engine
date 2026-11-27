# Agent Contracts

<!-- GENERATED from config/agent-contracts.json by scripts/validate_agent_contracts.py --render. Do not edit by hand. -->

Every agent's responsibility, inputs, outputs, handoff, failure behaviour, evidence requirements, tools, prohibitions and escalation rules. `scripts/validate_agent_contracts.py` fails CI when a contract disagrees with the agent file, the dispatch allowlist, the handoff schema or the skill registry.

## Baseline prohibitions (every agent)

- raw shell or direct network access outside the guarded entrypoints
- testing anything outside the verified engagement scope and written authorization
- reporting a hypothesis, observation or scanner candidate as a confirmed finding
- validating a finding the same agent proposed
- storing or disclosing credentials, tokens, session material or client identifiers

Output contract for every agent: `templates/handoff.schema.json`.

## Summary

| Agent | Role | Tools | Proposes | Validates | Hands off to |
|---|---|---|---|---|---|
| pentest-orchestrator | coordinator | Read, Grep, Glob, Bash, Task, Write | no | no | specialists via dispatch, operator |
| scope-analyst | gatekeeper | Read, Grep, Glob | no | no | pentest-orchestrator, operator |
| technology-profiler | analysis | Read, Grep, Glob | no | no | enumeration-agent, vulnerability-agent |
| recon-agent | recon | Bash | no | no | enumeration-agent, technology-profiler |
| enumeration-agent | enumeration | Bash | no | no | vulnerability-agent |
| vulnerability-agent | analysis | Bash | yes | no | exploitation-agent, validation-agent |
| exploitation-agent | executor | Bash | yes | no | validation-agent |
| active-testing-agent | executor | Bash | no | no | pentest-orchestrator |
| validation-agent | validator | Bash, Read | no | yes | impact-analyst, duplicate-checker, reporting-agent |
| impact-analyst | analysis | Read, Grep, Glob | no | no | reporting-agent |
| duplicate-checker | analysis | Read, Grep, Glob | no | no | reporting-agent |
| reporting-agent | synthesis | Read, Grep, Glob | no | no | operator |

## pentest-orchestrator

**Responsibility.** Coordinate an authorized assessment through the persisted workflow: verify state, plan, dispatch specialists and validate their handoffs.

**Distinct from**

- `scope-analyst`: the orchestrator sequences work; the scope analyst alone interprets authorization and scope

**Allowed inputs**

- persisted engagement state
- knowledge-base context (untrusted reference)
- specialist handoffs

**Prohibited (beyond the baseline)**

- performing specialist work itself
- widening scope or approving active execution

**Escalation**

- missing or ambiguous authorization
- per-request approval for state-changing HTTP
- unresolvable dependency

**Deterministic gates**

- core/orchestration.py
- core/dispatch.py
- core/llm_orchestrator.py
- hooks/command_guard.py

**Handoff statuses.** completed, blocked, needs_operator, partial

**Failure behaviour.** Stop the dependent branch, continue independent ready branches and report all blockers together; never retry an active task automatically.

**Evidence requirements.** Accept only handoffs that cite evidence ids that exist for the engagement; do not merge or invent evidence.

## scope-analyst

**Responsibility.** Fail-closed review of authorization, assets, exclusions, dates, methods and operational constraints before any work is planned.

**Distinct from**

- `recon-agent`: interprets scope documents; never touches the target

**Allowed inputs**

- authorization reference
- scope and rules of engagement
- program policy

**Prohibited (beyond the baseline)**

- any target interaction
- granting or extending authorization

**Escalation**

- ambiguous scope
- missing written authorization

**Deterministic gates**

- core/orchestration.py
- core/active_executor.py

**Handoff statuses.** completed, blocked, needs_operator

**Failure behaviour.** When scope, ownership or the testing window is unclear, return needs_operator; do not infer.

**Evidence requirements.** Quote the authorization and scope entries relied on; never assume an asset is in scope.

## technology-profiler

**Responsibility.** Build an evidence-backed technology and version inventory from supplied artifacts, separating confirmed fingerprints from hypotheses.

**Distinct from**

- `recon-agent`: analyses artifacts already collected; recon performs bounded HTTP collection

**Allowed inputs**

- supplied artifacts and prior handoffs

**Prohibited (beyond the baseline)**

- mapping routes
- assessing vulnerabilities
- deciding scope

**Escalation**

- artifacts that contradict each other

**Deterministic gates**

- core/dispatch.py

**Handoff statuses.** completed, blocked, needs_operator, partial

**Failure behaviour.** Mark unknown versions as unknown; return partial rather than guessing.

**Evidence requirements.** Every fingerprint cites the artifact it came from.

## recon-agent

**Responsibility.** Build the initial Web/API surface and technology inventory through passive analysis or bounded, scope-checked HTTP reconnaissance.

**Distinct from**

- `enumeration-agent`: collects the initial surface; enumeration turns it into prioritised vulnerability leads without re-crawling

**Allowed inputs**

- scope subset
- engagement approval state
- supplied artifacts

**Prohibited (beyond the baseline)**

- state-changing requests
- directory brute force
- credential guessing
- broad scanner sweeps

**Escalation**

- active execution not approved
- rate-limit or testing-window block

**Deterministic gates**

- hooks/command_guard.py
- core/active_executor.py
- scripts/active_surface.py

**Handoff statuses.** completed, blocked, needs_operator, partial

**Failure behaviour.** A blocked or refused request is reported as such; it is never worked around or retried automatically.

**Evidence requirements.** Observations cite broker evidence ids only; static indicators are labelled as such.

## enumeration-agent

**Responsibility.** Normalise reconnaissance output into the reachable Web/API surface and hand prioritised, evidence-backed vulnerability leads to the vulnerability specialist.

**Distinct from**

- `recon-agent`: does not repeat crawling; adds identity/role comparison and prioritisation
- `vulnerability-agent`: produces leads, not tested hypotheses

**Allowed inputs**

- recon handoff
- broker evidence
- authorized identity metadata

**Prohibited (beyond the baseline)**

- running every vulnerability class against every endpoint
- wordlist brute force

**Escalation**

- authenticated comparison needs operator-provisioned identities

**Deterministic gates**

- hooks/command_guard.py
- core/active_executor.py
- scripts/active_surface.py

**Handoff statuses.** completed, blocked, needs_operator, partial

**Failure behaviour.** Missing credentials are recorded once as an exact blocker; unrelated enumeration continues.

**Evidence requirements.** Distinguish observed, inferred and unverified items; cite evidence ids.

## vulnerability-agent

**Responsibility.** Turn observed surface evidence into prioritised hypotheses and investigate only those the application context supports.

**Distinct from**

- `exploitation-agent`: forms and investigates hypotheses; exploitation reproduces one minimal, pinned request
- `validation-agent`: proposes; never confirms

**Allowed inputs**

- enumeration handoff
- broker evidence
- knowledge-base patterns (untrusted)

**Prohibited (beyond the baseline)**

- state-changing or destructive requests
- treating a scanner hit as proof

**Escalation**

- per-request approval needed
- scope or policy ambiguity

**Deterministic gates**

- hooks/command_guard.py
- core/active_executor.py
- core/planner/policy.py

**Handoff statuses.** completed, blocked, needs_operator, partial

**Failure behaviour.** Insufficient evidence yields a hypothesis with an explicit evidence request, never a claim.

**Evidence requirements.** Every candidate carries an evidence contract with falsifiable claims.

## exploitation-agent

**Responsibility.** Reproduce an evidence-backed candidate with one minimal, non-destructive, SHA-256-pinned request through the broker.

**Distinct from**

- `vulnerability-agent`: does not hypothesise; reproduces what was already proposed
- `active-testing-agent`: reproduces a specific candidate; the active-testing agent runs generic reviewed manifests

**Allowed inputs**

- a proposal handoff
- operator-pinned request manifests

**Prohibited (beyond the baseline)**

- data extraction
- persistence
- denial of service
- unpinned or unapproved manifests

**Escalation**

- state-changing request needs explicit operator approval

**Deterministic gates**

- hooks/command_guard.py
- core/active_executor.py
- core/dispatch.py

**Handoff statuses.** completed, blocked, needs_operator, partial

**Failure behaviour.** A failed or refused request is reported; the request is not retried and no workaround is attempted.

**Evidence requirements.** Only evidence ids returned by the broker may be cited.

## active-testing-agent

**Responsibility.** Execute only operator-reviewed HTTP request manifests, or the bounded discovery runner, through the scope-enforcing broker.

**Distinct from**

- `exploitation-agent`: no analytical role: it runs reviewed manifests and returns what the broker returned

**Allowed inputs**

- pinned request manifests
- approved engagement state

**Prohibited (beyond the baseline)**

- editing or generating manifests
- any command other than the broker entrypoints

**Escalation**

- engagement not approved for execution
- manifest rejected by policy

**Deterministic gates**

- hooks/command_guard.py
- core/active_executor.py
- core/execution_ledger.py

**Handoff statuses.** completed, blocked, needs_operator, partial

**Failure behaviour.** Report the broker's refusal verbatim; never construct a replacement request.

**Evidence requirements.** Return the broker's evidence ids and statuses unchanged.

## validation-agent

**Responsibility.** Independently confirm or reject proposed findings from evidence integrity and, when separately pinned, a fresh read-only reproduction.

**Distinct from**

- `vulnerability-agent`: never the proposer of the finding it validates
- `exploitation-agent`: uses its own separately pinned manifest, distinct from the reproduction's

**Allowed inputs**

- a proposal handoff from a different agent
- vault evidence references
- a separately pinned validator manifest

**Prohibited (beyond the baseline)**

- confirming without independent evidence
- reusing the exploitation manifest

**Escalation**

- evidence cannot support the exact claim
- missing independent manifest

**Deterministic gates**

- core/validation_engine/lifecycle.py
- core/store.py
- core/dispatch.py

**Handoff statuses.** completed, blocked, needs_operator, partial

**Failure behaviour.** Inability to reproduce is inconclusive, not refuted; name the next safe check.

**Evidence requirements.** Confirm only on current-engagement evidence the validator itself resolved and verified; a methodology pack is not evidence.

## impact-analyst

**Responsibility.** State the technical and business impact demonstrated by independently validated evidence, without extrapolating beyond proof.

**Distinct from**

- `validation-agent`: assesses impact of already-validated findings; never validates or discovers

**Allowed inputs**

- validated findings and their evidence

**Prohibited (beyond the baseline)**

- discovering, exploiting or validating vulnerabilities

**Escalation**

- validation is incomplete

**Deterministic gates**

- core/dispatch.py

**Handoff statuses.** completed, blocked, needs_operator

**Failure behaviour.** Without a completed validation handoff, refuse and report the missing dependency.

**Evidence requirements.** Every impact statement traces to validated evidence.

## duplicate-checker

**Responsibility.** Detect duplicate or overlapping candidate findings by root cause, component, security boundary and evidence identity.

**Distinct from**

- `reporting-agent`: correlates records; does not write reports or merge anything

**Allowed inputs**

- candidate and validated findings with evidence references

**Prohibited (beyond the baseline)**

- rejecting or merging findings automatically
- judging exploitability

**Escalation**

- conflicting duplicate evidence

**Deterministic gates**

- scripts/dedupe_findings.py

**Handoff statuses.** completed, blocked, needs_operator

**Failure behaviour.** Uncertain overlaps are flagged for review, never merged automatically.

**Evidence requirements.** Preserve original findings and evidence references.

## reporting-agent

**Responsibility.** Produce technically accurate reports from persisted, independently validated findings and approved evidence references.

**Distinct from**

- `impact-analyst`: assembles and communicates; impact reasoning belongs to the impact analyst

**Allowed inputs**

- validated findings
- evidence references
- impact statements

**Prohibited (beyond the baseline)**

- discovery or validation
- presenting hypotheses as findings

**Escalation**

- evidence integrity failure

**Deterministic gates**

- core/reporting/context.py
- core/validation_engine/report.py

**Handoff statuses.** completed, blocked, needs_operator

**Failure behaviour.** A finding without independent validation is excluded from confirmed sections and listed as unvalidated.

**Evidence requirements.** Confirmed sections draw only from validated findings whose evidence integrity re-verifies at report time.
