# Adaptive Testing Planner

**Phase 3 — foundation.** Status: `lab_verified`. Replaces static, repeated test execution
with an evidence-driven planning loop that decides *what to test next*, consuming the
Phase 2 attack graph and feeding results back into it.

## Architecture (separated concerns)

The planner separates the stages the roadmap requires, so the reasoning layer proposes
while a deterministic layer decides:

| Stage | Module |
|---|---|
| Candidate generation | `candidates.py` — from graph evidence (attack paths + per-endpoint families) |
| Policy validation | `policy.py` — deterministic scope/identity/class/approval gate |
| Prioritization | `scoring.py` — transparent weighted score |
| Hypothesis lifecycle + persistence | `hypothesis.py` (table `planner_hypotheses`) |
| Loop / task creation / interpretation / observability | `loop.py` (table `planner_decisions`) |

## Hypothesis model and lifecycle

Each hypothesis (`planner_hypotheses`) carries: category, test class, skill, target entity,
required identity, required state, preconditions, supporting/contradictory evidence,
confidence, proposed test, expected outcomes, risk, state-changing flag, score + breakdown,
and status. Hypotheses deduplicate on a deterministic signature `(engagement, category,
target, identity)`. Lifecycle:

```
PROPOSED → READY → RUNNING → SUPPORTED | REFUTED | INCONCLUSIVE
         ↘ BLOCKED / DEFERRED ↗   (SUPPORTED/REFUTED are terminal)
```

A hypothesis is **not** a finding, and `SUPPORTED` from the executor is not independent
validation — that is Phase 4.

## Candidate generation (context, not spraying)

Candidates come only from enabling evidence:
- **Attack paths**: `propose_attack_paths` (BOLA/IDOR, BFLA) become hypotheses.
- **Per-endpoint families**, each gated: injection (`sqli`, `xss`) only for endpoints that
  accept parameters; `idor_bola` only when an endpoint references an object or carries a
  dynamic id; `ssrf` only for URL-like parameters.

An external proposer (an LLM) supplies additional candidates via `add_proposals` /
`candidate_from_proposal`; they pass through the identical policy and scoring.

## Policy validation (the authority the proposer cannot bypass)

`PolicyValidator` is deterministic and independent of who proposed the hypothesis. It
refuses — never grants — returning `READY` or a `BLOCKED` reason:

- `prohibited_test_class` — class in the engagement's prohibited list.
- `target_out_of_scope` — target URL fails the broker's own scope allowlist
  (`active_executor._validate_request_scope`).
- `identity_not_authorized` — required identity is not a registered control-plane identity.
- `test_class_not_allowed` — class not in `allowed_test_classes`.
- `awaiting_operator_approval_for_state_change` — state-changing test under
  `human_approval_required_for_state_changes` (never auto-run).

So an LLM proposal targeting an out-of-scope endpoint or an unauthorized identity is blocked
and never executed (tested in `test_llm_proposal_cannot_bypass_scope_or_authorization`).

## Prioritization (transparent, not model confidence)

```
score = 0.30·impact + 0.20·evidence + 0.15·exploitability + 0.10·reachability
      + 0.10·coverage_value + 0.05·cost_efficiency + 0.10·confidence_capped
      − 0.15·execution_risk
```

All factors are in [0, 1]; `confidence_capped = min(confidence, 0.6)` and is weighted 0.10,
so model confidence can shift a score by at most 0.06 and never dominates genuine evidence.
Weights are heuristic priors for ranking within an engagement, **not** probabilities, and
every score is persisted with its full breakdown. Limitations: priors are uncalibrated and
category-coarse; they rank, they do not predict.

## The bounded adaptive loop

Each cycle (`AdaptivePlanner.run`): regenerate candidates from the current graph → validate
→ score → persist → select the highest-scoring `READY` within budget → mark the target in
the graph (`TARGETS` edge, which updates coverage) → execute via the injected executor →
interpret the disposition → attach evidence on `SUPPORTED` → record a decision. Because the
target is now covered and the attempt is terminal, the **next cycle selects differently** —
the adaptive property (`test_results_change_subsequent_selection`).

**Bounds and safety**: hard stops on `max_cycles`, `max_tasks`, and the engagement's
`max_requests_per_engagement`. The loop runs **plan-only** (no execution) unless the
engagement is `active`, `execution_enabled` and `authorization_verified` and an executor is
supplied. It never executes anything not marked `READY`, never auto-runs state-changing
tests, and the executor cannot widen authorization — it only reports an observation.

## Observability

Every selected task writes a `planner_decisions` row with: why it was selected (score +
breakdown), the motivating evidence, the alternatives considered and why they were deferred,
the authorization basis (identity + class + policy result), the budget allocated, and the
result.

## Execution seam

The executor is injected — in production it dispatches the test through the scope-enforcing
broker and the validation engine; in tests it is a deterministic fake returning dispositions.
This keeps the planner CI-testable without live traffic, mirroring the browser/auth pattern.

## Tests

`tests/test_adaptive_planner.py` (13): lifecycle transition enforcement, context-driven
candidate generation, the five policy refusals + the valid path, transparent/capped scoring,
the adaptive cycle changing selection within budget, hard task-budget limit, plan-only mode,
an LLM proposal blocked by policy, and decision-record observability.

## Follow-ups

Wire the real executor through the broker + Phase 4 validation engine; feed `GraphQuery`
coverage signals into `coverage_value`; add contradictory-evidence handling and
`DEFERRED→READY` re-activation as validation results arrive.
