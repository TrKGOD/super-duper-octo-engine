"""Adaptive Testing Planner.

An evidence-driven planning loop that decides what to test next. It separates candidate
generation, deterministic policy validation, transparent prioritization, task creation,
execution (through an injected executor), result interpretation and plan update — so the
reasoning layer proposes while a deterministic policy decides what may run.

Invariants:
- The policy layer, not the proposer, authorizes a test. An LLM/external proposal flows
  through the same validation and can never widen scope, use an unauthorized identity, run
  a disallowed/prohibited class, or auto-run a state-changing test.
- The loop is bounded (cycles, tasks, the engagement's request ceiling) and runs plan-only
  unless the engagement is explicitly approved for execution and an executor is supplied.
- A hypothesis is not a finding; SUPPORTED by the executor is not independent validation.
"""
from core.planner.candidates import FAMILIES, candidate_from_proposal, generate_candidates
from core.planner.hypothesis import (Hypothesis, HypothesisStore, PlannerError, STATUSES,
                                      can_transition, hypothesis_id)
from core.planner.loop import AdaptivePlanner, PlannerBudget
from core.planner.policy import PolicyValidator
from core.planner.scoring import CATEGORY_PRIORS, WEIGHTS, score_hypothesis

__all__ = [
    "AdaptivePlanner", "PlannerBudget", "PolicyValidator", "Hypothesis", "HypothesisStore",
    "PlannerError", "STATUSES", "FAMILIES", "CATEGORY_PRIORS", "WEIGHTS", "can_transition",
    "hypothesis_id", "candidate_from_proposal", "generate_candidates", "score_hypothesis",
]
