"""Bounded adaptive planning loop.

Each cycle: regenerate candidates from the *current* graph state, validate them against the
deterministic policy, score and persist them, select the highest-scoring READY hypotheses
within budget, execute each through an injected executor, interpret the result, and fold it
back into the graph and coverage — so the next cycle's selection reflects what was learned.

Hard stops bound the loop (cycles, tasks, the engagement's own request ceiling). The loop
never executes anything the policy did not mark READY, never auto-runs state-changing tests,
and runs in plan-only mode unless the engagement is explicitly approved for execution and an
executor is supplied. The LLM/executor proposes and observes; it cannot widen authorization.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from core.graph.store import AttackGraph
from core.planner.candidates import candidate_from_proposal, generate_candidates
from core.planner.hypothesis import HypothesisStore, PlannerError
from core.planner.policy import PolicyValidator
from core.planner.scoring import score_hypothesis
from core.store import utc_now


@dataclass
class PlannerBudget:
    max_cycles: int = 5
    max_tasks: int = 20
    select_per_cycle: int = 3
    max_candidates_per_cycle: int = 200

    def validate(self) -> "PlannerBudget":
        if not 1 <= self.max_cycles <= 50:
            raise PlannerError("max_cycles must be 1..50")
        if not 1 <= self.max_tasks <= 500:
            raise PlannerError("max_tasks must be 1..500")
        if not 1 <= self.select_per_cycle <= 50:
            raise PlannerError("select_per_cycle must be 1..50")
        return self


class AdaptivePlanner:
    def __init__(self, store, engagement_id: str, graph: AttackGraph, *, executor=None,
                 budget: PlannerBudget | None = None, audit=None):
        self.store = store
        self.engagement_id = engagement_id
        self.graph = graph
        self.executor = executor
        self.budget = (budget or PlannerBudget()).validate()
        self.audit = audit or (lambda event, details: None)
        self.hyp = HypothesisStore(store.connection, engagement_id)
        self._load_engagement()
        self.policy = PolicyValidator(self.scope, self.rules, graph)
        ceiling = self.rules.get("max_requests_per_engagement", self.budget.max_tasks)
        self.max_tasks = min(self.budget.max_tasks, ceiling if isinstance(ceiling, int) and ceiling > 0 else self.budget.max_tasks)

    def _load_engagement(self):
        row = self.store.connection.execute(
            "SELECT status,scope_json,rules_json FROM engagements WHERE engagement_id=?",
            (self.engagement_id,)).fetchone()
        if row is None:
            raise PlannerError("Unknown engagement: " + str(self.engagement_id))
        self.status = row["status"]
        self.scope = json.loads(row["scope_json"])
        self.rules = json.loads(row["rules_json"])

    def _execution_enabled(self) -> bool:
        return (self.executor is not None and self.status == "active"
                and self.rules.get("execution_enabled") is True
                and self.rules.get("authorization_verified") is True)

    def _targeted_endpoint_ids(self) -> set:
        return {edge["dst"] for edge in self.graph.edges("TARGETS")}

    def add_proposals(self, proposals, *, source: str) -> list[str]:
        """Accept external (e.g. LLM) candidate proposals. They still pass policy + scoring."""
        ids = []
        for proposal in proposals:
            hyp = candidate_from_proposal(self.engagement_id, proposal)
            ids.append(self.hyp.upsert(hyp))
            self.audit("planner.proposal_received", {"source": source, "category": hyp.category})
        return ids

    def _record_decision(self, cycle, hyp_row, *, selected, rationale, result=None):
        self.store.connection.execute(
            "INSERT INTO planner_decisions(engagement_id,cycle,hypothesis_id,selected,score,"
            "rationale_json,result_json,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (self.engagement_id, cycle, hyp_row["hypothesis_id"], 1 if selected else 0,
             hyp_row["score"], json.dumps(rationale, sort_keys=True),
             json.dumps(result) if result is not None else None, utc_now()))
        self.store.connection.commit()

    def _mark_targeted(self, hyp_row):
        """Reflect an attempted hypothesis into the graph so coverage/selection update."""
        if not hyp_row["target_node_id"]:
            return
        target = self.graph.get_node_by_id(hyp_row["target_node_id"])
        if target is None or target["node_type"] not in ("endpoint", "route", "object", "parameter"):
            return
        node = self.graph.upsert_node("hypothesis", hyp_row["hypothesis_id"],
                                      label=hyp_row["category"], trust="inferred",
                                      provenance=[{"source": "planner"}], confidence=hyp_row["confidence"])
        self.graph.upsert_edge(node, "TARGETS", hyp_row["target_node_id"], trust="inferred",
                               provenance=[{"source": "planner"}])

    def _attach_support(self, hyp_row, evidence_refs):
        node_id = self.graph.node_id("hypothesis", hyp_row["hypothesis_id"])
        if self.graph.get_node_by_id(node_id) is None:
            return
        for ref in evidence_refs:
            ev = self.graph.upsert_node("evidence", str(ref), trust="observed",
                                        provenance=[{"source": "planner"}], confidence=0.6)
            self.graph.upsert_edge(ev, "SUPPORTS", node_id, trust="observed",
                                   provenance=[{"source": "planner"}], evidence_refs=[str(ref)])

    def _refresh_candidates(self):
        targeted = self._targeted_endpoint_ids()
        for candidate in generate_candidates(self.graph, self.engagement_id)[:self.budget.max_candidates_per_cycle]:
            self.hyp.upsert(candidate)
        # Validate and score every non-terminal hypothesis (generated and externally proposed),
        # so an external proposal is subject to exactly the same policy as a generated one.
        for row in self.hyp.list():
            if row["status"] in ("SUPPORTED", "REFUTED", "RUNNING"):
                continue
            status, reason = self.policy.validate(row)
            coverage_gap = row["target_node_id"] not in targeted
            score, breakdown = score_hypothesis(row, coverage_gap=coverage_gap)
            self.hyp.set_score(row["hypothesis_id"], score, breakdown)
            if row["status"] != status:
                self.hyp.set_status(row["hypothesis_id"], status, reason)

    def run(self) -> dict:
        execution_enabled = self._execution_enabled()
        tasks_used = 0
        cycles_run = 0
        stop_reason = None
        for cycle in range(self.budget.max_cycles):
            cycles_run = cycle + 1
            self._refresh_candidates()
            ready = [h for h in self.hyp.list("READY") if h["attempts"] == 0]
            if not ready:
                stop_reason = "no_ready_candidates"
                break
            if not execution_enabled:
                for hyp_row in ready[:self.budget.select_per_cycle]:
                    self._record_decision(cycle, hyp_row, selected=False, rationale={
                        "mode": "plan_only",
                        "reason": "engagement not approved for execution or no executor supplied",
                        "score_breakdown": hyp_row["score_breakdown"]})
                stop_reason = "plan_only"
                break
            selected = ready[:self.budget.select_per_cycle]
            deferred = ready[self.budget.select_per_cycle:self.budget.select_per_cycle + 5]
            for hyp_row in selected:
                if tasks_used >= self.max_tasks:
                    stop_reason = "task_budget_exhausted"
                    break
                rationale = {
                    "why_selected": f"highest-scoring READY candidate ({hyp_row['score']})",
                    "score_breakdown": hyp_row["score_breakdown"],
                    "evidence": hyp_row["supporting_evidence"],
                    "alternatives_considered": [{"id": a["hypothesis_id"], "score": a["score"]} for a in deferred],
                    "alternatives_deferred_reason": "lower priority score this cycle",
                    "authorization": {"required_identity": hyp_row["required_identity"],
                                      "test_class": hyp_row["test_class"], "policy": "READY"},
                    "budget_allocated": {"tasks": 1, "remaining_before": self.max_tasks - tasks_used},
                }
                self.hyp.set_status(hyp_row["hypothesis_id"], "RUNNING")
                self._mark_targeted(hyp_row)
                result = self.executor(dict(hyp_row)) or {}
                disposition = result.get("disposition", "INCONCLUSIVE")
                if disposition not in ("SUPPORTED", "REFUTED", "INCONCLUSIVE"):
                    disposition = "INCONCLUSIVE"
                self.hyp.set_status(hyp_row["hypothesis_id"], disposition, result.get("reason"))
                evidence_refs = result.get("evidence_refs", [])
                if evidence_refs:
                    self.hyp.add_evidence(hyp_row["hypothesis_id"], evidence_refs)
                if disposition == "SUPPORTED" and evidence_refs:
                    self._attach_support(hyp_row, evidence_refs)
                self._record_decision(cycle, self.hyp.get(hyp_row["hypothesis_id"]), selected=True,
                                      rationale=rationale, result=result)
                tasks_used += 1
            if stop_reason == "task_budget_exhausted":
                break
        else:
            stop_reason = stop_reason or "max_cycles_reached"
        return self._report(cycles_run, tasks_used, execution_enabled, stop_reason)

    def _report(self, cycles_run, tasks_used, execution_enabled, stop_reason) -> dict:
        by_status = {}
        for hyp in self.hyp.list():
            by_status.setdefault(hyp["status"], 0)
            by_status[hyp["status"]] += 1
        return {
            "engagement_id": self.engagement_id,
            "cycles_run": cycles_run,
            "tasks_used": tasks_used,
            "task_ceiling": self.max_tasks,
            "execution_enabled": execution_enabled,
            "stop_reason": stop_reason,
            "hypotheses_by_status": by_status,
            "supported": [h["hypothesis_id"] for h in self.hyp.list("SUPPORTED")],
            "note": "Hypotheses are candidates; SUPPORTED here means the injected executor reported "
                    "support and is not a substitute for independent validation (Phase 4).",
        }
