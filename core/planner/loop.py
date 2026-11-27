"""Bounded adaptive planning loop.

Each cycle: regenerate candidates from the *current* graph state, validate them against the
deterministic policy, score and persist them, select the highest-scoring READY hypotheses
within budget, execute each through an injected executor, interpret the result, and fold it
back into the graph and coverage — so the next cycle's selection reflects what was learned.

Hard stops bound the loop (cycles, tasks, the engagement's own request ceiling). The loop
never executes anything the policy did not mark READY, never auto-runs state-changing tests,
and runs in plan-only mode unless the engagement is explicitly approved for execution and an
executor is supplied. The LLM/executor proposes and observes; it cannot widen authorization.

Robustness guarantees
* An executor that raises never strands a hypothesis in ``RUNNING``: the failure is classified,
  recorded and the hypothesis becomes ``INCONCLUSIVE`` (a programming error is recorded, then
  re-raised so it is not hidden).
* After a crash, hypotheses left ``RUNNING`` are recovered at the start of the next run; one whose
  execution still needs an operator stays ``BLOCKED`` until it is resolved. Nothing re-runs.
* A tested hypothesis is retried only when the facts around it *changed* (see ``context.py``) and
  only up to ``max_attempts_per_hypothesis``; identical retries are never issued.
* With ``require_validation_record=True`` a SUPPORTED/REFUTED disposition must reference a
  validation record, otherwise it is downgraded to INCONCLUSIVE: the executor's own opinion is
  never a confirmation.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from core.errors import classify_exception
from core.graph.query import GraphQuery
from core.graph.store import AttackGraph
from core.planner.candidates import candidate_from_proposal, generate_candidates
from core.planner.context import fingerprint
from core.planner.hypothesis import HypothesisStore, PlannerError
from core.planner.policy import PolicyValidator
from core.planner.scoring import score_hypothesis
from core.redaction import redact, redact_value
from core.store import utc_now

_UNRESOLVED_EXECUTION = ("INTERRUPTED", "RECONCILIATION_REQUIRED")


@dataclass
class PlannerBudget:
    max_cycles: int = 5
    max_tasks: int = 20
    select_per_cycle: int = 3
    max_candidates_per_cycle: int = 200
    max_attempts_per_hypothesis: int = 2

    def validate(self) -> "PlannerBudget":
        if not 1 <= self.max_cycles <= 50:
            raise PlannerError("max_cycles must be 1..50")
        if not 1 <= self.max_tasks <= 500:
            raise PlannerError("max_tasks must be 1..500")
        if not 1 <= self.select_per_cycle <= 50:
            raise PlannerError("select_per_cycle must be 1..50")
        if not 1 <= self.max_attempts_per_hypothesis <= 5:
            raise PlannerError("max_attempts_per_hypothesis must be 1..5")
        return self


class AdaptivePlanner:
    def __init__(self, store, engagement_id: str, graph: AttackGraph, *, executor=None,
                 budget: PlannerBudget | None = None, audit=None,
                 require_validation_record: bool = False, execution_status=None):
        self.store = store
        self.engagement_id = engagement_id
        self.graph = graph
        self.executor = executor
        self.budget = (budget or PlannerBudget()).validate()
        self.audit = audit or (lambda event, details: None)
        self.require_validation_record = require_validation_record
        self.execution_status = execution_status      # callable(hypothesis_row) -> ledger status | None
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
             hyp_row["score"], json.dumps(redact_value(rationale), sort_keys=True, default=str),
             json.dumps(redact_value(result), sort_keys=True, default=str) if result is not None else None,
             utc_now()))
        self.store.connection.commit()

    # -- graph feedback ----------------------------------------------------------------
    def _hypothesis_node(self, hyp_row):
        """The graph node carrying a hypothesis; created before it is run so its outcome can attach."""
        if not hyp_row["target_node_id"]:
            return None
        target = self.graph.get_node_by_id(hyp_row["target_node_id"])
        if target is None or target["node_type"] not in ("endpoint", "route", "object", "parameter"):
            return None
        return self.graph.upsert_node("hypothesis", hyp_row["hypothesis_id"],
                                      label=hyp_row["category"], trust="inferred",
                                      provenance=[{"source": "planner"}], confidence=hyp_row["confidence"])

    def _mark_targeted(self, hyp_row):
        """Record coverage: the target was *actually* tested. Only called after a real execution —
        an attempt that was refused or has no automated executor must not count as coverage."""
        node = self._hypothesis_node(hyp_row)
        if node is not None:
            self.graph.upsert_edge(node, "TARGETS", hyp_row["target_node_id"], trust="inferred",
                                   provenance=[{"source": "planner"}])

    def _record_outcome(self, hyp_row, disposition, result):
        """Fold the outcome into the graph: the hypothesis node carries its disposition and the
        evidence that supports or validates it, so the next cycle (and any query) sees it."""
        node_id = self.graph.node_id("hypothesis", hyp_row["hypothesis_id"])
        if self.graph.get_node_by_id(node_id) is None:
            return
        record_id = result.get("validation_record_id")
        self.graph.upsert_node("hypothesis", hyp_row["hypothesis_id"], label=hyp_row["category"],
                               attributes={"disposition": disposition,
                                           **({"validation_record_id": record_id} if record_id else {})},
                               trust="inferred", provenance=[{"source": "planner"}],
                               confidence=hyp_row["confidence"])
        if disposition != "SUPPORTED":
            return
        for ref in result.get("evidence_refs", []) or []:
            evidence = self.graph.upsert_node("evidence", str(ref), trust="observed",
                                              provenance=[{"source": "planner"}], confidence=0.6)
            self.graph.upsert_edge(evidence, "SUPPORTS", node_id, trust="observed",
                                   provenance=[{"source": "planner"}], evidence_refs=[str(ref)])
            if record_id:
                self.graph.upsert_edge(node_id, "VALIDATED_BY", evidence, trust="observed",
                                       provenance=[{"source": "validation-engine", "record": record_id}],
                                       evidence_refs=[str(ref)])

    # -- candidate refresh ---------------------------------------------------------------
    def _awaiting_reconciliation(self, row) -> bool:
        if row["status_reason"] != "awaiting_reconciliation" or self.execution_status is None:
            return False
        return self.execution_status(row) in _UNRESOLVED_EXECUTION

    def _refresh_candidates(self, cycle: int = 0):
        targeted = self._targeted_endpoint_ids()
        for candidate in generate_candidates(self.graph, self.engagement_id)[:self.budget.max_candidates_per_cycle]:
            self.hyp.upsert(candidate)
        # Validate and score every non-terminal hypothesis (generated and externally proposed),
        # so an external proposal is subject to exactly the same policy as a generated one.
        for row in self.hyp.list():
            if row["status"] in ("SUPPORTED", "REFUTED", "RUNNING"):
                continue
            if row["status"] == "BLOCKED" and self._awaiting_reconciliation(row):
                continue                       # an unresolved execution must be settled by an operator
            if row["status"] == "BLOCKED" and row["status_reason"] == "awaiting_reconciliation":
                # The operator has since resolved the execution. Whatever they concluded is new
                # information about that attempt, so clear its context fingerprint: it may be
                # retried once (still bounded by max_attempts_per_hypothesis).
                self.hyp.record_attempt(row["hypothesis_id"], "")
            status, reason = self.policy.validate(row)
            coverage_gap = row["target_node_id"] not in targeted
            score, breakdown = score_hypothesis(row, coverage_gap=coverage_gap)
            self.hyp.set_score(row["hypothesis_id"], score, breakdown)
            if row["status"] == "INCONCLUSIVE" and status == "READY" and not self._eligible(row):
                # An inconclusive result stays visible as INCONCLUSIVE until a retry is actually
                # justified; flipping it back to READY every cycle erased the outcome from reports.
                continue
            if row["status"] != status:
                self.hyp.set_status(row["hypothesis_id"], status, reason)
                if status == "BLOCKED":        # record *why* it was rejected, not only what was selected
                    self._record_decision(cycle, {**row, "status": status}, selected=False, rationale={
                        "rejected_by": "deterministic_policy", "reason": reason,
                        "category": row["category"], "test_class": row["test_class"]})

    # -- recovery ----------------------------------------------------------------------------
    def _recover_interrupted(self):
        """Hypotheses still RUNNING belong to a run that never finished (a crash). They are never
        silently trusted nor re-run: settle them so the loop can make progress or wait."""
        for row in self.hyp.list("RUNNING"):
            if self.execution_status is not None and self.execution_status(row) in _UNRESOLVED_EXECUTION:
                self.hyp.set_status(row["hypothesis_id"], "BLOCKED", "awaiting_reconciliation")
            else:
                self.hyp.set_status(row["hypothesis_id"], "INCONCLUSIVE", "interrupted_before_result")
            self.audit("planner.recovered_running_hypothesis", {"hypothesis_id": row["hypothesis_id"]})

    # -- selection / execution ------------------------------------------------------------------
    def _eligible(self, row) -> bool:
        """New hypotheses are always eligible; a retried one needs a *changed* context."""
        if row["attempts"] == 0:
            return True
        if row["attempts"] >= self.budget.max_attempts_per_hypothesis:
            return False
        return fingerprint(self.graph, row) != row["attempt_fingerprint"]

    def _execute(self, hyp_row) -> dict:
        try:
            result = self.executor(dict(hyp_row))
        except Exception as exc:  # noqa: BLE001 - classified, recorded, and re-raised if it is a bug
            failure_class = classify_exception(exc)
            self.audit("planner.executor_failed", {"hypothesis_id": hyp_row["hypothesis_id"],
                                                   "failure_class": failure_class})
            result = {"disposition": "INCONCLUSIVE", "reason": "executor_error:" + failure_class,
                      "executor_error": redact(str(exc))[:300], "evidence_refs": []}
            if failure_class == "programming_error":
                self.hyp.set_status(hyp_row["hypothesis_id"], "INCONCLUSIVE", result["reason"])
                self._record_decision(-1, self.hyp.get(hyp_row["hypothesis_id"]), selected=True,
                                      rationale={"executor_failed": failure_class}, result=result)
                raise
        if not isinstance(result, dict):
            result = {"disposition": "INCONCLUSIVE", "reason": "executor_returned_a_non_mapping"}
        return result

    def run(self) -> dict:
        execution_enabled = self._execution_enabled()
        tasks_used = 0
        cycles_run = 0
        stop_reason = None
        self._recover_interrupted()
        for cycle in range(self.budget.max_cycles):
            cycles_run = cycle + 1
            self._refresh_candidates(cycle)
            ready = [h for h in self.hyp.list("READY") if self._eligible(h)]
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
                retry = hyp_row["attempts"] > 0
                rationale = {
                    "why_selected": ("retried: the facts around it changed since attempt "
                                     f"{hyp_row['attempts']}" if retry else
                                     f"highest-scoring READY candidate ({hyp_row['score']})"),
                    "score_breakdown": hyp_row["score_breakdown"],
                    "evidence": hyp_row["supporting_evidence"],
                    "alternatives_considered": [{"id": a["hypothesis_id"], "score": a["score"]} for a in deferred],
                    "alternatives_deferred_reason": "lower priority score this cycle",
                    "authorization": {"required_identity": hyp_row["required_identity"],
                                      "test_class": hyp_row["test_class"], "policy": "READY"},
                    "budget_allocated": {"tasks": 1, "remaining_before": self.max_tasks - tasks_used},
                    "outstanding_evidence_requests": hyp_row["evidence_requests"],
                }
                self.hyp.set_status(hyp_row["hypothesis_id"], "RUNNING")
                self.hyp.record_attempt(hyp_row["hypothesis_id"], fingerprint(self.graph, hyp_row))
                self._hypothesis_node(hyp_row)
                result = self._execute(hyp_row)
                disposition = result.get("disposition", "INCONCLUSIVE")
                if disposition not in ("SUPPORTED", "REFUTED", "INCONCLUSIVE"):
                    disposition = "INCONCLUSIVE"
                if (self.require_validation_record and disposition in ("SUPPORTED", "REFUTED")
                        and not result.get("validation_record_id")):
                    result = {**result, "reason": "disposition_without_validation_record"}
                    disposition = "INCONCLUSIVE"
                self.hyp.set_status(hyp_row["hypothesis_id"], disposition, result.get("reason"))
                evidence_refs = result.get("evidence_refs", [])
                if evidence_refs:
                    self.hyp.add_evidence(hyp_row["hypothesis_id"], evidence_refs)
                self.hyp.set_evidence_requests(hyp_row["hypothesis_id"], result.get("evidence_requests", []))
                self.hyp.set_last_execution(hyp_row["hypothesis_id"], result.get("execution_id"))
                if result.get("executed", True):          # executors that omit the flag really ran
                    self.hyp.mark_executed(hyp_row["hypothesis_id"])
                    self._mark_targeted(hyp_row)
                self._record_outcome(hyp_row, disposition, result)
                # Re-record the context *after* the attempt: whatever the executor itself wrote to the
                # graph while testing (observed accesses, evidence) must not look like new information.
                self.hyp.record_attempt(hyp_row["hypothesis_id"], fingerprint(self.graph, hyp_row))
                self._record_decision(cycle, self.hyp.get(hyp_row["hypothesis_id"]), selected=True,
                                      rationale=rationale, result=result)
                tasks_used += 1
            if stop_reason == "task_budget_exhausted":
                break
        else:
            stop_reason = stop_reason or "max_cycles_reached"
        return self._report(cycles_run, tasks_used, execution_enabled, stop_reason)

    # -- reporting ------------------------------------------------------------------------------
    def coverage(self) -> dict:
        """Per test class: what was attempted and how it came out; plus what was never targeted."""
        by_class: dict = {}
        for hyp in self.hyp.list():
            bucket = by_class.setdefault(hyp["test_class"], {
                "hypotheses": 0, "attempted": 0, "SUPPORTED": 0, "REFUTED": 0, "INCONCLUSIVE": 0,
                "BLOCKED": 0, "awaiting_operator": 0})
            bucket["hypotheses"] += 1
            bucket["attempted"] += 1 if hyp["executed"] else 0
            if hyp["status"] in ("SUPPORTED", "REFUTED", "INCONCLUSIVE", "BLOCKED"):
                bucket[hyp["status"]] += 1
            if hyp["status"] == "BLOCKED" and "operator" in str(hyp["status_reason"]):
                bucket["awaiting_operator"] += 1
        untested = [node["key"] for node in GraphQuery(self.graph).low_coverage_endpoints()]
        return {"by_test_class": by_class, "untested_endpoints": untested}

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
            "pending_evidence_requests": [
                {"hypothesis_id": h["hypothesis_id"], "category": h["category"], "requests": h["evidence_requests"]}
                for h in self.hyp.list("INCONCLUSIVE") + self.hyp.list("READY") if h["evidence_requests"]],
            "coverage": self.coverage(),
            "note": "Hypotheses are candidates; SUPPORTED here means the injected executor reported "
                    "support (with require_validation_record=True: backed by a validation record) and "
                    "is not a substitute for independent validation of the finding.",
        }
