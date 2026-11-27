"""One coherent investigative lifecycle.

    OBSERVATION            guarded same-origin discovery through the broker  -> graph (observed trust)
    -> HYPOTHESIS          planner candidate generation from graph facts
    -> PRIORITISATION      transparent scoring
    -> POLICY              deterministic validator (scope, identity, test class, state change)
    -> TOOL SELECTION      registry + execution-profile policy (RESTRICTED never auto-selected)
    -> AUTHORIZED EXECUTION broker only; every request is a ledger execution with linked evidence
    -> EVIDENCE            vault, SHA-256, engagement- and execution-linked
    -> INDEPENDENT VALIDATION  validation engine on vault-resolved evidence; proposer != validator
    -> GRAPH + COVERAGE    observed access, finding node, validation edges, per-class coverage
    -> NEXT CYCLE          retries only when the facts around a hypothesis changed

``AssessmentPipeline`` owns no logic of its own: it wires the existing components together and
reports the result. The planner decides *what* to test, the executor *does* it, the validator
*judges* it, and none of them can overrule the others.
"""
from __future__ import annotations

import uuid
from urllib.parse import urlsplit

from core.execution_ledger import ExecutionLedger
from core.graph.ingest import GraphIngestor
from core.graph.store import AttackGraph
from core.pipeline.discovery import project_discovery
from core.pipeline.executor import PipelineExecutor
from core.pipeline.identities import IdentityDirectory
from core.planner import AdaptivePlanner, PlannerBudget


class AssessmentPipeline:
    def __init__(self, workflow, engagement_id: str, identities: IdentityDirectory, *, registry=None,
                 budget: PlannerBudget | None = None, project_root=None, audit=None):
        self.workflow = workflow
        self.engagement_id = engagement_id
        self.budget = budget
        self.audit = audit or (lambda event, details: None)
        self.graph = AttackGraph(workflow.store.connection, engagement_id)
        self.ingestor = GraphIngestor(self.graph)
        self.ledger = ExecutionLedger(workflow.store.connection)
        self.executor = PipelineExecutor(workflow, engagement_id, self.graph, identities,
                                         registry=registry, project_root=project_root, audit=self.audit)

    # -- observation ---------------------------------------------------------------------------------
    def observe(self, report: dict, *, origin: str) -> dict:
        """Project an existing discovery report into the graph."""
        return project_discovery(self.ingestor, report, origin=origin)

    def discover(self, url: str, *, max_pages: int = 10, max_depth: int = 2) -> dict:
        """Run the guarded same-origin discovery runner for ``url`` and project what it saw."""
        from scripts.active_surface import run_discovery      # imported late: the runner pulls in the broker
        parsed = urlsplit(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        subset = self.executor._scope_subset(url)
        if not subset:
            raise ValueError("The discovery target is not covered by an explicit engagement asset")
        created = self.workflow.create_plan(self.engagement_id, {"tasks": [{
            "task_key": "pipeline-discovery-" + uuid.uuid4().hex[:10], "agent": "recon-agent",
            "objective": "Same-origin surface discovery for " + origin,
            "completion_criteria": ["Surface mapped through the broker with evidence"],
            "scope_subset": subset, "domain": "web", "skill_tags": ["passive-recon"], "active_testing": True}]})
        task_id = created[0]["task_id"]
        self.workflow.start_task(task_id, model="deterministic-pipeline")
        report = run_discovery(self.workflow.store.db_path, self.engagement_id, task_id, url,
                               max_pages=max_pages, max_depth=max_depth,
                               project_root=self.executor.project_root)
        projected = project_discovery(self.ingestor, report, origin=origin)
        try:
            self.workflow.accept_handoff(task_id, {
                "task_id": task_id, "engagement_id": self.engagement_id, "agent": "recon-agent",
                "status": "completed" if report.get("status") == "completed" else "blocked",
                "scope_subset": subset, "summary": f"Mapped {projected['endpoints']} endpoint(s).",
                "observations": [], "hypotheses": [], "evidence_refs": list(report.get("evidence_refs", [])),
                "limitations": ["Static, same-origin GET/OPTIONS discovery only."]})
        except Exception as exc:  # noqa: BLE001 - the task must not stay 'running'; the reason is recorded
            self.audit("pipeline.discovery_handoff_rejected", {"task_id": task_id, "reason": str(exc)[:200]})
            self.workflow.store.update_task(task_id, "failed", {"handoff_error": str(exc)[:200]})
        return {"report": report, "projected": projected, "task_id": task_id}

    # -- investigation -------------------------------------------------------------------------------
    def _execution_status(self, hypothesis_row):
        """Ledger status behind a hypothesis: one execution, or the worst of a task's executions."""
        reference = hypothesis_row.get("last_execution_id")
        if not reference:
            return None
        try:
            if reference.startswith("task:"):
                statuses = [e["status"] for e in self.ledger.list(self.engagement_id, task_id=reference[5:])]
                for unresolved in ("RECONCILIATION_REQUIRED", "INTERRUPTED", "RUNNING", "AUTHORIZED",
                                   "QUEUED", "CREATED"):
                    if unresolved in statuses:
                        return unresolved
                return statuses[-1] if statuses else None
            return self.ledger.get(reference, self.engagement_id)["status"]
        except Exception:  # noqa: BLE001 - an unknown reference simply has no known status
            return None

    def run(self) -> dict:
        """Reconcile anything a previous process left half-done, then run the planning loop."""
        reconciled = self.ledger.reconcile_stale(engagement_id=self.engagement_id)
        # A fresh planner each run: it re-reads the engagement's status and rules, so a pause or a
        # revoked approval takes effect immediately.
        planner = AdaptivePlanner(
            self.workflow.store, self.engagement_id, self.graph, executor=self.executor, budget=self.budget,
            audit=self.audit, require_validation_record=True, execution_status=self._execution_status)
        report = planner.run()
        report["reconciled_executions"] = reconciled
        report["pending_operator_reconciliation"] = [
            {"execution_id": e["execution_id"], "status": e["status"], "tool_id": e["tool_id"]}
            for e in self.ledger.pending_reconciliation(self.engagement_id)]
        report["executions_by_status"] = self._execution_counts()
        return report

    def _execution_counts(self) -> dict:
        counts: dict = {}
        for execution in self.ledger.list(self.engagement_id):
            counts[execution["status"]] = counts.get(execution["status"], 0) + 1
        return counts
