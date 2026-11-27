"""Adaptive planner robustness: failure containment, recovery, justified retries, evidence-backed outcomes."""
import unittest

from core.planner import AdaptivePlanner, PlannerBudget
from core.planner.context import fingerprint
from tests.test_adaptive_planner import PlannerTestBase


class Scripted:
    """Executor with per-category scripted behaviour, recording every call."""

    def __init__(self, behaviour):
        self.behaviour, self.calls = behaviour, []

    def __call__(self, hypothesis):
        self.calls.append((hypothesis["category"], hypothesis["hypothesis_id"]))
        action = self.behaviour.get(hypothesis["category"], {"disposition": "REFUTED"})
        if isinstance(action, BaseException):
            raise action
        return dict(action() if callable(action) else action)

    def count(self, category):
        return sum(1 for c, _ in self.calls if c == category)


def planner(base, executor, **kwargs):
    budget = kwargs.pop("budget", PlannerBudget(max_cycles=4, max_tasks=50, select_per_cycle=10))
    return AdaptivePlanner(base.store, "eng", base.graph, executor=executor, budget=budget, **kwargs)


class FailureContainmentTests(PlannerTestBase):
    def test_an_operational_executor_failure_never_strands_a_hypothesis_running(self):
        executor = Scripted({"idor_bola": ConnectionResetError("target dropped the connection")})
        report = planner(self, executor).run()
        statuses = {h["category"]: h for h in planner(self, executor).hyp.list()}
        self.assertEqual(statuses["idor_bola"]["status"], "INCONCLUSIVE")
        self.assertEqual(statuses["idor_bola"]["status_reason"], "executor_error:infrastructure")
        self.assertEqual(report["hypotheses_by_status"].get("RUNNING", 0), 0)
        self.assertGreater(len(executor.calls), 1, "one failing hypothesis stopped the whole loop")

    def test_the_failure_is_recorded_in_the_decision_log_without_secrets(self):
        executor = Scripted({"idor_bola": ConnectionResetError("reset while sending token=abc123secret")})
        planner(self, executor).run()
        rows = self.store.connection.execute(
            "SELECT result_json FROM planner_decisions WHERE engagement_id='eng' AND selected=1").fetchall()
        recorded = " ".join(r["result_json"] or "" for r in rows)
        self.assertIn("executor_error:infrastructure", recorded)
        self.assertNotIn("abc123secret", recorded)

    def test_a_programming_error_is_recorded_and_then_surfaced_not_hidden(self):
        executor = Scripted({"idor_bola": TypeError("bug in the executor")})
        with self.assertRaises(TypeError):
            planner(self, executor).run()
        states = [h["status"] for h in planner(self, Scripted({})).hyp.list() if h["category"] == "idor_bola"]
        self.assertNotIn("RUNNING", states)


class RecoveryTests(PlannerTestBase):
    def _strand(self):
        """Simulate a crash: run a hypothesis to RUNNING and never settle it."""
        first = planner(self, None)
        first._refresh_candidates()
        target = next(h for h in first.hyp.list("READY") if h["category"] == "idor_bola")
        first.hyp.set_status(target["hypothesis_id"], "RUNNING")
        # what the loop itself stores when it starts an attempt: the real context fingerprint
        first.hyp.record_attempt(target["hypothesis_id"], fingerprint(self.graph, target), "exec_1")
        return target["hypothesis_id"]

    def test_a_hypothesis_left_running_by_a_crash_is_recovered_not_trusted_or_rerun_blindly(self):
        hid = self._strand()
        executor = Scripted({})
        planner(self, executor).run()
        recovered = planner(self, executor).hyp.get(hid)
        self.assertNotEqual(recovered["status"], "RUNNING")
        self.assertEqual(recovered["attempts"], 1)
        self.assertNotIn(hid, [h for _, h in executor.calls], "an interrupted attempt was blindly re-run")

    def test_an_unresolved_execution_keeps_the_hypothesis_blocked_until_an_operator_resolves_it(self):
        hid = self._strand()
        state = {"status": "RECONCILIATION_REQUIRED"}
        executor = Scripted({})
        run = lambda: planner(self, executor, execution_status=lambda row: state["status"]
                              if row["hypothesis_id"] == hid else None).run()
        run()
        held = planner(self, executor).hyp.get(hid)
        self.assertEqual((held["status"], held["status_reason"]), ("BLOCKED", "awaiting_reconciliation"))
        self.assertNotIn(hid, [h for _, h in executor.calls])
        run()                                                  # still unresolved: still blocked, still not run
        self.assertEqual(planner(self, executor).hyp.get(hid)["status"], "BLOCKED")
        self.assertNotIn(hid, [h for _, h in executor.calls])
        state["status"] = "FAILED"                             # the operator resolved it: no effect on the target
        run()
        after = planner(self, executor).hyp.get(hid)
        self.assertNotEqual((after["status"], after["status_reason"]), ("BLOCKED", "awaiting_reconciliation"))
        self.assertEqual([h for _, h in executor.calls].count(hid), 1, "one bounded retry after operator resolution")


class JustifiedRetryTests(PlannerTestBase):
    INCONCLUSIVE = {"disposition": "INCONCLUSIVE", "reason": "ownership not declared",
                    "evidence_requests": [{"kind": "confirm_object_ownership", "reason": "undeclared", "detail": {}}]}

    def test_an_inconclusive_test_is_not_repeated_while_nothing_has_changed(self):
        executor = Scripted({"idor_bola": self.INCONCLUSIVE})
        planner(self, executor).run()
        planner(self, executor).run()
        planner(self, executor).run()
        self.assertEqual(executor.count("idor_bola"), 1)

    def test_new_facts_justify_exactly_one_more_attempt_within_the_cap(self):
        executor = Scripted({"idor_bola": self.INCONCLUSIVE})
        planner(self, executor).run()
        self.assertEqual(executor.count("idor_bola"), 1)
        self.ing.grant_role("alice", "analyst")                # the required identity gains a role: new fact
        planner(self, executor).run()
        self.assertEqual(executor.count("idor_bola"), 2)
        self.ing.grant_role("alice", "auditor")                # more change, but the attempt cap (2) holds
        planner(self, executor).run()
        self.assertEqual(executor.count("idor_bola"), 2)

    def test_the_planners_own_bookkeeping_does_not_count_as_new_information(self):
        executor = Scripted({"idor_bola": self.INCONCLUSIVE})
        report = planner(self, executor, budget=PlannerBudget(max_cycles=6, max_tasks=50, select_per_cycle=10)).run()
        self.assertEqual(executor.count("idor_bola"), 1, "the planner retried because of its own TARGETS edges")
        self.assertEqual(report["stop_reason"], "no_ready_candidates")

    def test_outstanding_evidence_requests_are_reported_for_the_operator(self):
        executor = Scripted({"idor_bola": self.INCONCLUSIVE})
        report = planner(self, executor).run()
        kinds = [r["kind"] for item in report["pending_evidence_requests"] for r in item["requests"]]
        self.assertIn("confirm_object_ownership", kinds)


class EvidenceBackedOutcomeTests(PlannerTestBase):
    def test_a_disposition_without_a_validation_record_is_downgraded_when_required(self):
        executor = Scripted({"idor_bola": {"disposition": "SUPPORTED", "evidence_refs": ["ev1"], "reason": "I say so"}})
        p = planner(self, executor, require_validation_record=True)
        p.run()
        row = next(h for h in p.hyp.list() if h["category"] == "idor_bola")
        self.assertEqual((row["status"], row["status_reason"]), ("INCONCLUSIVE", "disposition_without_validation_record"))
        self.assertEqual(self.graph.edges("VALIDATED_BY"), [])

    def test_a_record_backed_support_is_accepted_and_folded_into_the_graph(self):
        executor = Scripted({"idor_bola": {"disposition": "SUPPORTED", "evidence_refs": ["ev-a", "ev-b"],
                                           "validation_record_id": "vrec_1", "execution_id": "exec_9"}})
        p = planner(self, executor, require_validation_record=True)
        p.run()
        row = next(h for h in p.hyp.list() if h["category"] == "idor_bola")
        self.assertEqual(row["status"], "SUPPORTED")
        self.assertEqual(row["last_execution_id"], "exec_9")
        node = self.graph.get_node("hypothesis", row["hypothesis_id"])
        self.assertEqual(node["attributes"]["disposition"], "SUPPORTED")
        self.assertEqual(node["attributes"]["validation_record_id"], "vrec_1")
        self.assertEqual(len(self.graph.edges("VALIDATED_BY", src_id=node["node_id"])), 2)

    def test_the_default_remains_compatible_with_executors_that_return_a_bare_disposition(self):
        executor = Scripted({"idor_bola": {"disposition": "SUPPORTED", "evidence_refs": ["ev"]}})
        p = planner(self, executor)
        p.run()
        self.assertEqual(next(h for h in p.hyp.list() if h["category"] == "idor_bola")["status"], "SUPPORTED")


class DecisionAndCoverageTests(PlannerTestBase):
    def test_rejections_are_recorded_with_their_reason(self):
        self.ing.register_endpoint("GET", "https://evil.example:443", "/x")
        evil = self.graph.get_node("endpoint", "GET https://evil.example:443/x")
        self.ing.graph.upsert_node("parameter", "GET https://evil.example:443/x?q", label="q", trust="observed")
        self.graph.upsert_edge(evil["node_id"], "ACCEPTS",
                               self.graph.node_id("parameter", "GET https://evil.example:443/x?q"), trust="observed")
        planner(self, Scripted({})).run()
        rows = self.store.connection.execute(
            "SELECT rationale_json FROM planner_decisions WHERE engagement_id='eng' AND selected=0").fetchall()
        reasons = {__import__("json").loads(r["rationale_json"]).get("reason") for r in rows}
        self.assertIn("target_out_of_scope", reasons)

    def test_the_report_summarises_coverage_by_test_class_and_lists_untested_endpoints(self):
        executor = Scripted({"idor_bola": {"disposition": "SUPPORTED", "validation_record_id": "v", "evidence_refs": ["e"]}})
        p = planner(self, executor, budget=PlannerBudget(max_cycles=1, max_tasks=1, select_per_cycle=1))
        report = p.run()
        coverage = report["coverage"]
        attempted = sum(bucket["attempted"] for bucket in coverage["by_test_class"].values())
        self.assertEqual(attempted, 1)
        self.assertTrue(coverage["untested_endpoints"], "endpoints never targeted must be listed as gaps")


if __name__ == "__main__":
    unittest.main()
