"""Adaptive Testing Planner tests.

Demonstrates the roadmap exit criterion: a synthetic engagement runs an adaptive cycle in
which test results change subsequent selection, without bypassing authorization or resource
limits. Also covers the hypothesis lifecycle, deterministic policy validation (including
that an external/LLM proposal cannot widen scope or authorization), transparent scoring,
budgets, plan-only mode, redundancy control and decision observability.
"""
import tempfile
import unittest
from pathlib import Path

from scripts.migrate import migrate
from core.store import StateStore
from core.graph import AttackGraph, GraphIngestor, GraphQuery
from core.planner import (AdaptivePlanner, Hypothesis, HypothesisStore, PlannerBudget,
                          PlannerError, PolicyValidator, generate_candidates, score_hypothesis)

SCOPE = {"allowed_domains": ["app.local"], "allowed_http_ports": [443, 80],
         "allowed_applications": [], "allowed_ips": [], "allowed_cidrs": [], "excluded_assets": []}
RULES = {"execution_enabled": True, "authorization_verified": True,
         "allowed_test_classes": ["web-authorization-idor", "web-sqli", "web-xss", "web-ssrf", "web-authorization-bac"],
         "prohibited_test_classes": ["denial-of-service", "destructive-testing"],
         "human_approval_required_for_state_changes": True, "max_requests_per_engagement": 20}
ORIGIN = "https://app.local:443"


class RecordingExecutor:
    def __init__(self, dispositions=None):
        self.calls = []
        self.dispositions = dispositions or {}

    def __call__(self, hyp):
        self.calls.append(hyp["hypothesis_id"])
        disposition = self.dispositions.get(hyp["category"], "REFUTED")
        refs = ["ev-" + hyp["hypothesis_id"][4:10]] if disposition == "SUPPORTED" else []
        return {"disposition": disposition, "evidence_refs": refs, "reason": "synthetic"}


class PlannerTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "state.sqlite3")
        migrate(self.db)
        self.store = StateStore(self.db)
        self.store.create_engagement("eng", "AUTH-LAB", SCOPE, RULES, status="active")
        self.graph = AttackGraph(self.store.connection, "eng")
        self.ing = GraphIngestor(self.graph)
        self._seed()

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def _seed(self):
        self.ing.register_identity("alice")
        self.ing.register_identity("bob")
        self.e1 = self.ing.register_endpoint("GET", ORIGIN, "/api/orders/{id}")
        obj = self.graph.upsert_node("object", "order-7", trust="control_plane")
        self.graph.upsert_edge(self.e1, "REFERENCES", obj, trust="observed")
        self.ing.declare_object_owner("order-7", "bob")
        self.ing.observe_access("alice", self.e1, evidence_refs=["r1"])
        self.e2 = self.ing.register_endpoint("GET", ORIGIN, "/api/search")
        pq = self.graph.upsert_node("parameter", f"GET {ORIGIN}/api/search?q", label="q", trust="observed")
        self.graph.upsert_edge(self.e2, "ACCEPTS", pq, trust="observed")
        self.ing.observe_access("alice", self.e2)
        self.e3 = self.ing.register_endpoint("GET", ORIGIN, "/api/fetch")
        pu = self.graph.upsert_node("parameter", f"GET {ORIGIN}/api/fetch?url", label="url", trust="observed")
        self.graph.upsert_edge(self.e3, "ACCEPTS", pu, trust="observed")


class HypothesisLifecycleTests(PlannerTestBase):
    def test_status_transitions_are_enforced(self):
        hs = HypothesisStore(self.store.connection, "eng")
        hid = hs.upsert(Hypothesis("eng", "sqli", "web-sqli", "probe", target_node_id=self.e2))
        self.assertEqual(hs.get(hid)["status"], "PROPOSED")
        hs.set_status(hid, "READY")
        hs.set_status(hid, "RUNNING")
        hs.set_status(hid, "SUPPORTED")
        self.assertEqual(hs.get(hid)["attempts"], 1)
        with self.assertRaises(PlannerError):  # SUPPORTED is terminal
            hs.set_status(hid, "RUNNING")


class CandidateGenerationTests(PlannerTestBase):
    def test_candidates_are_context_driven(self):
        categories = {c.category for c in generate_candidates(self.graph, "eng")}
        self.assertIn("idor_bola", categories)   # e1 references an owned object
        self.assertIn("sqli", categories)        # e2/e3 accept parameters
        self.assertIn("xss", categories)
        self.assertIn("ssrf", categories)        # e3 has a url-like parameter
        # No endpoint without parameters/objects should spawn an injection candidate.
        bare = self.ing.register_endpoint("GET", ORIGIN, "/health")
        cands = [c for c in generate_candidates(self.graph, "eng") if c.target_node_id == bare]
        self.assertEqual(cands, [])


class PolicyTests(PlannerTestBase):
    def _policy(self):
        return PolicyValidator(SCOPE, RULES, self.graph)

    def test_valid_candidate_is_ready(self):
        hyp = Hypothesis("eng", "idor_bola", "web-authorization-idor", "t", target_node_id=self.e1,
                         required_identity="alice")
        self.assertEqual(self._policy().validate(hyp), ("READY", None))

    def test_out_of_scope_target_is_blocked(self):
        evil = self.ing.register_endpoint("GET", "https://evil.example:443", "/x")
        hyp = Hypothesis("eng", "sqli", "web-sqli", "t", target_node_id=evil)
        self.assertEqual(self._policy().validate(hyp)[1], "target_out_of_scope")

    def test_unauthorized_identity_is_blocked(self):
        hyp = Hypothesis("eng", "sqli", "web-sqli", "t", target_node_id=self.e2, required_identity="ghost")
        self.assertEqual(self._policy().validate(hyp)[1], "identity_not_authorized")

    def test_disallowed_and_prohibited_classes_are_blocked(self):
        allowed_only_sqli = dict(RULES, allowed_test_classes=["web-sqli"])
        pol = PolicyValidator(SCOPE, allowed_only_sqli, self.graph)
        xss = Hypothesis("eng", "xss", "web-xss", "t", target_node_id=self.e2, required_identity="alice")
        self.assertEqual(pol.validate(xss)[1], "test_class_not_allowed")
        prohibited = PolicyValidator(SCOPE, dict(RULES, prohibited_test_classes=["web-sqli"]), self.graph)
        sqli = Hypothesis("eng", "sqli", "web-sqli", "t", target_node_id=self.e2, required_identity="alice")
        self.assertEqual(prohibited.validate(sqli)[1], "prohibited_test_class")

    def test_state_changing_requires_approval(self):
        hyp = Hypothesis("eng", "idor_bola", "web-authorization-idor", "t", target_node_id=self.e1,
                         required_identity="alice", state_changing=True)
        self.assertEqual(self._policy().validate(hyp)[1], "awaiting_operator_approval_for_state_change")


class ScoringTests(PlannerTestBase):
    def test_score_is_transparent_and_confidence_is_capped(self):
        strong = Hypothesis("eng", "sqli", "web-sqli", "t", supporting_evidence=["a", "b", "c"], confidence=0.3)
        score, breakdown = score_hypothesis(strong, coverage_gap=True)
        self.assertIn("weights", breakdown)
        self.assertIn("factors", breakdown)
        # A model reporting confidence 1.0 cannot outrank genuine evidence: the confidence
        # factor is capped at 0.6 and weighted 0.10, so it moves the score by at most 0.06.
        low_ev_high_conf = Hypothesis("eng", "xss", "web-xss", "t", supporting_evidence=[], confidence=1.0)
        s2, b2 = score_hypothesis(low_ev_high_conf, coverage_gap=True)
        self.assertLessEqual(b2["factors"]["confidence"], 0.6)
        self.assertGreater(score, s2)


class AdaptiveLoopTests(PlannerTestBase):
    def test_results_change_subsequent_selection_within_budget(self):
        before_gaps = len(GraphQuery(self.graph).low_coverage_endpoints())
        executor = RecordingExecutor({"idor_bola": "SUPPORTED"})  # BOLA supported, others refuted
        planner = AdaptivePlanner(self.store, "eng", self.graph, executor=executor,
                                  budget=PlannerBudget(max_cycles=6, max_tasks=6, select_per_cycle=1))
        report = planner.run()

        # Adaptivity: each executed hypothesis is distinct (no equivalent re-run) and the
        # loop progressed across multiple cycles as prior results removed attempted work.
        self.assertEqual(len(executor.calls), len(set(executor.calls)))
        self.assertGreaterEqual(report["cycles_run"], 2)
        # Coverage updated by results -> fewer untested endpoints feed the next selection.
        after_gaps = len(GraphQuery(self.graph).low_coverage_endpoints())
        self.assertLess(after_gaps, before_gaps)
        # The SUPPORTED hypothesis carries attached evidence in the graph.
        self.assertTrue(report["supported"])
        supported_node = self.graph.node_id("hypothesis", report["supported"][0])
        self.assertTrue(self.graph.edges("SUPPORTS", dst_id=supported_node))

    def test_task_budget_is_hard_limit(self):
        executor = RecordingExecutor()
        planner = AdaptivePlanner(self.store, "eng", self.graph, executor=executor,
                                  budget=PlannerBudget(max_cycles=10, max_tasks=2, select_per_cycle=1))
        report = planner.run()
        self.assertEqual(len(executor.calls), 2)
        self.assertEqual(report["tasks_used"], 2)
        self.assertEqual(report["stop_reason"], "task_budget_exhausted")

    def test_plan_only_when_execution_not_enabled(self):
        self.store.connection.execute(
            "UPDATE engagements SET rules_json=? WHERE engagement_id='eng'",
            (__import__("json").dumps(dict(RULES, execution_enabled=False)),))
        self.store.connection.commit()
        executor = RecordingExecutor()
        planner = AdaptivePlanner(self.store, "eng", self.graph, executor=executor)
        report = planner.run()
        self.assertEqual(report["stop_reason"], "plan_only")
        self.assertEqual(executor.calls, [])
        self.assertNotIn("SUPPORTED", report["hypotheses_by_status"])

    def test_llm_proposal_cannot_bypass_scope_or_authorization(self):
        evil = self.ing.register_endpoint("GET", "https://evil.example:443", "/pwn")
        executor = RecordingExecutor({"sqli": "SUPPORTED"})
        planner = AdaptivePlanner(self.store, "eng", self.graph, executor=executor,
                                  budget=PlannerBudget(max_cycles=3, max_tasks=10, select_per_cycle=5))
        # An external proposal targeting an out-of-scope endpoint and an unauthorized identity.
        ids = planner.add_proposals([
            {"category": "sqli", "target_node_id": evil, "required_identity": "mallory",
             "proposed_test": "attacker-chosen"}], source="llm")
        planner.run()
        hs = HypothesisStore(self.store.connection, "eng")
        proposed = hs.get(ids[0])
        self.assertEqual(proposed["status"], "BLOCKED")
        self.assertNotIn(ids[0], executor.calls)

    def test_decisions_are_recorded_with_rationale(self):
        executor = RecordingExecutor()
        planner = AdaptivePlanner(self.store, "eng", self.graph, executor=executor,
                                  budget=PlannerBudget(max_cycles=2, max_tasks=2, select_per_cycle=1))
        planner.run()
        rows = self.store.connection.execute(
            "SELECT rationale_json FROM planner_decisions WHERE engagement_id='eng' AND selected=1").fetchall()
        self.assertTrue(rows)
        rationale = __import__("json").loads(rows[0]["rationale_json"])
        for key in ("why_selected", "score_breakdown", "authorization", "budget_allocated", "alternatives_considered"):
            self.assertIn(key, rationale)


if __name__ == "__main__":
    unittest.main()
