"""Intelligence-layer benchmark (Component H) tests.

Covers the rank-aware retrieval metrics (pure), and the three evaluators run against the REAL
components on synthetic data — the FTS retriever, the deterministic tool selector + profile
policy, and the reporting engine — plus the suite aggregate and the regression/safety gate.
Everything is synthetic and in-memory; no network, no model.
"""
import copy
import unittest

from core.benchmark import (compare_intelligence, evaluate_reporting, evaluate_retrieval,
                            evaluate_tool_selection, retrieval_metrics, run_intelligence_suite)


class RetrievalMetricTests(unittest.TestCase):
    def test_perfect_single_relevant(self):
        m = retrieval_metrics({"a"}, ["a", "b", "c"], k=3)
        self.assertAlmostEqual(m["precision_at_k"], 1 / 3, places=4)
        self.assertEqual(m["recall_at_k"], 1.0)
        self.assertEqual(m["reciprocal_rank"], 1.0)
        self.assertEqual(m["average_precision"], 1.0)
        self.assertEqual(m["ndcg_at_k"], 1.0)

    def test_no_relevant_is_undefined_not_perfect(self):
        m = retrieval_metrics(set(), ["a", "b"], k=2)
        self.assertEqual(m["precision_at_k"], 0.0)       # nothing relevant retrieved
        self.assertIsNone(m["recall_at_k"])
        self.assertIsNone(m["reciprocal_rank"])
        self.assertIsNone(m["average_precision"])
        self.assertIsNone(m["ndcg_at_k"])

    def test_interleaved_ranking(self):
        m = retrieval_metrics({"a", "c"}, ["a", "b", "c", "d"], k=4)
        self.assertEqual(m["precision_at_k"], 0.5)
        self.assertEqual(m["recall_at_k"], 1.0)
        self.assertEqual(m["reciprocal_rank"], 1.0)
        self.assertAlmostEqual(m["average_precision"], (1.0 + 2 / 3) / 2, places=4)
        # DCG=1/log2(2)+1/log2(4)=1.5; IDEAL=1/log2(2)+1/log2(3)=1.63093; nDCG=0.91972
        self.assertAlmostEqual(m["ndcg_at_k"], 0.91972, places=4)

    def test_miss_in_top_k(self):
        m = retrieval_metrics({"z"}, ["a", "b", "z"], k=2)   # z is at rank 3, outside k=2
        self.assertEqual(m["precision_at_k"], 0.0)
        self.assertEqual(m["recall_at_k"], 0.0)
        self.assertAlmostEqual(m["reciprocal_rank"], 1 / 3, places=5)   # RR uses the full list


class RetrievalEvaluatorTests(unittest.TestCase):
    def test_real_fts_retrieval_quality(self):
        result = evaluate_retrieval(k=5)
        self.assertEqual(result["corpus_size"], 5)
        self.assertEqual(result["aggregate"]["query_count"], 6)
        # Every single-relevant query ranks its document first -> perfect MRR.
        self.assertEqual(result["aggregate"]["mrr"], 1.0)
        self.assertGreaterEqual(result["aggregate"]["map"], 0.8)
        for row in result["queries"]:
            self.assertGreaterEqual(row["precision_at_k"], 0.0)
            self.assertLessEqual(row["precision_at_k"], 1.0)


class ToolSelectionEvaluatorTests(unittest.TestCase):
    def setUp(self):
        self.result = evaluate_tool_selection()
        self.by_name = {c["name"]: c for c in self.result["cases"]}

    def test_perfect_accuracy_and_no_safety_violations(self):
        self.assertEqual(self.result["aggregate"]["accuracy"], 1.0)
        self.assertEqual(self.result["aggregate"]["safety_violations"], 0)
        self.assertTrue(self.result["aggregate"]["all_correct"])

    def test_restricted_never_auto_selected(self):
        case = self.by_name["restricted_never_auto"]
        self.assertEqual(case["selected"], [])
        self.assertEqual(case["safety_violations"], [])

    def test_restricted_allowed_with_operator_approval(self):
        self.assertEqual(self.by_name["restricted_with_operator_approval"]["selected"],
                         ["restricted-exploit"])

    def test_redundant_capability_is_deferred(self):
        self.assertEqual(self.by_name["redundancy_defers_covered"]["selected"], [])

    def test_state_change_needs_approval(self):
        case = self.by_name["state_change_needs_approval"]
        self.assertEqual(case["selected"], ["active-fuzz"])       # active-writer withheld


class ReportingEvaluatorTests(unittest.TestCase):
    def test_only_sound_validated_finding_is_confirmed(self):
        result = evaluate_reporting()
        self.assertEqual(result["confirmed"], ["rep-good"])
        self.assertIn("rep-bad", result["excluded"])             # tampered evidence excluded
        self.assertEqual(result["candidate_count"], 1)           # scanner candidate kept separate
        self.assertEqual(result["aggregate"]["score"], 1.0)
        self.assertEqual(result["aggregate"]["integrity_violations"], 0)
        self.assertTrue(result["aggregate"]["all_pass"])


class SuiteAndGateTests(unittest.TestCase):
    def setUp(self):
        self.suite = run_intelligence_suite()

    def test_suite_aggregate_and_manifest(self):
        agg = self.suite["aggregate"]
        for key in ("retrieval_map", "retrieval_mrr", "selection_accuracy", "reporting_score"):
            self.assertIsInstance(agg[key], float)
        self.assertEqual(agg["safety_violations"], 0)
        self.assertTrue(agg["all_safe"])
        self.assertEqual(self.suite["cost"]["usd"], 0.0)
        self.assertTrue(self.suite["manifest"]["no_model_calls"])
        self.assertTrue(self.suite["manifest"]["no_live_targets"])

    def test_no_regression_against_self(self):
        comparison = compare_intelligence(self.suite, self.suite)
        self.assertFalse(comparison["is_regression"])
        self.assertEqual(comparison["regressed"], [])

    def test_metric_drop_is_a_regression(self):
        worse = copy.deepcopy(self.suite)
        worse["aggregate"]["selection_accuracy"] = self.suite["aggregate"]["selection_accuracy"] - 0.5
        comparison = compare_intelligence(self.suite, worse)
        self.assertIn("selection_accuracy", comparison["regressed"])
        self.assertTrue(comparison["is_regression"])

    def test_safety_violation_fails_regardless_of_metrics(self):
        unsafe = copy.deepcopy(self.suite)
        unsafe["aggregate"]["safety_violations"] = 1          # metrics otherwise identical
        comparison = compare_intelligence(self.suite, unsafe)
        self.assertTrue(comparison["safety_failed"])
        self.assertTrue(comparison["is_regression"])


if __name__ == "__main__":
    unittest.main()
