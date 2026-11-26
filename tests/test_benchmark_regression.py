"""Deterministic regression benchmark tests (also the CI-safe benchmark smoke).

Runs synthetic scenarios through the real graph → planner → validation pipeline and checks
the reported metrics, reproducibility across repeated runs, variance measurement, noisy-
detector behaviour, suite aggregation, and regression comparison. No live target is
contacted and no model is called.
"""
import unittest
from dataclasses import replace

from core.benchmark import (BenchmarkRunner, DetectorProfile, build_default_scenarios,
                           compare_results, compute_metrics)
from core.benchmark.scenarios import Scenario


def scenario(name):
    return [s for s in build_default_scenarios() if s.name == name][0]


class MetricsTests(unittest.TestCase):
    def test_perfect_and_edge_cases(self):
        m = compute_metrics({("a", "x")}, {("a", "x")})
        self.assertEqual((m["precision"], m["recall"], m["f1"]), (1.0, 1.0, 1.0))
        clean = compute_metrics(set(), set())          # no vulns, nothing reported
        self.assertIsNone(clean["precision"])
        self.assertIsNone(clean["recall"])
        fp = compute_metrics(set(), {("a", "x")})      # a false positive with no real vulns
        self.assertEqual(fp["precision"], 0.0)
        fn = compute_metrics({("a", "x")}, set())      # missed the only vuln
        self.assertEqual(fn["recall"], 0.0)


class ScenarioRunTests(unittest.TestCase):
    def setUp(self):
        self.runner = BenchmarkRunner()

    def test_bola_scenario_is_detected(self):
        result = self.runner.run_scenario(scenario("web-bola-basic"))
        m = result["metrics"]
        self.assertEqual((m["true_positives"], m["false_positives"], m["false_negatives"]), (1, 0, 0))
        self.assertEqual((m["precision"], m["recall"], m["f1"]), (1.0, 1.0, 1.0))
        self.assertEqual(m["validated_findings"], 1)
        self.assertTrue(result["manifest"]["no_live_targets"])
        self.assertTrue(result["manifest"]["no_model_calls"])

    def test_sqli_scenario_distinguishes_class_on_same_endpoint(self):
        # /search yields both sqli and xss candidates; only sqli is a real vuln.
        m = self.runner.run_scenario(scenario("web-sqli-basic"))["metrics"]
        self.assertEqual(m["true_positives"], 1)
        self.assertEqual(m["false_positives"], 0)  # xss on /search validated REFUTED

    def test_clean_scenario_has_no_false_positives(self):
        m = self.runner.run_scenario(scenario("clean-negative"))["metrics"]
        self.assertEqual(m["false_positives"], 0)
        self.assertEqual(m["validated_findings"], 0)

    def test_mixed_scenario(self):
        m = self.runner.run_scenario(scenario("mixed-web-api"))["metrics"]
        self.assertEqual(m["true_positives"], 2)
        self.assertEqual((m["precision"], m["recall"]), (1.0, 1.0))

    def test_noisy_detector_lowers_recall(self):
        noisy = replace(scenario("mixed-web-api"),
                        detector=DetectorProfile(false_negatives=frozenset({("sqli", "/search")})))
        m = self.runner.run_scenario(noisy)["metrics"]
        self.assertEqual(m["false_negatives"], 1)
        self.assertEqual(m["recall"], 0.5)

    def test_noisy_detector_lowers_precision(self):
        noisy = replace(scenario("mixed-web-api"),
                        detector=DetectorProfile(false_positives=frozenset({("sqli", "/profile")})))
        m = self.runner.run_scenario(noisy)["metrics"]
        self.assertEqual(m["false_positives"], 1)
        self.assertEqual(m["precision"], 2 / 3)


class ReproducibilityAndSuiteTests(unittest.TestCase):
    def setUp(self):
        self.runner = BenchmarkRunner()

    def test_repeated_runs_are_reproducible(self):
        result = self.runner.run_scenario(scenario("mixed-web-api"), repetitions=3)
        self.assertTrue(result["reproducible"])
        self.assertEqual(result["variance"]["precision"]["stdev"], 0.0)
        self.assertEqual(len(result["runs"]), 3)

    def test_suite_aggregates_and_is_reproducible(self):
        suite = self.runner.run_suite(build_default_scenarios())
        self.assertEqual(suite["aggregate"]["scenario_count"], 5)
        self.assertTrue(suite["aggregate"]["all_reproducible"])
        self.assertEqual(suite["aggregate"]["macro_precision"], 1.0)
        self.assertGreaterEqual(suite["aggregate"]["total_validated_findings"], 4)

    def test_regression_comparison(self):
        baseline = {"scenarios": [{"scenario": "x", "metrics": {"precision": 1.0, "recall": 1.0, "f1": 1.0}}]}
        candidate = {"scenarios": [{"scenario": "x", "metrics": {"precision": 0.5, "recall": 1.0, "f1": 0.67}}]}
        comparison = compare_results(baseline, candidate)
        self.assertTrue(comparison["is_regression"])
        self.assertIn("x.precision", comparison["regressed"])
        self.assertAlmostEqual(comparison["deltas"]["x"]["precision"], -0.5)


if __name__ == "__main__":
    unittest.main()
