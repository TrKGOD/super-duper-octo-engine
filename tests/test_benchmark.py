import json
import tempfile
import unittest
from pathlib import Path

from scripts.evaluate_benchmark import evaluate


class BenchmarkEvaluatorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.cases = self.root / "cases"
        self.cases.mkdir()
        self.predictions = self.root / "predictions.json"
        self.write_case("positive", True, ["request", "owner"])
        self.write_case("negative", False, ["authorization"])

    def tearDown(self):
        self.tmp.cleanup()

    def write_case(self, case_id, expected, required):
        (self.cases / f"{case_id}.json").write_text(json.dumps({
            "case_id": case_id, "kind": "synthetic", "expected_finding": expected,
            "required_evidence": required,
            "fixtures": {item: "synthetic fixture value" for item in required} if expected else {}
        }), encoding="utf-8")

    def write_predictions(self, predictions):
        self.predictions.write_text(json.dumps({"predictions": predictions}), encoding="utf-8")

    def test_metrics_and_evidence_completeness(self):
        self.write_predictions([
            {"case_id": "positive", "detected": True, "evidence_fields": ["request"]},
            {"case_id": "negative", "detected": True, "evidence_fields": []}
        ])
        result = evaluate(self.cases, self.predictions)
        self.assertEqual((result["tp"], result["fp"], result["tn"], result["fn"]), (1, 1, 0, 0))
        self.assertEqual(result["evidence_completeness"], 0.5)
        self.assertEqual(result["precision"], 0.5)

    def test_missing_prediction_fails_closed(self):
        self.write_predictions([])
        with self.assertRaisesRegex(ValueError, "Missing predictions"):
            evaluate(self.cases, self.predictions)

    def test_unknown_prediction_rejected(self):
        self.write_predictions([{"case_id": "unknown", "detected": False, "evidence_fields": []}])
        with self.assertRaisesRegex(ValueError, "Unknown prediction"):
            evaluate(self.cases, self.predictions)

    def test_positive_case_with_missing_fixture_payload_rejected(self):
        (self.cases / "broken-positive.json").write_text(json.dumps({
            "case_id": "broken-positive", "kind": "synthetic",
            "expected_finding": True, "required_evidence": ["proof"],
            "fixtures": {}
        }), encoding="utf-8")
        self.write_predictions([])
        with self.assertRaisesRegex(ValueError, "lacks required fixture fields"):
            evaluate(self.cases, self.predictions)

    def test_non_synthetic_case_rejected(self):
        (self.cases / "bad.json").write_text(json.dumps({
            "case_id": "bad", "kind": "client", "expected_finding": True
        }), encoding="utf-8")
        self.write_predictions([])
        with self.assertRaisesRegex(ValueError, "Non-synthetic"):
            evaluate(self.cases, self.predictions)


if __name__ == "__main__":
    unittest.main()
