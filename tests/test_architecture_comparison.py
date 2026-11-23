import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.compare_architecture_results import compare


class ArchitectureComparisonTests(unittest.TestCase):
    def test_comparison_requires_same_model_and_corpus(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cases = root / "cases"
            cases.mkdir()
            (cases / "one.json").write_text(json.dumps({
                "case_id": "SYN-001", "kind": "synthetic",
                "expected_finding": True, "required_evidence": ["proof"],
                "fixtures": {"proof": "synthetic"},
            }), encoding="utf-8")
            for name in ("m1-pred.json", "hybrid-pred.json"):
                (root / name).write_text(json.dumps({"predictions": [{
                    "case_id": "SYN-001", "detected": True, "evidence_fields": ["proof"]
                }]}), encoding="utf-8")
            corpus = [json.loads((cases / "one.json").read_text(encoding="utf-8"))]
            corpus_hash = hashlib.sha256(
                json.dumps(corpus, sort_keys=True, ensure_ascii=False).encode()
            ).hexdigest()
            common = {"model": "pinned-model", "corpus_sha256": corpus_hash, "total_seconds": 10, "total_cost_usd": 0.1}
            (root / "m1.json").write_text(json.dumps({**common, "architecture": "model1"}), encoding="utf-8")
            (root / "hybrid.json").write_text(json.dumps({**common, "architecture": "hybrid"}), encoding="utf-8")
            result = compare(
                cases, root / "m1-pred.json", root / "m1.json",
                root / "hybrid-pred.json", root / "hybrid.json",
            )
            self.assertEqual(result["comparison_status"], "comparable_synthetic_pipeline_simulation")
            self.assertEqual(result["hybrid_minus_model1"]["f1"], 0.0)
            bad = {**common, "architecture": "hybrid", "model": "different-model"}
            (root / "hybrid.json").write_text(json.dumps(bad), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "same model"):
                compare(
                    cases, root / "m1-pred.json", root / "m1.json",
                    root / "hybrid-pred.json", root / "hybrid.json",
                )


if __name__ == "__main__":
    unittest.main()
