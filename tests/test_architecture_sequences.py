import unittest

from scripts.run_architecture_benchmark import validate_architecture_sequence


class ArchitectureSequenceTests(unittest.TestCase):
    def test_model1_and_hybrid_are_distinct_fixed_sequences(self):
        model1 = [
            "recon-agent", "enumeration-agent", "vulnerability-agent",
            "exploitation-agent", "validation-agent", "reporting-agent",
        ]
        hybrid = [
            "scope-analyst", "recon-agent", "technology-profiler",
            "enumeration-agent", "vulnerability-agent", "validation-agent",
            "impact-analyst", "duplicate-checker", "reporting-agent",
        ]
        validate_architecture_sequence([{"agent": item} for item in model1], "model1")
        validate_architecture_sequence([{"agent": item} for item in hybrid], "hybrid")
        with self.assertRaisesRegex(ValueError, "does not match"):
            validate_architecture_sequence([{"agent": item} for item in hybrid], "model1")


if __name__ == "__main__":
    unittest.main()
