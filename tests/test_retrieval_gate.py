import unittest
from scripts.retrieval_gate import run_gates


class RetrievalGateTests(unittest.TestCase):
    def test_all_wave_skills_are_retrievable_and_capability_contracts_hold(self):
        result = run_gates()
        self.assertEqual(result["retrieval_failed"], [])
        self.assertEqual(result["capability_failed"], [])
        self.assertEqual(result["retrieval_passed"], 7)


if __name__ == "__main__":
    unittest.main()
