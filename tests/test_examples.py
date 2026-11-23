import json
import unittest
from pathlib import Path
try:
    from jsonschema import Draft202012Validator, FormatChecker
except ImportError:
    Draft202012Validator = None
ROOT = Path(__file__).resolve().parents[1]
class ExampleTests(unittest.TestCase):
    def test_handoff_example_matches_schema(self):
        schema = json.loads((ROOT / "templates/handoff.schema.json").read_text())
        example = json.loads((ROOT / "templates/examples/handoff.completed.example.json").read_text())
        if Draft202012Validator:
            Draft202012Validator(schema,format_checker=FormatChecker()).validate(example)
        else:
            self.assertTrue(set(schema["required"]).issubset(example))
    def test_finding_schema_has_conditional_validation(self):
        schema = json.loads((ROOT / "templates/finding.schema.json").read_text())
        self.assertTrue(schema["allOf"])
if __name__ == "__main__": unittest.main()
