import json,unittest
from pathlib import Path
from jsonschema import Draft202012Validator,FormatChecker
ROOT=Path(__file__).resolve().parents[1]
class ExampleTests(unittest.TestCase):
 def test_handoff(self):
  s=json.loads((ROOT/"templates/handoff.schema.json").read_text()); e=json.loads((ROOT/"templates/examples/handoff.completed.example.json").read_text()); Draft202012Validator(s,format_checker=FormatChecker()).validate(e)
 def test_plan(self):
  s=json.loads((ROOT/"templates/plan.schema.json").read_text()); e=json.loads((ROOT/"templates/examples/plan.passive.example.json").read_text()); Draft202012Validator(s,format_checker=FormatChecker()).validate(e)
 def test_finding_contract(self): self.assertTrue(json.loads((ROOT/"templates/finding.schema.json").read_text())["allOf"])
if __name__=="__main__": unittest.main()
