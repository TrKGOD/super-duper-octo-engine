import json,unittest
from pathlib import Path
from jsonschema import Draft202012Validator,FormatChecker
from scripts.skill_registry import load_registry, select_skills
ROOT=Path(__file__).resolve().parents[1]
class ExampleTests(unittest.TestCase):
 def test_handoff(self):
  s=json.loads((ROOT/"templates/handoff.schema.json").read_text()); e=json.loads((ROOT/"templates/examples/handoff.completed.example.json").read_text()); Draft202012Validator(s,format_checker=FormatChecker()).validate(e)
 def test_plan(self):
  s=json.loads((ROOT/"templates/plan.schema.json").read_text()); validator=Draft202012Validator(s,format_checker=FormatChecker())
  registry=load_registry()
  for path in sorted((ROOT/"templates/examples").glob("plan*.json")):
   e=json.loads(path.read_text()); validator.validate(e)
   for task in e["tasks"]:
    self.assertTrue(task.get("domain"), f"{path.name}:{task.get('task_key')} missing domain")
    self.assertTrue(task.get("skill_tags"), f"{path.name}:{task.get('task_key')} missing skill_tags")
    self.assertTrue(select_skills(registry,domain=task["domain"],agent=task["agent"],tags=task["skill_tags"]), f"{path.name}:{task['task_key']} selects no Skill")
  
 def test_plan_rejects_missing_methodology_metadata(self):
  s=json.loads((ROOT/"templates/plan.schema.json").read_text()); validator=Draft202012Validator(s)
  invalid={"tasks":[{"task_key":"x","agent":"recon-agent","objective":"x","completion_criteria":["x"]}]}
  self.assertTrue(list(validator.iter_errors(invalid)))
 def test_finding_contract(self): self.assertTrue(json.loads((ROOT/"templates/finding.schema.json").read_text())["allOf"])
if __name__=="__main__": unittest.main()
