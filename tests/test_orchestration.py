import tempfile,unittest
from pathlib import Path
from core.orchestration import Workflow,WorkflowError
from scripts.migrate import migrate

class OrchestrationTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.db=str(Path(self.tmp.name)/"state.sqlite"); migrate(self.db)
  self.w=Workflow(self.db)
  self.w.initialize({"engagement_id":"eng-test","authorization_reference":"AUTH-LAB-001","scope":{"allowed_domains":["app.example.test"]},"rules_of_engagement":{"execution_enabled":False}})
 def tearDown(self): self.w.close(); self.tmp.cleanup()
 def plan(self):
  return {"tasks":[
   {"task_key":"recon","agent":"recon-agent","objective":"Review supplied inventory","depends_on":[],"scope_subset":["app.example.test"],"completion_criteria":["Cite source evidence"]},
   {"task_key":"enum","agent":"enumeration-agent","objective":"Map supplied routes","depends_on":["recon"],"scope_subset":["app.example.test"],"completion_criteria":["Cite route sources"]}
  ]}
 def test_dependencies_and_persisted_status(self):
  tasks=self.w.create_plan("eng-test",self.plan())
  with self.assertRaises(WorkflowError): self.w.start_task(tasks[1]["task_id"])
  self.w.start_task(tasks[0]["task_id"])
  self.assertEqual(self.w.status("eng-test")["tasks"][0]["status"],"running")
 def test_rejects_scope_expansion_and_cycles(self):
  bad=self.plan(); bad["tasks"][0]["scope_subset"]=["outside.test"]
  with self.assertRaises(WorkflowError): self.w.create_plan("eng-test",bad)
  cycle=self.plan(); cycle["tasks"][0]["depends_on"]=["enum"]
  with self.assertRaises(WorkflowError): self.w.create_plan("eng-test",cycle)
 def test_handoff_completes_task_and_unlocks_dependency(self):
  tasks=self.w.create_plan("eng-test",self.plan()); first=tasks[0]; self.w.start_task(first["task_id"])
  handoff={"task_id":first["task_id"],"engagement_id":"eng-test","agent":"recon-agent","status":"completed","scope_subset":["app.example.test"],"summary":"Reviewed supplied artifacts.","observations":[],"hypotheses":[],"evidence_refs":["evidence://lab/recon-1"],"limitations":[],"next_steps":[]}
  self.w.accept_handoff(first["task_id"],handoff)
  self.assertEqual(self.w.status("eng-test")["tasks"][0]["status"],"completed")
  self.assertTrue(self.w.start_task(tasks[1]["task_id"]).startswith("run_"))
 def test_active_tasks_and_bad_identity_rejected(self):
  bad=self.plan(); bad["tasks"][0]["active_testing"]=True
  with self.assertRaises(WorkflowError): self.w.create_plan("eng-test",bad)
  tasks=self.w.create_plan("eng-test",self.plan()); tid=tasks[0]["task_id"]; self.w.start_task(tid)
  handoff={"task_id":tid,"engagement_id":"wrong","agent":"recon-agent","status":"completed","scope_subset":["app.example.test"],"summary":"x","observations":[],"hypotheses":[],"evidence_refs":[],"limitations":[]}
  with self.assertRaises(WorkflowError): self.w.accept_handoff(tid,handoff)
if __name__=="__main__": unittest.main()
