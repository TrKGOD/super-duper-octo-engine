import tempfile
import unittest
from pathlib import Path
from core.orchestration import Workflow,WorkflowError
from scripts.migrate import migrate

class OrchestrationTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory()
  self.db=str(Path(self.tmp.name)/"state.sqlite")
  migrate(self.db)
  self.w=Workflow(self.db)
  self.w.initialize({"engagement_id":"eng-test","authorization_reference":"AUTH-LAB-001","scope":{"allowed_domains":["app.example.test"]},"rules_of_engagement":{"execution_enabled":False}})
 def tearDown(self):
  self.w.close()
  self.tmp.cleanup()
 def plan(self):
  return {"tasks":[
   {"task_key":"recon","agent":"recon-agent","objective":"Review supplied inventory","depends_on":[],"scope_subset":["app.example.test"],"completion_criteria":["Cite source evidence"]},
   {"task_key":"enum","agent":"enumeration-agent","objective":"Map supplied routes","depends_on":["recon"],"scope_subset":["app.example.test"],"completion_criteria":["Cite route sources"]}
  ]}
 def test_dependency_gate_and_run_link(self):
  tasks=self.w.create_plan("eng-test",self.plan())
  with self.assertRaises(WorkflowError):
   self.w.start_task(tasks[1]["task_id"])
  run=self.w.start_task(tasks[0]["task_id"])
  row=self.w.store.connection.execute("SELECT task_id,status FROM agent_runs WHERE run_id=?",(run,)).fetchone()
  self.assertEqual(row["task_id"],tasks[0]["task_id"])
  self.assertEqual(row["status"],"running")
 def test_scope_expansion_and_cycles_rejected(self):
  plan=self.plan()
  plan["tasks"][0]["scope_subset"]=["outside.test"]
  with self.assertRaises(WorkflowError):
   self.w.create_plan("eng-test",plan)
  plan=self.plan()
  plan["tasks"][0]["depends_on"]=["enum"]
  with self.assertRaises(WorkflowError):
   self.w.create_plan("eng-test",plan)
 def test_handoff_completes_run_and_unlocks_dependency(self):
  tasks=self.w.create_plan("eng-test",self.plan())
  task=tasks[0]
  run=self.w.start_task(task["task_id"])
  evidence=self.w.store.record_evidence("eng-test","reproduction_notes",".local/evidence/recon.txt","recon-agent")
  handoff={"task_id":task["task_id"],"engagement_id":"eng-test","agent":"recon-agent","status":"completed","scope_subset":["app.example.test"],"summary":"Reviewed supplied artifacts.","observations":[],"hypotheses":[],"evidence_refs":[evidence],"limitations":[],"next_steps":[]}
  self.w.accept_handoff(task["task_id"],handoff)
  self.assertEqual(self.w.status("eng-test")["tasks"][0]["status"],"completed")
  self.assertEqual(self.w.store.connection.execute("SELECT status FROM agent_runs WHERE run_id=?",(run,)).fetchone()["status"],"completed")
  self.assertTrue(self.w.start_task(tasks[1]["task_id"]).startswith("run_"))
 def test_active_tasks_and_bad_identity_rejected(self):
  plan=self.plan()
  plan["tasks"][0]["active_testing"]=True
  with self.assertRaises(WorkflowError):
   self.w.create_plan("eng-test",plan)
  task_id=self.w.create_plan("eng-test",self.plan())[0]["task_id"]
  self.w.start_task(task_id)
  evidence=self.w.store.record_evidence("eng-test","reproduction_notes",".local/evidence/bad-handoff.txt","recon-agent")
  handoff={"task_id":task_id,"engagement_id":"wrong","agent":"recon-agent","status":"completed","scope_subset":["app.example.test"],"summary":"x","observations":[],"hypotheses":[],"evidence_refs":[evidence],"limitations":[]}
  with self.assertRaises(WorkflowError):
   self.w.accept_handoff(task_id,handoff)
 def test_finding_write_uses_deterministic_validator(self):
  finding={"finding_id":"f1","engagement_id":"eng-test","title":"Synthetic hypothesis","status":"hypothesis","asset":"app.example.test","description":"Lab hypothesis only","evidence_refs":["evidence://lab/h1"],"proposed_by":"vulnerability-agent"}
  evidence=self.w.store.record_evidence("eng-test","reproduction_notes",".local/evidence/finding.txt","operator")
  finding["evidence_refs"]=[evidence]
  self.w.record_finding("eng-test",finding)
  self.assertEqual(self.w.store.connection.execute("SELECT status FROM findings WHERE finding_id='f1'").fetchone()["status"],"hypothesis")
if __name__=="__main__":
 unittest.main()
