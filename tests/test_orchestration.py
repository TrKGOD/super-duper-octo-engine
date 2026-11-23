import tempfile
import unittest
from pathlib import Path
from core.orchestration import Workflow,WorkflowError
from core.evidence import EvidenceVault
from scripts.migrate import migrate

class OrchestrationTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory()
  self.db=str(Path(self.tmp.name)/"state.sqlite")
  migrate(self.db)
  self.w=Workflow(self.db, project_root=self.tmp.name)
  self.vault=EvidenceVault(self.w.store,self.tmp.name)
  self.w.initialize({"engagement_id":"eng-test","authorization_reference":"AUTH-LAB-001","scope":{"allowed_domains":["app.example.test"]},"rules_of_engagement":{"execution_enabled":False}})
 def tearDown(self):
  self.w.close()
  self.tmp.cleanup()
 def plan(self):
  return {"tasks":[
   {"task_key":"recon","agent":"recon-agent","objective":"Review supplied inventory","depends_on":[],"scope_subset":["app.example.test"],"completion_criteria":["Cite source evidence"],"domain":"web","skill_tags":["passive-recon"]},
   {"task_key":"enum","agent":"enumeration-agent","objective":"Map supplied routes","depends_on":["recon"],"scope_subset":["app.example.test"],"completion_criteria":["Cite route sources"],"domain":"web","skill_tags":["routes"]}
  ]}
 def test_engagement_persists_active_execution_mode_by_default(self):
  row=self.w.store.connection.execute(
   "SELECT rules_json FROM engagements WHERE engagement_id='eng-test'"
  ).fetchone()
  self.assertEqual(__import__("json").loads(row["rules_json"])["execution_mode"],"active")

 def test_invalid_execution_mode_is_rejected(self):
  config={"engagement_id":"eng-invalid-mode","authorization_reference":"AUTH-LAB-002",
          "scope":{"allowed_domains":["app.example.test"]},
          "rules_of_engagement":{"execution_enabled":False},
          "execution_mode":"unrestricted"}
  with self.assertRaisesRegex(WorkflowError,"execution_mode"):
   self.w.initialize(config)

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
  evidence=self.vault.capture("eng-test","reproduction_notes","recon.txt",b"synthetic passive evidence","recon-agent",redacted=True)["evidence_id"]
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
 def test_handoff_rejects_unknown_evidence_reference(self):
  task_id=self.w.create_plan("eng-test",self.plan())[0]["task_id"]
  self.w.start_task(task_id)
  handoff={"task_id":task_id,"engagement_id":"eng-test","agent":"recon-agent","status":"completed","scope_subset":["app.example.test"],"summary":"Reviewed supplied artifacts.","observations":[],"hypotheses":[],"evidence_refs":["evidence://fabricated"],"limitations":[]}
  with self.assertRaises(WorkflowError):
   self.w.accept_handoff(task_id,handoff)

 def test_collected_artifact_must_match_registered_evidence(self):
  task_id=self.w.create_plan("eng-test",self.plan())[0]["task_id"]
  self.w.start_task(task_id)
  handoff={"task_id":task_id,"engagement_id":"eng-test","agent":"recon-agent","status":"completed","scope_subset":["app.example.test"],"summary":"Artifact check","observations":[],"hypotheses":[],"evidence_refs":[],"evidence_artifacts":[{"artifact_id":"a1","type":"http_response","path":".local/evidence/fake.json","collection_status":"collected","description":"Claimed collected response","redacted":True,"sha256":"a"*64}],"limitations":[]}
  with self.assertRaisesRegex(WorkflowError,"registered evidence"):
   self.w.accept_handoff(task_id,handoff)

 def test_finding_write_uses_deterministic_validator(self):
  finding={"finding_id":"f1","engagement_id":"eng-test","title":"Synthetic hypothesis","status":"hypothesis","asset":"app.example.test","description":"Lab hypothesis only","evidence_refs":["evidence://lab/h1"],"proposed_by":"vulnerability-agent"}
  evidence=self.w.store.record_evidence("eng-test","reproduction_notes",".local/evidence/finding.txt","operator")
  finding["evidence_refs"]=[evidence]
  self.w.record_finding("eng-test",finding)
  self.assertEqual(self.w.store.connection.execute("SELECT status FROM findings WHERE finding_id='f1'").fetchone()["status"],"hypothesis")

 def test_passive_followup_is_queued_from_valid_handoff(self):
  task_id=self.w.create_plan("eng-test",self.plan())[0]["task_id"]
  self.w.start_task(task_id)
  evidence=self.vault.capture("eng-test","reproduction_notes","parent.txt",b"route inventory","recon-agent",redacted=True)["evidence_id"]
  handoff={"task_id":task_id,"engagement_id":"eng-test","agent":"recon-agent","status":"completed",
   "scope_subset":["app.example.test"],"summary":"Inventory reviewed","observations":[],"hypotheses":[],
   "evidence_refs":[evidence],"limitations":[],"follow_up_tasks":[{
    "task_key":"recon-context-review","agent":"recon-agent","objective":"Correlate supplied route inventory with existing asset records",
    "completion_criteria":["Cite each correlation"],"domain":"web","skill_tags":["passive-recon"],
    "scope_subset":["app.example.test"],"evidence_refs":[evidence],"constraints":["Use supplied evidence only"]}]}
  self.w.accept_handoff(task_id,handoff)
  rows=self.w.store.connection.execute("SELECT agent,status,input_json FROM tasks WHERE engagement_id='eng-test' ORDER BY rowid").fetchall()
  self.assertEqual(len(rows),3)
  followup=__import__("json").loads(rows[2]["input_json"])
  self.assertEqual(rows[2]["status"],"queued")
  self.assertFalse(followup["active_testing"])
  self.assertEqual(followup["depends_on"],["recon"])
  self.assertEqual(followup["origin"],"adaptive_followup")

 def test_active_and_unknown_agent_followups_are_rejected_without_failing_parent(self):
  task_id=self.w.create_plan("eng-test",self.plan())[0]["task_id"]
  self.w.start_task(task_id)
  evidence=self.vault.capture("eng-test","reproduction_notes","parent2.txt",b"evidence","recon-agent",redacted=True)["evidence_id"]
  base={"task_key":"unsafe-followup","objective":"Do active testing","completion_criteria":["Complete"],
   "domain":"web","skill_tags":["passive-recon"],"scope_subset":["app.example.test"],"evidence_refs":[evidence]}
  handoff={"task_id":task_id,"engagement_id":"eng-test","agent":"recon-agent","status":"completed",
   "scope_subset":["app.example.test"],"summary":"done","observations":[],"hypotheses":[],
   "evidence_refs":[evidence],"limitations":[],"follow_up_tasks":[
    dict(base,agent="active-testing-agent"),dict(base,task_key="unknown-agent",agent="made-up-agent")]}
  self.w.accept_handoff(task_id,handoff)
  self.assertEqual(self.w.store.connection.execute("SELECT COUNT(*) FROM tasks WHERE engagement_id='eng-test'").fetchone()[0],2)
  self.assertEqual(self.w.status("eng-test")["tasks"][0]["status"],"completed")
  self.assertEqual(self.w.store.connection.execute("SELECT COUNT(*) FROM audit_events WHERE engagement_id='eng-test' AND event_type='followup.rejected'").fetchone()[0],2)

 def test_followup_scope_expansion_and_bad_evidence_are_rejected(self):
  task_id=self.w.create_plan("eng-test",self.plan())[0]["task_id"]
  self.w.start_task(task_id)
  evidence=self.vault.capture("eng-test","reproduction_notes","parent3.txt",b"evidence","recon-agent",redacted=True)["evidence_id"]
  handoff={"task_id":task_id,"engagement_id":"eng-test","agent":"recon-agent","status":"completed",
   "scope_subset":["app.example.test"],"summary":"done","observations":[],"hypotheses":[],
   "evidence_refs":[evidence],"limitations":[],"follow_up_tasks":[{
    "task_key":"scope-expansion","agent":"recon-agent","objective":"Review supplied evidence",
    "completion_criteria":["Document"],"domain":"web","skill_tags":["passive-recon"],
    "scope_subset":["outside.example"],"evidence_refs":["evidence://fake"]}]}
  self.w.accept_handoff(task_id,handoff)
  self.assertEqual(len(self.w.status("eng-test")["tasks"]),2)

if __name__=="__main__":
 unittest.main()
