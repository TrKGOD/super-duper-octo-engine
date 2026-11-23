import unittest
from hooks.command_guard import allowed_argv,safe_local_json
class CommandGuardTests(unittest.TestCase):
 def test_allows_local_workflow_commands(self):
  self.assertTrue(allowed_argv(["python3","scripts/migrate.py","--db",".local/state.sqlite3"]))
  self.assertTrue(allowed_argv(["python3","scripts/workflow.py","--db",".local/state.sqlite3","start","--task-id","task_1"]))
  self.assertTrue(allowed_argv(["python3","scripts/workflow.py","--db",".local/state.sqlite3","handoff","--task-id","task_1","--file",".local/handoff.json"]))
 def test_rejects_arbitrary_commands(self):
  self.assertFalse(allowed_argv(["python3","-c","import os"]))
  self.assertFalse(allowed_argv(["nmap","app.example.test"]))
  self.assertFalse(allowed_argv(["python3","scripts/workflow.py","--db","/tmp/db","status","--engagement-id","e"]))
 def test_local_json_paths_are_confined(self):
  self.assertTrue(safe_local_json(".local/plan.json"))
  self.assertFalse(safe_local_json("../plan.json"))
  self.assertFalse(safe_local_json("/tmp/plan.json"))
if __name__=="__main__":
 unittest.main()
