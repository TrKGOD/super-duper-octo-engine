import json
import tempfile
import unittest
from pathlib import Path

from core.orchestration import Workflow, WorkflowError
from scripts.migrate import migrate


class AuthPlanPropagationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "state.sqlite")
        migrate(self.db)
        self.workflow = Workflow(self.db, project_root=self.tmp.name)
        self.workflow.initialize({
            "engagement_id": "auth-plan-lab",
            "authorization_reference": "AUTH-PLAN-LAB-001",
            "scope": {"allowed_domains": ["app.example.test"]},
            "rules_of_engagement": {"execution_enabled": False},
        })
        rules = {
            "execution_enabled": False, "authorization_verified": False,
            "allowed_test_classes": ["http-read-only", "authentication-http"],
            "prohibited_test_classes": ["denial-of-service"],
            "human_approval_required_for_state_changes": True,
            "max_concurrency": 1, "requests_per_second": 1,
            "authorized_identity_ids": ["synthetic-user"],
        }
        self.workflow.store.connection.execute(
            "UPDATE engagements SET rules_json=? WHERE engagement_id=?",
            (json.dumps(rules), "auth-plan-lab"),
        )
        self.workflow.store.connection.commit()
        self.workflow.approve_engagement(
            "auth-plan-lab", "operator", "AUTH-PLAN-LAB-001",
            confirm_written_authorization=True, confirm_scope=True, confirm_rules=True,
        )

    def tearDown(self):
        self.workflow.close()
        self.tmp.cleanup()

    def plan(self, identity_ids):
        return {"tasks": [{
            "task_key": "authenticated-recon", "agent": "recon-agent",
            "objective": "Inspect synthetic authenticated surface",
            "completion_criteria": ["Record scoped response evidence"],
            "domain": "web", "skill_tags": ["authenticated-testing"],
            "scope_subset": ["app.example.test"], "active_testing": True,
            "auth_identity_id": "synthetic-user",
            "auth_session_id": "sess_" + "a" * 32,
            "authorized_identity_ids": identity_ids,
        }]}

    def test_auth_context_is_persisted_into_task_input(self):
        created = self.workflow.create_plan("auth-plan-lab", self.plan(["synthetic-user"]))
        row = self.workflow.store.connection.execute(
            "SELECT input_json FROM tasks WHERE task_id=?", (created[0]["task_id"],)
        ).fetchone()
        task = json.loads(row["input_json"])
        self.assertEqual(task["auth_identity_id"], "synthetic-user")
        self.assertEqual(task["auth_session_id"], "sess_" + "a" * 32)
        self.assertEqual(task["authorized_identity_ids"], ["synthetic-user"])

    def test_task_cannot_select_identity_outside_authorized_set(self):
        with self.assertRaisesRegex(WorkflowError, "explicitly listed"):
            self.workflow.create_plan("auth-plan-lab", self.plan(["another-user"]))


if __name__ == "__main__":
    unittest.main()
