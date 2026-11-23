import json
import sys
import tempfile
import unittest
from pathlib import Path

from core.llm_orchestrator import generate_plan
from core.orchestration import Workflow, WorkflowError
from scripts.migrate import migrate


class LLMOrchestratorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = str(self.root / "state.sqlite")
        migrate(self.db)
        self.workflow = Workflow(self.db)
        self.workflow.initialize({
            "engagement_id": "eng-planner",
            "authorization_reference": "AUTH-OPERATOR-SUPPLIED",
            "scope": {"allowed_domains": ["app.example.test"]},
            "rules_of_engagement": {"execution_enabled": False},
        })

    def tearDown(self):
        self.workflow.close()
        self.tmp.cleanup()

    def _fake_cli(self, asset="app.example.test"):
        fake = self.root / "claude-planner-fake"
        plan = {"tasks": [{
            "task_key": "review-supplied-artifacts",
            "agent": "recon-agent",
            "objective": "Review supplied passive inventory for " + asset,
            "completion_criteria": ["Return source-backed observations"],
            "scope_subset": [asset],
            "domain": "web",
            "skill_tags": ["passive-recon"],
            "constraints": ["passive analysis only", "no network requests"],
        }]}
        fake.write_text(
            "#!" + sys.executable + "\n"
            "import json\n"
            "print(json.dumps({'result': json.dumps(" + repr(plan) + ")}))\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        return str(fake)

    def test_generates_and_persists_plan_with_no_tools_cli(self):
        result = generate_plan(
            self.workflow, "eng-planner", "pinned-model",
            claude_bin=self._fake_cli(), timeout_seconds=30,
        )
        self.assertEqual(result["planner"], "pentest-orchestrator")
        self.assertEqual(len(result["created_tasks"]), 1)
        self.assertEqual(self.workflow.status("eng-planner")["tasks"][0]["status"], "queued")

    def test_rejects_llm_plan_expanding_scope(self):
        with self.assertRaisesRegex(WorkflowError, "scope exceeds"):
            generate_plan(
                self.workflow, "eng-planner", "pinned-model",
                claude_bin=self._fake_cli("outside.example.test"), timeout_seconds=30,
            )

    def test_refuses_engagement_without_explicit_assets(self):
        self.workflow.store.connection.execute(
            "UPDATE engagements SET scope_json=? WHERE engagement_id=?",
            (json.dumps({"allowed_domains": []}), "eng-planner"),
        )
        self.workflow.store.connection.commit()
        with self.assertRaisesRegex(WorkflowError, "No explicit in-scope assets"):
            generate_plan(
                self.workflow, "eng-planner", "pinned-model",
                claude_bin=self._fake_cli(), timeout_seconds=30,
            )


if __name__ == "__main__":
    unittest.main()
