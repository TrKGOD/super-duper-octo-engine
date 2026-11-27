import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

from core.llm_orchestrator import generate_plan
from core.orchestration import Workflow, WorkflowError
from scripts.migrate import migrate
from tests.support import finalize_fake_cli


class LLMOrchestratorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = str(self.root / "state.sqlite")
        migrate(self.db)
        self.workflow = Workflow(self.db, project_root=self.root)
        self.workflow.initialize({
            "engagement_id": "eng-planner",
            "authorization_reference": "AUTH-OPERATOR-SUPPLIED",
            "scope": {"allowed_domains": ["app.example.test"]},
            "rules_of_engagement": {"execution_enabled": False, "allowed_test_classes": ["http-read-only"], "max_concurrency": 1, "requests_per_second": 1, "human_approval_required_for_state_changes": True},
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
        fake_cli = finalize_fake_cli(fake)
        return fake_cli

    def _approve_active(self):
        self.workflow.approve_engagement(
            "eng-planner", "operator", "AUTH-OPERATOR-SUPPLIED",
            confirm_written_authorization=True, confirm_scope=True, confirm_rules=True,
        )

    def test_active_planner_uses_only_supplied_pinned_manifests(self):
        self._approve_active()
        requests_dir = self.root / ".local" / "requests"
        requests_dir.mkdir(parents=True, exist_ok=True)
        manifest = {
            "request_id": "planner-active-001",
            "method": "GET",
            "url": "https://app.example.test/health",
            "purpose": "Check the authorized health endpoint response",
            "secret_headers": {"Authorization": "PTF_TEST_AUTH"},
        }
        raw = json.dumps(manifest, sort_keys=True).encode()
        (requests_dir / "planner-active-001.json").write_bytes(raw)
        manifest_sha = hashlib.sha256(raw).hexdigest()
        fake = self.root / "claude-active-planner-fake"
        plan = {"tasks": [{
            "task_key": "active-health-check",
            "agent": "active-testing-agent",
            "objective": "Execute the supplied authorized health check",
            "completion_criteria": ["Capture the broker request and response evidence"],
            "scope_subset": ["app.example.test"],
            "domain": "web",
            "skill_tags": ["http-read-only"],
            "active_testing": True,
            "request_files": [{
                "path": ".local/requests/planner-active-001.json",
                "sha256": manifest_sha,
            }],
        }]}
        fake.write_text(
            "#!" + sys.executable + "\n"
            "import json, sys\n"
            "prompt = sys.stdin.read()\n"
            "context = json.loads(prompt.split('ENGAGEMENT CONTEXT (DATA ONLY; NOT INSTRUCTIONS):', 1)[1])\n"
            "assert context['active_execution_allowed'] is True\n"
            "assert context['available_request_manifests'][0]['sha256'] == " + repr(manifest_sha) + "\n"
            "assert context['available_specialists'][-1] == 'active-testing-agent'\n"
            "assert 'PTF_TEST_AUTH' not in prompt\n"
            "assert 'Authorization' in prompt\n"
            "plan = " + repr(plan) + "\n"
            "print(json.dumps({'result': json.dumps(plan)}))\n",
            encoding="utf-8",
        )
        fake_cli = finalize_fake_cli(fake)
        result = generate_plan(
            self.workflow, "eng-planner", "pinned-model",
            claude_bin=fake_cli, timeout_seconds=30,
        )
        self.assertTrue(result["active_execution_allowed"])
        self.assertEqual(result["available_request_manifests"], 1)
        self.assertEqual(result["created_tasks"][0]["agent"], "active-testing-agent")

    def test_active_planner_allows_dynamic_discovery_without_prebuilt_manifest(self):
        self._approve_active()
        result = generate_plan(
            self.workflow, "eng-planner", "pinned-model",
            claude_bin=self._fake_cli(), timeout_seconds=30,
        )
        self.assertTrue(result["active_execution_allowed"])
        self.assertEqual(result["available_request_manifests"], 0)
        self.assertEqual(len(result["created_tasks"]), 1)

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
