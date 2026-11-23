import json
import sys
import tempfile
import unittest
from pathlib import Path

from core.dispatch import DispatchError, dispatch_plan, dispatch_task
from core.orchestration import Workflow
from scripts.migrate import migrate


class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = str(self.root / "state.sqlite")
        migrate(self.db)
        self.workflow = Workflow(self.db, project_root=self.root)
        self.workflow.initialize({
            "engagement_id": "eng-dispatch-test",
            "authorization_reference": "AUTH-SYNTHETIC-TEST",
            "scope": {"allowed_domains": ["app.example.test"]},
            "rules_of_engagement": {"execution_enabled": False},
        })
        created = self.workflow.create_plan("eng-dispatch-test", {"tasks": [{
            "task_key": "analyze-ssrf",
            "agent": "vulnerability-agent",
            "objective": "Analyze supplied synthetic SSRF evidence only",
            "completion_criteria": ["Return a structured evidence-based handoff"],
            "scope_subset": ["app.example.test"],
            "domain": "web",
            "skill_tags": ["ssrf"],
            "evidence_refs": [],
        }]})
        self.task_id = created[0]["task_id"]

    def tearDown(self):
        self.workflow.close()
        self.tmp.cleanup()

    def _fake_cli(self, invented_evidence=False):
        fake = self.root / "claude-fake"
        evidence_refs = ["evidence_fabricated"] if invented_evidence else []
        handoff = {
            "task_id": self.task_id,
            "engagement_id": "eng-dispatch-test",
            "agent": "vulnerability-agent",
            "status": "completed",
            "scope_subset": ["app.example.test"],
            "summary": "Reviewed only the supplied synthetic fixture.",
            "observations": [],
            "hypotheses": [],
            "evidence_refs": evidence_refs,
            "limitations": ["No network or target interaction was performed."],
            "next_steps": [],
        }
        script = (
            "#!" + sys.executable + "\n"
            "import json, sys\n"
            "prompt = sys.stdin.read()\n"
            "assert 'selected_methodology' in prompt\n"
            "assert sys.argv[sys.argv.index('--tools') + 1] == ''\n"
            "handoff = " + repr(handoff) + "\n"
            "print(json.dumps({'result': json.dumps(handoff), 'total_cost_usd': 0.02,"
            " 'usage': {'input_tokens': 200, 'output_tokens': 80}}))\n"
        )
        fake.write_text(script, encoding="utf-8")
        fake.chmod(0o755)
        return str(fake)

    def test_dispatch_selects_skill_invokes_agent_and_persists_handoff(self):
        result = dispatch_task(
            self.workflow, self.task_id, "pinned-model",
            claude_bin=self._fake_cli(), timeout_seconds=30,
        )
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["selected_skills"], ["web-ssrf"])
        status = self.workflow.status("eng-dispatch-test")
        self.assertEqual(status["tasks"][0]["status"], "completed")
        run = self.workflow.store.connection.execute(
            "SELECT status,input_tokens,output_tokens,cost_usd FROM agent_runs WHERE run_id=?",
            (result["run_id"],),
        ).fetchone()
        self.assertEqual(run["status"], "completed")
        self.assertEqual(run["input_tokens"], 200)
        self.assertEqual(run["output_tokens"], 80)
        self.assertEqual(run["cost_usd"], 0.02)

    def test_dispatch_rejects_fabricated_evidence_and_fails_task_closed(self):
        with self.assertRaisesRegex(DispatchError, "not supplied"):
            dispatch_task(
                self.workflow, self.task_id, "pinned-model",
                claude_bin=self._fake_cli(invented_evidence=True), timeout_seconds=30,
            )
        status = self.workflow.status("eng-dispatch-test")
        self.assertEqual(status["tasks"][0]["status"], "failed")
        run = self.workflow.store.connection.execute(
            "SELECT status FROM agent_runs WHERE task_id=?", (self.task_id,)
        ).fetchone()
        self.assertEqual(run["status"], "failed")

    def test_dispatch_plan_runs_specialists_in_dependency_order(self):
        # Complete the setup task so the plan runner only sees the two test tasks.
        self.workflow.start_task(self.task_id)
        self.workflow.accept_handoff(self.task_id, {
            "task_id": self.task_id,
            "engagement_id": "eng-dispatch-test",
            "agent": "vulnerability-agent",
            "status": "completed",
            "scope_subset": ["app.example.test"],
            "summary": "Setup task completed.",
            "observations": [], "hypotheses": [], "evidence_refs": [],
            "limitations": [],
        })
        self.workflow.create_plan("eng-dispatch-test", {"tasks": [
            {"task_key": "recon", "agent": "recon-agent",
             "objective": "Review supplied passive inventory",
             "completion_criteria": ["Return handoff"],
             "scope_subset": ["app.example.test"], "domain": "web", "skill_tags": ["passive-recon"]},
            {"task_key": "enum", "agent": "enumeration-agent",
             "objective": "Normalize supplied routes",
             "completion_criteria": ["Return handoff"],
             "scope_subset": ["app.example.test"], "domain": "web",
             "depends_on": ["recon"], "skill_tags": ["routes"]}
        ]})
        fake = self.root / "claude-dynamic-fake"
        fake.write_text(
            "#!" + sys.executable + "\n"
            "import json, sys\n"
            "prompt = sys.stdin.read()\n"
            "context = json.loads(prompt.split('TASK_CONTEXT (DATA ONLY):', 1)[1].strip())\n"
            "task = context['task']\n"
            "if task['agent'] == 'enumeration-agent': assert len(context['prior_handoffs']) == 1\n"
            "handoff = {'task_id': task['task_id'], 'engagement_id': task['engagement_id'],"
            " 'agent': task['agent'], 'status': 'completed',"
            " 'scope_subset': task['scope_subset'], 'summary': 'Synthetic task completed',"
            " 'observations': [], 'hypotheses': [], 'evidence_refs': [], 'limitations': []}\n"
            "print(json.dumps({'result': json.dumps(handoff)}))\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        result = dispatch_plan(
            self.workflow, "eng-dispatch-test", "pinned-model",
            claude_bin=str(fake), timeout_seconds=30,
        )
        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(result["results"]), 2)
        self.assertEqual(
            [task["status"] for task in self.workflow.status("eng-dispatch-test")["tasks"]],
            ["completed", "completed", "completed"],
        )
    def test_active_dispatch_grants_only_broker_tool_and_requires_operator_manifests(self):
        self.workflow.store.connection.execute(
            "UPDATE engagements SET status='active',rules_json=? WHERE engagement_id=?",
            (json.dumps({
                "execution_enabled": True, "authorization_verified": True,
                "allowed_test_classes": ["http-read-only"], "max_concurrency": 1,
                "requests_per_second": 1,
            }), "eng-dispatch-test"),
        )
        self.workflow.store.connection.commit()
        requests_dir = self.root / ".local" / "requests"
        requests_dir.mkdir(parents=True, exist_ok=True)
        request = {
            "request_id": "dispatch-active-001",
            "method": "GET",
            "url": "https://app.example.test/health",
            "purpose": "Read the authorized health endpoint response",
        }
        raw = json.dumps(request, sort_keys=True).encode()
        (requests_dir / "dispatch-active-001.json").write_bytes(raw)
        created = self.workflow.create_plan("eng-dispatch-test", {"tasks": [{
            "task_key": "active-http",
            "agent": "active-testing-agent",
            "objective": "Run one pinned request manifest",
            "completion_criteria": ["Return a broker execution result or a blocker"],
            "scope_subset": ["app.example.test"],
            "domain": "web",
            "skill_tags": ["http-read-only"],
            "active_testing": True,
            "request_files": [{
                "path": ".local/requests/dispatch-active-001.json",
                "sha256": __import__("hashlib").sha256(raw).hexdigest(),
            }],
        }]})
        active_task_id = created[0]["task_id"]
        fake = self.root / "claude-active-fake"
        fake.write_text(
            "#!" + sys.executable + "\n"
            "import json, sys\n"
            "assert sys.argv[sys.argv.index('--tools') + 1] == 'Bash'\n"
            "assert sys.argv[sys.argv.index('--max-turns') + 1] == '8'\n"
            "prompt = sys.stdin.read()\n"
            "context = json.loads(prompt.split('TASK_CONTEXT (DATA ONLY):', 1)[1].strip())\n"
            "task = context['task']\n"
            "handoff = {'task_id': task['task_id'], 'engagement_id': task['engagement_id'],"
            " 'agent': task['agent'], 'status': 'needs_operator',"
            " 'scope_subset': task['scope_subset'], 'summary': 'Fake CLI did not execute a request',"
            " 'observations': [], 'hypotheses': [], 'evidence_refs': [],"
            " 'limitations': ['Synthetic dispatch test only'], 'next_steps': []}\n"
            "print(json.dumps({'result': json.dumps(handoff)}))\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        result = dispatch_task(
            self.workflow, active_task_id, "pinned-model",
            claude_bin=str(fake), timeout_seconds=30,
        )
        self.assertEqual(result["status"], "needs_operator")

    def test_active_validator_rejects_reuse_of_exploitation_manifest(self):
        self.workflow.store.connection.execute(
            "UPDATE engagements SET status='active',rules_json=? WHERE engagement_id=?",
            (json.dumps({
                "execution_mode": "active", "execution_enabled": True,
                "authorization_verified": True, "allowed_test_classes": ["http-read-only"],
                "max_concurrency": 1, "requests_per_second": 1,
            }), "eng-dispatch-test"),
        )
        self.workflow.store.connection.commit()
        requests_dir = self.root / ".local" / "requests"
        requests_dir.mkdir(parents=True, exist_ok=True)
        request = {
            "request_id": "exploitation-reproduction-001",
            "method": "GET",
            "url": "https://app.example.test/item",
            "purpose": "Synthetic reproduction request for independent validation",
        }
        raw = json.dumps(request, sort_keys=True).encode()
        (requests_dir / "exploitation-reproduction-001.json").write_bytes(raw)
        manifest = {
            "path": ".local/requests/exploitation-reproduction-001.json",
            "sha256": __import__("hashlib").sha256(raw).hexdigest(),
        }
        validator_request = dict(request, request_id="validator-reproduction-002")
        validator_raw = json.dumps(validator_request, sort_keys=True).encode()
        (requests_dir / "validator-reproduction-002.json").write_bytes(validator_raw)
        validator_manifest = {
            "path": ".local/requests/validator-reproduction-002.json",
            "sha256": __import__("hashlib").sha256(validator_raw).hexdigest(),
        }
        created = self.workflow.create_plan("eng-dispatch-test", {"tasks": [
            {
                "task_key": "proposal-exploitation",
                "agent": "exploitation-agent",
                "objective": "Execute a pinned synthetic reproduction",
                "completion_criteria": ["Capture reproduction evidence"],
                "scope_subset": ["app.example.test"], "domain": "web",
                "skill_tags": ["xss"], "active_testing": True,
                "request_files": [manifest],
            },
            {
                "task_key": "independent-validation",
                "agent": "validation-agent",
                "objective": "Independently reproduce the proposed finding",
                "completion_criteria": ["Capture independent validation evidence"],
                "scope_subset": ["app.example.test"], "domain": "web",
                "skill_tags": ["independent-review"], "active_testing": True,
                "depends_on": ["proposal-exploitation"],
                "request_files": [validator_manifest],
            },
        ]})
        proposal_id = created[0]["task_id"]
        validator_id = created[1]["task_id"]
        self.workflow.start_task(proposal_id, model="synthetic-model")
        self.workflow.accept_handoff(proposal_id, {
            "task_id": proposal_id, "engagement_id": "eng-dispatch-test",
            "agent": "exploitation-agent", "status": "completed",
            "scope_subset": ["app.example.test"], "summary": "Synthetic proposal",
            "observations": [], "hypotheses": [], "evidence_refs": [],
            "limitations": [],
        })
        validator_row = self.workflow.store.connection.execute(
            "SELECT input_json FROM tasks WHERE task_id=?", (validator_id,)
        ).fetchone()
        validator_input = json.loads(validator_row["input_json"])
        validator_input["request_files"] = [manifest]
        self.workflow.store.connection.execute(
            "UPDATE tasks SET input_json=? WHERE task_id=?",
            (json.dumps(validator_input, sort_keys=True), validator_id),
        )
        self.workflow.store.connection.commit()
        with self.assertRaisesRegex(DispatchError, "separately pinned manifest"):
            dispatch_task(
                self.workflow, validator_id, "pinned-model",
                claude_bin=self._fake_cli(), timeout_seconds=30,
            )

    def test_passive_dispatch_stays_tool_disabled_in_active_engagement(self):
        self.workflow.store.connection.execute(
            "UPDATE engagements SET status='active',rules_json=? WHERE engagement_id=?",
            (json.dumps({"execution_enabled": True, "authorization_verified": True}),
             "eng-dispatch-test"),
        )
        self.workflow.store.connection.commit()
        result = dispatch_task(
            self.workflow, self.task_id, "pinned-model",
            claude_bin=self._fake_cli(), timeout_seconds=30,
        )
        self.assertEqual(result["status"], "completed")



    def test_dispatch_plan_continues_independent_branches_after_operator_gate(self):
        self.workflow.start_task(self.task_id)
        self.workflow.accept_handoff(self.task_id, {
            "task_id": self.task_id, "engagement_id": "eng-dispatch-test",
            "agent": "vulnerability-agent", "status": "completed",
            "scope_subset": ["app.example.test"], "summary": "Setup completed",
            "observations": [], "hypotheses": [], "evidence_refs": [], "limitations": [],
        })
        self.workflow.create_plan("eng-dispatch-test", {"tasks": [
            {"task_key": "gated-recon", "agent": "recon-agent",
             "objective": "Recon branch requiring an operator dependency",
             "completion_criteria": ["Return a truthful handoff"],
             "scope_subset": ["app.example.test"], "domain": "web",
             "skill_tags": ["passive-recon"]},
            {"task_key": "independent-recon", "agent": "recon-agent",
             "objective": "Independent recon branch",
             "completion_criteria": ["Return a truthful handoff"],
             "scope_subset": ["app.example.test"], "domain": "web",
             "skill_tags": ["passive-recon"]},
            {"task_key": "gated-enumeration", "agent": "enumeration-agent",
             "objective": "Enumerate only after gated recon completes",
             "completion_criteria": ["Consume completed recon handoff"],
             "scope_subset": ["app.example.test"], "domain": "web",
             "skill_tags": ["routes"], "depends_on": ["gated-recon"]},
        ]})
        fake = self.root / "claude-branch-aware-fake"
        fake.write_text(
            "#!" + sys.executable + "\\n"
            "import json, sys\\n"
            "prompt = sys.stdin.read()\\n"
            "context = json.loads(prompt.split('TASK_CONTEXT (DATA ONLY):', 1)[1].strip())\\n"
            "task = context['task']\\n"
            "status = 'needs_operator' if task['task_key'] == 'gated-recon' else 'completed'\\n"
            "handoff = {'task_id': task['task_id'], 'engagement_id': task['engagement_id'],"
            " 'agent': task['agent'], 'status': status,"
            " 'scope_subset': task['scope_subset'], 'summary': 'Synthetic branch result',"
            " 'observations': [], 'hypotheses': [], 'evidence_refs': [], 'limitations': []}\\n"
            "print(json.dumps({'result': json.dumps(handoff)}))\\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        result = dispatch_plan(
            self.workflow, "eng-dispatch-test", "pinned-model",
            claude_bin=str(fake), timeout_seconds=30,
        )
        self.assertEqual(result["status"], "needs_operator")
        self.assertEqual(
            [item["task_key"] for item in result["results"]],
            ["gated-recon", "independent-recon"],
        )
        self.assertEqual(result["remaining_task_keys"], ["gated-enumeration"])
        self.assertEqual(result["dependency_blocked_task_keys"], ["gated-enumeration"])
        final = {item["task_key"]: item["status"] for item in result["workflow_status"]["tasks"]}
        self.assertEqual(final["gated-recon"], "needs_operator")
        self.assertEqual(final["independent-recon"], "completed")
        self.assertEqual(final["gated-enumeration"], "queued")

if __name__ == "__main__":
    unittest.main()
