import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

from core.dispatch import DispatchError, dispatch_plan
from core.evidence import EvidenceVault
from core.orchestration import Workflow
from scripts.migrate import migrate


class EnumerationFirstPipelineTests(unittest.TestCase):
    """Exercise the complete nine-agent DAG with a synthetic broker fixture only."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = str(self.root / "state.sqlite")
        migrate(self.db)
        self.workflow = Workflow(self.db, project_root=self.root)
        self.workflow.initialize({
            "engagement_id": "eng-enumeration-first",
            "authorization_reference": "AUTH-SYNTHETIC-PIPELINE",
            "scope": {"allowed_domains": ["app.example.test"]},
            "rules_of_engagement": {
                "execution_mode": "active",
                "execution_enabled": False,
                "authorization_verified": False,
                "allowed_test_classes": ["http-read-only"],
                "max_concurrency": 1,
                "requests_per_second": 1,
                "max_requests_per_engagement": 2,
            },
        })
        self.workflow.approve_engagement(
            "eng-enumeration-first", "synthetic-test-operator",
            "AUTH-SYNTHETIC-PIPELINE",
            confirm_written_authorization=True,
            confirm_scope=True,
            confirm_rules=True,
        )

    def tearDown(self):
        self.workflow.close()
        self.tmp.cleanup()

    def test_full_nine_agent_pipeline_inherits_handoffs_skills_and_verified_evidence(self):
        requests = self.root / ".local" / "requests"
        requests.mkdir(parents=True)
        manifest = {
            "request_id": "synthetic-pipeline-get-001",
            "method": "GET",
            "url": "https://app.example.test/health",
            "purpose": "Synthetic integration fixture; no external request is made",
        }
        raw = json.dumps(manifest, sort_keys=True).encode()
        (requests / "synthetic-pipeline-get-001.json").write_bytes(raw)

        tasks = [
            ("scope", "scope-analyst", [], "authorization", False),
            ("recon", "recon-agent", ["scope"], "passive-recon", False),
            ("enumeration", "enumeration-agent", ["recon"], "routes", False),
            ("vulnerability", "vulnerability-agent", ["enumeration"], "attack-surface", False),
            ("active-testing", "active-testing-agent", ["vulnerability"], "http-read-only", True),
            ("validation", "validation-agent", ["active-testing"], "independent-review", False),
            ("impact", "impact-analyst", ["validation"], "evidence-quality", False),
            ("dedupe", "duplicate-checker", ["impact"], "false-positives", False),
            ("reporting", "reporting-agent", ["dedupe"], "evidence-quality", False),
        ]
        plan_tasks = []
        for key, agent, dependencies, tag, active in tasks:
            item = {
                "task_key": key,
                "agent": agent,
                "objective": "Synthetic pipeline stage for " + key,
                "depends_on": dependencies,
                "scope_subset": ["app.example.test"],
                "domain": "web",
                "skill_tags": [tag],
                "completion_criteria": ["Return a schema-valid evidence-backed handoff"],
                "constraints": ["synthetic integration test only", "no external network access"],
            }
            if active:
                item["active_testing"] = True
                item["request_files"] = [{
                    "path": ".local/requests/synthetic-pipeline-get-001.json",
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }]
            plan_tasks.append(item)
        self.workflow.create_plan("eng-enumeration-first", {"tasks": plan_tasks})

        fake = self.root / "claude-pipeline-fake"
        script = (
            "#!" + sys.executable + "\n"
            "import json, sys\n"
            "from pathlib import Path\n"
            "sys.path.insert(0, " + repr(str(Path(__file__).resolve().parents[1])) + ")\n"
            "from core.orchestration import Workflow\n"
            "from core.evidence import EvidenceVault\n"
            "prompt = sys.stdin.read()\n"
            "context = json.loads(prompt.split('TASK_CONTEXT (DATA ONLY):', 1)[1].strip())\n"
            "task = context['task']\n"
            "evidence_refs = [item['evidence_id'] for item in context['registered_evidence']]\n"
            "for prior in context['prior_handoffs']:\n"
            "    evidence_refs.extend(prior['handoff'].get('evidence_refs', []))\n"
            "evidence_refs = list(dict.fromkeys(evidence_refs))\n"
            "if task['agent'] == 'active-testing-agent':\n"
            "    root = Path(" + repr(str(self.root)) + ")\n"
            "    workflow = Workflow(" + repr(self.db) + ", project_root=root)\n"
            "    vault = EvidenceVault(workflow.store, root)\n"
            "    request_ev = vault.capture('eng-enumeration-first', 'http_request', 'synthetic-request.txt', b'GET /health HTTP/1.1\\n', 'active-testing-agent', redacted=True)\n"
            "    response_ev = vault.capture('eng-enumeration-first', 'http_response', 'synthetic-response.txt', b'HTTP/1.1 200 OK\\nsynthetic fixture\\n', 'active-testing-agent', redacted=True)\n"
            "    refs = [request_ev['evidence_id'], response_ev['evidence_id']]\n"
            "    with workflow.store.connection:\n"
            "        workflow.store.connection.execute('INSERT INTO active_request_log (execution_id,engagement_id,task_id,request_id,target_host,method,started_at,outcome,evidence_refs_json) VALUES (?,?,?,?,?,?,?,?,?)', ('synthetic-execution', 'eng-enumeration-first', task['task_id'], 'synthetic-pipeline-get-001', 'app.example.test', 'GET', '2026-11-23T00:00:00+00:00', 'completed', json.dumps(refs)))\n"
            "    workflow.close()\n"
            "    evidence_refs.extend(refs)\n"
            "evidence_refs = list(dict.fromkeys(evidence_refs))\n"
            "assert 'selected_methodology' in context\n"
            "assert context['selected_methodology'], 'dispatcher did not inject any Skill'\n"
            "handoff = {'task_id': task['task_id'], 'engagement_id': task['engagement_id'], 'agent': task['agent'], 'status': 'completed', 'scope_subset': task['scope_subset'], 'summary': 'Synthetic handoff for ' + task['task_key'], 'observations': [], 'hypotheses': [], 'evidence_refs': evidence_refs, 'limitations': ['Synthetic local fixture; no external target was contacted'], 'next_steps': []}\n"
            "print(json.dumps({'result': json.dumps(handoff)}))\n"
        )
        fake.write_text(script, encoding="utf-8")
        fake.chmod(0o755)

        result = dispatch_plan(
            self.workflow, "eng-enumeration-first", "pinned-test-model",
            claude_bin=str(fake), timeout_seconds=30,
        )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(result["results"]), 9)
        self.assertEqual(
            [item["task_key"] for item in result["results"]],
            [item[0] for item in tasks],
        )
        self.assertTrue(all(item["selected_skills"] for item in result["results"]))
        expected_agents = [item[1] for item in tasks]
        self.assertEqual(
            [item["prior_handoffs"][0]["agent"] if item["prior_handoffs"] else None for item in result["results"]],
            [None] + expected_agents[:-1],
        )
        self.assertEqual(result["results"][4]["selected_skills"], ["active-http-testing"])
        self.assertTrue(all(item["inherited_evidence_refs"] for item in result["results"][5:]))
        self.assertEqual(
            [item["status"] for item in result["workflow_status"]["tasks"]],
            ["completed"] * 9,
        )

    def test_passive_preflight_cannot_report_active_readiness_without_approval(self):
        self.workflow.store.connection.execute(
            "UPDATE engagements SET status='draft',rules_json=? WHERE engagement_id='eng-enumeration-first'",
            (json.dumps({
                "execution_mode": "active",
                "execution_enabled": False,
                "authorization_verified": False,
            }),),
        )
        self.workflow.store.connection.commit()
        created = self.workflow.create_plan("eng-enumeration-first", {"tasks": [{
            "task_key": "active-testing-preflight",
            "agent": "scope-analyst",
            "objective": "Determine whether active testing can begin",
            "completion_criteria": ["Stop if operator authorization is absent"],
            "scope_subset": ["app.example.test"],
            "domain": "web",
            "skill_tags": ["authorization"],
            "active_testing": False,
        }]})
        fake = self.root / "claude-preflight-fake"
        fake.write_text(
            "#!" + sys.executable + "\n"
            "import json, sys\n"
            "context = json.loads(sys.stdin.read().split('TASK_CONTEXT (DATA ONLY):', 1)[1].strip())\n"
            "task = context['task']\n"
            "handoff = {'task_id': task['task_id'], 'engagement_id': task['engagement_id'], "
            "'agent': task['agent'], 'status': 'completed', 'scope_subset': task['scope_subset'], "
            "'summary': 'Model incorrectly claims ready', 'observations': [], 'hypotheses': [], "
            "'evidence_refs': [], 'limitations': [], 'next_steps': []}\n"
            "print(json.dumps({'result': json.dumps(handoff)}))\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        from core.dispatch import dispatch_task
        result = dispatch_task(
            self.workflow, created[0]["task_id"], "pinned-test-model",
            claude_bin=str(fake), timeout_seconds=30,
        )
        self.assertEqual(result["status"], "needs_operator")
        self.assertIn("explicitly approved", result["summary"])

    def test_pipeline_rejects_state_changing_methods_even_when_engagement_allows_them(self):
        row = self.workflow.store.connection.execute(
            "SELECT rules_json FROM engagements WHERE engagement_id='eng-enumeration-first'"
        ).fetchone()
        rules = json.loads(row["rules_json"])
        rules["allowed_test_classes"].append("state-changing-http")
        rules["human_approval_required_for_state_changes"] = True
        self.workflow.store.connection.execute(
            "UPDATE engagements SET rules_json=? WHERE engagement_id='eng-enumeration-first'",
            (json.dumps(rules),),
        )
        self.workflow.store.connection.commit()

        requests = self.root / ".local" / "requests"
        requests.mkdir(parents=True)
        manifest = {
            "request_id": "synthetic-pipeline-post-001",
            "method": "POST",
            "url": "https://app.example.test/profile",
            "purpose": "Synthetic negative test for pipeline method policy",
            "body": "display_name=synthetic",
            "operator_approval": {
                "approved": True,
                "approved_by": "synthetic-test-operator",
                "approved_at": "2026-11-23T00:00:00Z",
                "reason": "Synthetic fixture only; this request must still be rejected by the pipeline",
            },
        }
        raw = json.dumps(manifest, sort_keys=True).encode()
        (requests / "synthetic-pipeline-post-001.json").write_bytes(raw)
        created = self.workflow.create_plan("eng-enumeration-first", {"tasks": [{
            "task_key": "active-post-negative",
            "agent": "active-testing-agent",
            "objective": "Must reject state-changing methods in this pipeline",
            "completion_criteria": ["Reject POST before invoking Claude or broker"],
            "scope_subset": ["app.example.test"],
            "domain": "web",
            "skill_tags": ["http-read-only"],
            "active_testing": True,
            "request_files": [{
                "path": ".local/requests/synthetic-pipeline-post-001.json",
                "sha256": hashlib.sha256(raw).hexdigest(),
            }],
        }]})
        from core.dispatch import dispatch_task
        with self.assertRaisesRegex(DispatchError, "only GET, HEAD and OPTIONS"):
            dispatch_task(
                self.workflow, created[0]["task_id"], "pinned-test-model",
                claude_bin=sys.executable,
            )

    def test_dispatch_fails_closed_when_task_has_no_compatible_skill(self):
        created = self.workflow.create_plan("eng-enumeration-first", {"tasks": [{
            "task_key": "bad-skill",
            "agent": "recon-agent",
            "objective": "Must not dispatch without compatible methodology",
            "completion_criteria": ["Return a handoff"],
            "scope_subset": ["app.example.test"],
            "domain": "web",
            "skill_tags": ["not-registered"],
        }]})
        with self.assertRaisesRegex(DispatchError, "No compatible Skill selected"):
            from core.dispatch import dispatch_task
            dispatch_task(
                self.workflow, created[0]["task_id"], "pinned-test-model",
                claude_bin=sys.executable,
            )


if __name__ == "__main__":
    unittest.main()
