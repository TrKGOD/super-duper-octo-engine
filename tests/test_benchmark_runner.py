import json
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.run_benchmark import parse_model_json, run, validate_case
from scripts.runtime_smoke import parse_agent_result


class BenchmarkRunnerTests(unittest.TestCase):
    def _case(self, cases):
        cases.mkdir()
        (cases / "one.json").write_text(json.dumps({
            "case_id": "SYN-TEST-001",
            "kind": "synthetic",
            "description": "Fixture with a demonstrated cross-user object read.",
            "expected_finding": True,
            "required_evidence": ["request_identity", "object_owner_identity"],
            "fixtures": {
                "request_identity": "tenant-b",
                "object_owner_identity": "tenant-a",
            },
        }), encoding="utf-8")

    def test_runner_passes_prompt_on_stdin_and_captures_usage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cases = root / "cases"
            self._case(cases)
            fake = root / "claude-fake"
            fake.write_text(
                "#!" + sys.executable + "\n"
                "import json, sys\n"
                "prompt = sys.stdin.read()\n"
                "assert 'Synthetic isolated security-analysis fixture' in prompt\n"
                "assert 'AGENT NAME: vulnerability-agent' in prompt\n"
                "assert not any('Synthetic isolated security-analysis fixture' in a for a in sys.argv)\n"
                "result = {'case_id':'SYN-TEST-001','detected':True,"
                "'vulnerability_type':'BOLA','evidence_fields':['request_identity']}\n"
                "print(json.dumps({'result':json.dumps(result),'total_cost_usd':0.0123,"
                "'usage':{'input_tokens':120,'output_tokens':35},'duration_ms':900}))\n",
                encoding="utf-8",
            )
            fake.chmod(0o755)
            predictions, manifest = run(
                cases, "vulnerability-agent", "pinned-model", 60,
                "synthetic-lab-v1", str(fake),
            )
            self.assertEqual(predictions["predictions"][0]["case_id"], "SYN-TEST-001")
            self.assertEqual(manifest["execution"], "claude_code_cli_prompt_via_stdin")
            self.assertEqual(manifest["model"], "pinned-model")
            self.assertTrue(manifest["usage_available"])
            self.assertEqual(manifest["total_cost_usd"], 0.0123)
            self.assertEqual(manifest["runs"][0]["usage"]["usage"]["input_tokens"], 120)

    def test_positive_case_requires_complete_fixture_payload(self):
        with self.assertRaisesRegex(ValueError, "lacks required fixture fields"):
            validate_case({
                "case_id": "SYN-BAD-001",
                "kind": "synthetic",
                "expected_finding": True,
                "required_evidence": ["request_identity"],
                "fixtures": {},
            }, "bad.json")

    def test_negative_case_may_have_no_fixture_payload(self):
        validate_case({
            "case_id": "SYN-NEG-001",
            "kind": "synthetic",
            "expected_finding": False,
            "required_evidence": ["request_identity"],
            "fixtures": {},
        }, "negative.json")

    def test_parse_fenced_json_result_envelope(self):
        payload = {"case_id": "SYN-TEST-FENCE", "detected": True, "evidence_fields": ["request_identity"]}
        stdout = json.dumps({"result": "```json\n" + json.dumps(payload) + "\n```"})
        self.assertEqual(parse_model_json(stdout), payload)

    def test_parse_plain_json_result_envelope(self):
        payload = {"case_id": "SYN-TEST-PLAIN", "detected": False, "evidence_fields": []}
        stdout = json.dumps({"result": json.dumps(payload)})
        self.assertEqual(parse_model_json(stdout), payload)

    def test_runtime_smoke_parses_fenced_result(self):
        payload = {"smoke_test": True, "agent": "vulnerability-agent", "status": "completed"}
        stdout = json.dumps({"result": "```json\n" + json.dumps(payload) + "\n```"})
        _, parsed = parse_agent_result(stdout)
        self.assertEqual(parsed, payload)

    def test_runtime_smoke_prompt_parser_accepts_plain_result(self):
        payload = {"smoke_test": True, "agent": "recon-agent", "status": "completed"}
        _, parsed = parse_agent_result(json.dumps({"result": json.dumps(payload)}))
        self.assertEqual(parsed, payload)


if __name__ == "__main__":
    unittest.main()
