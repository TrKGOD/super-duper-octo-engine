"""Initial tool adapters (Component E) tests.

Real parsers are tested against realistic tool output; the catalog's honesty is checked
(binaries absent -> requires_operator_configuration, never a fake "available"); arguments are
injection-safe; and one adapter is run end-to-end through the real Phase 5 broker with a
synthetic stand-in plus the real parser, proving the full path works without claiming an
unbundled binary is installed.
"""
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.migrate import migrate
from core.store import StateStore
from core.workers import WorkerManager
from core.workers.tools import ToolError, ToolSpec
from core.tools import (ProfilePolicy, SAFE, PASSIVE, ACTIVE_CONTROLLED, ToolDefinition,
                       adapter_for, build_default_catalog)
from core.tools.parsers import (parse_dalfox, parse_dnsx, parse_ffuf, parse_httpx, parse_katana,
                                parse_nuclei, parse_subfinder)

PY = sys.executable


class ParserTests(unittest.TestCase):
    def test_subfinder(self):
        out = parse_subfinder("api.example.com\nwww.example.com\napi.example.com\n")
        self.assertEqual([o["host"] for o in out], ["api.example.com", "www.example.com"])

    def test_dnsx(self):
        out = parse_dnsx('{"host":"api.example.com","a":["1.2.3.4"],"status_code":"NOERROR"}')
        self.assertEqual(out[0], {"type": "dns_record", "host": "api.example.com",
                                  "a_records": ["1.2.3.4"], "status": "NOERROR"})

    def test_httpx(self):
        out = parse_httpx('{"url":"https://api.example.com","status_code":200,"title":"API","tech":["nginx"]}')
        self.assertEqual(out[0]["url"], "https://api.example.com")
        self.assertEqual(out[0]["status"], 200)
        self.assertEqual(out[0]["technologies"], ["nginx"])

    def test_katana_ignores_relative(self):
        out = parse_katana("https://app/login\nhttps://app/api/users\n/relative\n")
        self.assertEqual([o["url"] for o in out], ["https://app/login", "https://app/api/users"])

    def test_nuclei_marks_candidates(self):
        out = parse_nuclei('{"template-id":"CVE-2021-1","info":{"severity":"high","name":"RCE"},'
                           '"matched-at":"https://app/x"}')
        self.assertEqual(out[0]["type"], "vulnerability_candidate")
        self.assertEqual(out[0]["disposition"], "CANDIDATE")
        self.assertEqual(out[0]["severity"], "high")

    def test_dalfox_marks_candidates(self):
        out = parse_dalfox('[{"type":"V","inject_type":"inHTML","poc":"https://app?q=x","severity":"High","cwe":"CWE-79"}]')
        self.assertEqual(out[0]["type"], "xss_candidate")
        self.assertEqual(out[0]["disposition"], "CANDIDATE")
        self.assertEqual(out[0]["cwe"], "CWE-79")

    def test_ffuf(self):
        out = parse_ffuf('{"results":[{"url":"https://app/admin","status":200,"length":100}]}')
        self.assertEqual(out[0], {"type": "content", "url": "https://app/admin", "status": 200, "length": 100})

    def test_parsers_tolerate_malformed_input(self):
        self.assertEqual(parse_httpx("not json\n{bad}\n"), [])
        self.assertEqual(parse_nuclei(""), [])
        self.assertEqual(parse_ffuf("<html>"), [])


class CatalogHonestyTests(unittest.TestCase):
    def setUp(self):
        self.registry = build_default_catalog()

    def test_catalog_contents_and_profiles(self):
        ids = {t.tool_id for t in self.registry.list()}
        self.assertEqual(ids, {"subfinder", "dnsx", "httpx", "katana", "ffuf", "nuclei", "dalfox"})
        self.assertEqual(self.registry.get("subfinder").execution_profile, PASSIVE)
        self.assertEqual(self.registry.get("nuclei").execution_profile, ACTIVE_CONTROLLED)

    def test_availability_is_honest_not_fabricated(self):
        # Binaries are not bundled; every tool must report its real status, never 'available'.
        for definition in self.registry.list():
            self.assertEqual(definition.status, "adapter_implemented")
            self.assertEqual(definition.binary, definition.tool_id)
        # Deterministic selection cannot select an unavailable tool.
        result = self.registry.select_tools(capability="http_probing",
                                            policy=ProfilePolicy({"execution_enabled": True,
                                                                  "authorization_verified": True}))
        self.assertEqual(result["selected"], [])
        self.assertTrue(any(r["reason"] == "requires_operator_configuration" for r in result["rejected"]))

    def test_arguments_are_injection_safe(self):
        subfinder = self.registry.get("subfinder")
        self.assertEqual(subfinder.spec.build_argv({"domain": "example.com"}),
                         ["subfinder", "-silent", "-d", "example.com"])
        with self.assertRaises(ToolError):      # shell metacharacters fail the parameter pattern
            subfinder.spec.build_argv({"domain": "example.com; rm -rf /"})


class SyntheticEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        root = Path(self.tmp.name)
        db = str(root / "state.sqlite3")
        migrate(db)
        self.store = StateStore(db)
        self.store.create_engagement("eng", "AUTH", {}, {}, status="active")
        self.wm = WorkerManager(self.store, root / "run")
        self.worker = self.wm.provision("eng", "task-1")

    def tearDown(self):
        try:
            self.store.close()
        except Exception:
            pass
        self.tmp.cleanup()

    def test_adapter_runs_through_broker_with_real_parser(self):
        # A synthetic stand-in emits real httpx JSONL; the real parse_httpx handles it.
        program = ("import json; print(json.dumps({'url':'https://api.app.local',"
                   "'status_code':200,'title':'API','tech':['nginx']}))")
        definition = ToolDefinition(
            tool_id="synth-httpx", name="synthetic httpx", category="recon", version="x",
            spec=ToolSpec("synth-httpx", "x", "x", "x", command=(PY, "-c", program),
                          timeout_seconds=15, max_output_bytes=100000),
            capabilities=("http_probing",), execution_profile=SAFE, binary=None,
            parser="httpx", status="lab_tested")
        result = adapter_for(definition).execute(
            self.wm, self.worker, definition, {}, allowed_tools=["synth-httpx"],
            policy=ProfilePolicy({"execution_enabled": True, "authorization_verified": True}))
        self.assertEqual(result.exit_status, 0)
        self.assertEqual(result.observations[0]["type"], "http_service")
        self.assertEqual(result.observations[0]["url"], "https://api.app.local")
        self.assertEqual(result.observations[0]["technologies"], ["nginx"])


if __name__ == "__main__":
    unittest.main()
