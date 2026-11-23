import json
import sqlite3
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class BootstrapTests(unittest.TestCase):
    def test_execution_disabled(self):
        cfg = json.loads((ROOT / "config/engagement.example.json").read_text())
        self.assertFalse(cfg["rules_of_engagement"]["execution_enabled"])

    def test_no_targets_in_example(self):
        cfg = json.loads((ROOT / "config/engagement.example.json").read_text())
        scope = cfg["scope"]
        self.assertEqual(scope["allowed_domains"], [])
        self.assertEqual(scope["allowed_ips"], [])
        self.assertEqual(scope["allowed_cidrs"], [])

    def test_schema_creates(self):
        con = sqlite3.connect(":memory:")
        con.executescript((ROOT / "database/schema.sql").read_text())
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        expected = {"engagements","assets","endpoints","tasks","findings","evidence","agent_runs","audit_events"}
        self.assertTrue(expected.issubset(tables))
        con.close()

    def test_finding_schema_states(self):
        schema = json.loads((ROOT / "templates/finding.schema.json").read_text())
        states = schema["properties"]["status"]["enum"]
        self.assertIn("validated", states)
        self.assertIn("rejected", states)
        self.assertIn("needs_more_evidence", states)

if __name__ == "__main__":
    unittest.main()
