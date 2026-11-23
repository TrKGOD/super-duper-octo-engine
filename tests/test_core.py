import sqlite3
import tempfile
import unittest
from pathlib import Path
from core.store import StateStore
from core.validation import FindingValidationError, validate_finding
from scripts.migrate import migrate


def finding(**overrides):
    data = {"finding_id":"f-001","engagement_id":"eng-001","title":"Example finding","status":"validated","asset":"https://app.example.test","description":"Synthetic lab evidence.","evidence_refs":["evidence://lab/001"],"proposed_by":"vulnerability-agent","validated_by":"validation-agent","validation_notes":"Independently reproduced in the lab."}
    data.update(overrides)
    return data

class CoreTests(unittest.TestCase):
    def test_self_validation_is_rejected(self):
        with self.assertRaises(FindingValidationError): validate_finding(finding(validated_by="vulnerability-agent"))
    def test_validated_requires_evidence(self):
        with self.assertRaises(FindingValidationError): validate_finding(finding(evidence_refs=[]))
    def test_rejected_requires_reason(self):
        with self.assertRaises(FindingValidationError): validate_finding(finding(status="rejected",validated_by=None,validation_notes=None))
    def test_store_persists_and_audits_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "state.sqlite")
            migrate(db)
            with StateStore(db) as store:
                store.create_engagement("eng-001","AUTH-LOCAL-001",{"assets":[]},{"execution_enabled":False})
                task = store.create_task("eng-001","recon-agent",{"mode":"passive"})
                store.update_task(task,"running")
                store.update_task(task,"completed",{"summary":"done"})
                run = store.start_agent_run("eng-001","recon-agent","test-model")
                store.finish_agent_run(run,"completed",10,20,0.001)
                store.record_finding(finding())
                events = store.audit_events("eng-001")
                self.assertGreaterEqual(len(events),7)
                self.assertEqual(events[-1]["event_type"],"finding.recorded")
    def test_migrations_are_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "state.sqlite")
            self.assertTrue(migrate(db))
            self.assertEqual(migrate(db),[])
            con = sqlite3.connect(db)
            cols = {r[1] for r in con.execute("PRAGMA table_info(findings)")}
            self.assertIn("preconditions_json",cols)
            con.close()

if __name__ == "__main__": unittest.main()
