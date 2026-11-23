import sqlite3
import tempfile
import unittest
from pathlib import Path

from core.store import StateStore
from core.validation import FindingValidationError, validate_finding, validate_finding_transition
from scripts.migrate import migrate


def finding(**overrides):
    data = {
        "finding_id": "f-001",
        "engagement_id": "eng-001",
        "title": "Example finding",
        "status": "validated",
        "asset": "https://app.example.test",
        "description": "Synthetic lab evidence.",
        "evidence_refs": [],
        "proposed_by": "vulnerability-agent",
        "validated_by": "validation-agent",
        "validation_notes": "Independently reproduced in the lab.",
    }
    data.update(overrides)
    return data


class CoreTests(unittest.TestCase):
    def test_self_validation_is_rejected(self):
        with self.assertRaises(FindingValidationError):
            validate_finding(finding(validated_by="vulnerability-agent"))

    def test_validated_requires_evidence(self):
        with self.assertRaises(FindingValidationError):
            validate_finding(finding(evidence_refs=[]))

    def test_rejected_requires_reason(self):
        with self.assertRaises(FindingValidationError):
            validate_finding(finding(status="rejected", validated_by=None, validation_notes=None))

    def test_finding_lifecycle_requires_independent_validator(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "state.sqlite")
            migrate(db)
            with StateStore(db) as store:
                store.create_engagement("eng-001", "AUTH-LOCAL-001", {"assets": []}, {"execution_enabled": False})
                evidence = store.record_evidence(
                    "eng-001", "reproduction_notes", ".local/evidence/f-001.txt", "operator"
                )
                store.record_finding(finding(status="observation"))
                self.assertEqual(store.transition_finding("f-001", "hypothesis", "vulnerability-agent"), "hypothesis")
                self.assertEqual(store.transition_finding("f-001", "validation_pending", "vulnerability-agent"), "validation_pending")
                with self.assertRaises(FindingValidationError):
                    store.transition_finding("f-001", "validated", "vulnerability-agent", evidence_refs=[evidence])
                self.assertEqual(
                    store.transition_finding(
                        "f-001", "validated", "validation-agent",
                        validation_notes="Independent lab reproduction.", evidence_refs=[evidence],
                    ),
                    "validated",
                )
                self.assertEqual(store.transition_finding("f-001", "reported", "reporting-agent"), "reported")
                with self.assertRaises(FindingValidationError):
                    store.transition_finding("f-001", "observation", "operator")
                events = [event for event in store.audit_events("eng-001") if event["event_type"] == "finding.status_changed"]
                self.assertEqual([event["details"]["to"] for event in events], [
                    "hypothesis", "validation_pending", "validated", "reported"
                ])

    def test_finding_transition_matrix_rejects_skips(self):
        with self.assertRaises(FindingValidationError):
            validate_finding_transition("observation", "validated")
        with self.assertRaises(FindingValidationError):
            validate_finding_transition("rejected", "hypothesis")

    def test_store_persists_and_audits_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "state.sqlite")
            migrate(db)
            with StateStore(db) as store:
                store.create_engagement("eng-001", "AUTH-LOCAL-001", {"assets": []}, {"execution_enabled": False})
                evidence = store.record_evidence(
                    "eng-001", "reproduction_notes", ".local/evidence/f-001.txt", "operator"
                )
                task = store.create_task("eng-001", "recon-agent", {"mode": "passive"})
                store.update_task(task, "running")
                store.update_task(task, "completed", {"summary": "done"})
                run = store.start_agent_run("eng-001", "recon-agent", "test-model")
                store.finish_agent_run(run, "completed", 10, 20, 0.001)
                store.record_finding(finding(evidence_refs=[evidence]))
                events = store.audit_events("eng-001")
                self.assertGreaterEqual(len(events), 8)
                self.assertEqual(events[-1]["event_type"], "finding.recorded")
                row = store.connection.execute(
                    "SELECT validation_notes FROM findings WHERE finding_id='f-001'"
                ).fetchone()
                self.assertIn("Independently", row["validation_notes"])
                self.assertEqual(store.finding_evidence("f-001")[0]["evidence_id"], evidence)

    def test_evidence_references_must_exist_and_match_engagement(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "state.sqlite")
            migrate(db)
            with StateStore(db) as store:
                store.create_engagement("eng-001", "AUTH-LOCAL-001", {"assets": []}, {"execution_enabled": False})
                store.create_engagement("eng-002", "AUTH-LOCAL-002", {"assets": []}, {"execution_enabled": False})
                with self.assertRaises(FindingValidationError):
                    store.record_finding(finding(evidence_refs=["evidence://not-in-database"]))
                evidence = store.record_evidence(
                    "eng-002", "screenshot", ".local/evidence/other.png", "operator"
                )
                with self.assertRaises(FindingValidationError):
                    store.record_finding(finding(evidence_refs=[evidence]))

    def test_evidence_paths_and_hashes_are_validated(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "state.sqlite")
            migrate(db)
            with StateStore(db) as store:
                store.create_engagement("eng-001", "AUTH-LOCAL-001", {"assets": []}, {"execution_enabled": False})
                with self.assertRaises(ValueError):
                    store.record_evidence("eng-001", "screenshot", "../../secret.png", "operator")
                with self.assertRaises(ValueError):
                    store.record_evidence(
                        "eng-001", "screenshot", ".local/evidence/x.png", "operator", sha256="not-a-hash"
                    )

    def test_only_one_running_agent_run_per_task(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "state.sqlite")
            migrate(db)
            with StateStore(db) as store:
                store.create_engagement("eng-001", "AUTH-LOCAL-001", {"assets": []}, {"execution_enabled": False})
                task = store.create_task("eng-001", "recon-agent", {"task_key": "recon"})
                store.update_task(task, "running")
                store.start_agent_run("eng-001", "recon-agent", "test-model", task_id=task)
                with self.assertRaises(sqlite3.IntegrityError):
                    store.start_agent_run("eng-001", "recon-agent", "test-model", task_id=task)

    def test_evidence_database_trigger_prevents_cross_engagement_link(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "state.sqlite")
            migrate(db)
            with StateStore(db) as store:
                store.create_engagement("eng-001", "AUTH-LOCAL-001", {"assets": []}, {"execution_enabled": False})
                store.create_engagement("eng-002", "AUTH-LOCAL-002", {"assets": []}, {"execution_enabled": False})
                store.record_finding(finding(
                    finding_id="f-002", engagement_id="eng-002", status="observation",
                    validated_by=None, validation_notes=None, evidence_refs=[],
                ))
                evidence = store.record_evidence(
                    "eng-001", "screenshot", ".local/evidence/foreign.png", "operator"
                )
                with self.assertRaises(sqlite3.IntegrityError):
                    store.connection.execute(
                        "UPDATE evidence SET finding_id='f-002' WHERE evidence_id=?", (evidence,)
                    )

    def test_migrations_are_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "state.sqlite")
            self.assertTrue(migrate(db))
            self.assertEqual(migrate(db), [])
            con = sqlite3.connect(db)
            columns = {row[1] for row in con.execute("PRAGMA table_info(findings)")}
            self.assertIn("preconditions_json", columns)
            self.assertIn("validation_notes", columns)
            con.close()


if __name__ == "__main__":
    unittest.main()
