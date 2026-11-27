"""Migration audit: ordering, idempotency, additive upgrades that preserve historical data."""
import json
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from core.validation_engine.records import ValidationRecord, ValidationRecordStore, integrity_hash
from scripts.migrate import MIGRATIONS, MigrationError, discover, migrate


class MigrationDiscoveryTests(unittest.TestCase):
    def test_versions_are_contiguous_and_unique_in_the_repository(self):
        versions = sorted(discover())
        self.assertEqual(versions, list(range(versions[0], versions[-1] + 1)))
        self.assertGreaterEqual(versions[-1], 14)

    def test_a_gap_or_duplicate_is_an_error_not_a_silent_skip(self):
        with tempfile.TemporaryDirectory() as d:
            directory = Path(d)
            (directory / "002_a.sql").write_text("SELECT 1;")
            (directory / "004_c.sql").write_text("SELECT 1;")
            with self.assertRaisesRegex(MigrationError, "not contiguous"):
                discover(directory)
            (directory / "003_b.sql").write_text("SELECT 1;")
            (directory / "003_dup.sql").write_text("SELECT 1;")
            with self.assertRaisesRegex(MigrationError, "Duplicate"):
                discover(directory)


class FreshDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "fresh.sqlite3")

    def tearDown(self):
        self.tmp.cleanup()

    def test_fresh_initialisation_is_complete_consistent_and_idempotent(self):
        applied = migrate(self.db)
        self.assertEqual(applied[0], "1: baseline_schema")
        self.assertEqual(len(applied), 1 + len(discover()))
        self.assertEqual(migrate(self.db), [])                       # idempotent
        con = sqlite3.connect(self.db)
        try:
            self.assertEqual(con.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(con.execute("PRAGMA foreign_key_check").fetchall(), [])
            tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            for expected in ("engagements", "evidence", "findings", "executions", "execution_events",
                             "validation_records", "graph_nodes", "planner_hypotheses", "tool_observations"):
                self.assertIn(expected, tables)
        finally:
            con.close()

    def test_every_applied_migration_has_a_checksum(self):
        migrate(self.db)
        con = sqlite3.connect(self.db)
        try:
            missing = con.execute("SELECT version FROM schema_migrations WHERE checksum IS NULL").fetchall()
        finally:
            con.close()
        self.assertEqual(missing, [])

    def test_modifying_an_applied_migration_is_detected(self):
        with tempfile.TemporaryDirectory() as d:
            copy = Path(d) / "migrations"
            shutil.copytree(MIGRATIONS, copy)
            migrate(self.db, directory=copy)
            target = next(copy.glob("013_*.sql"))
            target.write_text(target.read_text(encoding="utf-8") + "\n-- tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(MigrationError, "modified after it was applied"):
                migrate(self.db, directory=copy)

    def test_a_failing_migration_leaves_the_database_untouched(self):
        with tempfile.TemporaryDirectory() as d:
            copy = Path(d) / "migrations"
            shutil.copytree(MIGRATIONS, copy)
            migrate(self.db, directory=copy)
            (copy / "999_bad.sql").write_text(
                "CREATE TABLE half_done (x INTEGER);\nTHIS IS NOT SQL;\n", encoding="utf-8")
            # versions 015..998 are absent -> contiguity error first; give it the next number instead
            (copy / "999_bad.sql").rename(copy / "015_bad.sql")
            with self.assertRaises(sqlite3.DatabaseError):
                migrate(self.db, directory=copy)
            con = sqlite3.connect(self.db)
            try:
                self.assertIsNone(con.execute(
                    "SELECT name FROM sqlite_master WHERE name='half_done'").fetchone())
                self.assertIsNone(con.execute("SELECT 1 FROM schema_migrations WHERE version=15").fetchone())
            finally:
                con.close()


class UpgradeWithHistoricalDataTests(unittest.TestCase):
    """Upgrade a database that already holds an engagement's findings, evidence and history."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "historic.sqlite3")
        migrate(self.db, up_to=13)                                   # the schema before this work
        self.con = sqlite3.connect(self.db)
        self.con.row_factory = sqlite3.Row
        self.con.execute("PRAGMA foreign_keys=ON")
        self._seed()

    def tearDown(self):
        self.con.close()
        self.tmp.cleanup()

    def _seed(self):
        c = self.con
        c.execute("INSERT INTO engagements VALUES('eng-old','AUTH-1','active','{\"allowed_ips\":[\"127.0.0.1\"]}',"
                  "'{\"execution_enabled\":true,\"authorization_verified\":true}','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')")
        c.execute("INSERT INTO tasks(task_id,engagement_id,agent,status,input_json) VALUES('task-old','eng-old','recon-agent','completed','{}')")
        c.execute("INSERT INTO findings(finding_id,engagement_id,title,status,severity,asset,description,evidence_refs_json,"
                  "proposed_by,validated_by,created_at,updated_at) VALUES('f-old','eng-old','Old finding','validated','high',"
                  "'app.test','desc','[\"ev-old\"]','vuln-agent','validation-agent','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')")
        c.execute("INSERT INTO evidence(evidence_id,engagement_id,finding_id,evidence_type,local_path,sha256,redacted,captured_at,captured_by) "
                  "VALUES('ev-old','eng-old','f-old','http_response','.local/evidence/eng-old/a.json','" + "c" * 64 + "',1,'2026-01-01T00:00:00Z','recon-agent')")
        c.execute("INSERT INTO active_request_log(execution_id,engagement_id,task_id,request_id,target_host,method,started_at,outcome,evidence_refs_json) "
                  "VALUES('legacy-exec','eng-old','task-old','req-1','127.0.0.1','GET','2026-01-01T00:00:00Z','completed','[\"ev-old\"]')")
        c.execute("INSERT INTO worker_executions(worker_id,engagement_id,task_id,backend,status,started_at) "
                  "VALUES('wrk-old','eng-old','task-old','subprocess','torn_down','2026-01-01T00:00:00Z')")
        c.execute("INSERT INTO audit_events(engagement_id,actor,event_type,details_json,created_at) "
                  "VALUES('eng-old','operator','engagement.created','{}','2026-01-01T00:00:00Z')")
        # a validation record written by the pre-014 code: its integrity hash covers the old material
        legacy = ValidationRecord(engagement_id="eng-old", vulnerability_class="sqli", oracle="sqli",
                                  disposition="SUPPORTED", explanation="legacy", finding_id="f-old",
                                  request_refs=["ev-old"], created_at="2026-01-01T00:00:00Z")
        ValidationRecordStore(c, "eng-old")
        c.execute(
            "INSERT INTO validation_records(record_id,engagement_id,finding_id,hypothesis_id,vulnerability_class,oracle,"
            "validator_id,validator_version,disposition,explanation,comparison_json,request_refs_json,response_refs_json,"
            "baseline_refs_json,sanitized,integrity_hash,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("vrec-old", "eng-old", "f-old", None, "sqli", "sqli", "exploit-validation-engine", "1.0", "SUPPORTED",
             "legacy", "{}", '["ev-old"]', "[]", "[]", 1, legacy.integrity(), "2026-01-01T00:00:00Z"))
        c.execute("INSERT INTO planner_hypotheses(hypothesis_id,engagement_id,category,test_class,proposed_test,status,created_at,updated_at) "
                  "VALUES('hyp-old','eng-old','sqli','web-sqli','probe','SUPPORTED','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')")
        c.commit()

    def test_upgrade_preserves_every_historical_row(self):
        before = {t: self.con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                  for t in ("engagements", "tasks", "findings", "evidence", "active_request_log",
                            "worker_executions", "audit_events", "validation_records", "planner_hypotheses")}
        self.con.close()
        self.assertEqual(migrate(self.db), ["14: execution_ledger"])
        self.con = sqlite3.connect(self.db)
        self.con.row_factory = sqlite3.Row
        after = {t: self.con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in before}
        self.assertEqual(before, after)
        self.assertEqual(self.con.execute("PRAGMA foreign_key_check").fetchall(), [])
        self.assertEqual(self.con.execute("PRAGMA integrity_check").fetchone()[0], "ok")

    def test_historical_data_is_unchanged_and_new_columns_have_honest_defaults(self):
        self.con.close()
        migrate(self.db)
        self.con = sqlite3.connect(self.db)
        self.con.row_factory = sqlite3.Row
        finding = self.con.execute("SELECT status,validated_by FROM findings WHERE finding_id='f-old'").fetchone()
        self.assertEqual((finding["status"], finding["validated_by"]), ("validated", "validation-agent"))
        evidence = self.con.execute("SELECT sha256,execution_id,task_id,finding_id FROM evidence WHERE evidence_id='ev-old'").fetchone()
        self.assertEqual((evidence["sha256"], evidence["execution_id"], evidence["task_id"], evidence["finding_id"]),
                         ("c" * 64, None, None, "f-old"))
        record = self.con.execute("SELECT evidence_verified,evidence_hashes_json,evidence_requests_json "
                                  "FROM validation_records WHERE record_id='vrec-old'").fetchone()
        # a pre-014 validation was NOT run on vault-verified evidence, and must not claim to be
        self.assertEqual((record["evidence_verified"], record["evidence_hashes_json"], record["evidence_requests_json"]),
                         (0, "[]", "[]"))
        hypothesis = self.con.execute("SELECT status,attempt_fingerprint,last_execution_id FROM planner_hypotheses").fetchone()
        self.assertEqual((hypothesis["status"], hypothesis["attempt_fingerprint"], hypothesis["last_execution_id"]),
                         ("SUPPORTED", None, None))

    def test_a_legacy_validation_record_still_verifies_after_the_upgrade(self):
        self.con.close()
        migrate(self.db)
        self.con = sqlite3.connect(self.db)
        self.con.row_factory = sqlite3.Row
        self.assertTrue(ValidationRecordStore(self.con, "eng-old").verify("vrec-old"),
                        "the upgrade invalidated a historical tamper-evident record")

    def test_the_upgraded_database_accepts_new_ledger_rows_for_the_old_engagement(self):
        self.con.close()
        migrate(self.db)
        from core.execution_ledger import ExecutionLedger
        con = sqlite3.connect(self.db)
        con.row_factory = sqlite3.Row
        try:
            ledger = ExecutionLedger(con)
            execution_id = ledger.create(engagement_id="eng-old", kind="http", tool_id="active-http",
                                         execution_profile="safe", external_ref="legacy-exec")
            self.assertEqual(ledger.get(execution_id)["external_ref"], "legacy-exec")
        finally:
            con.close()


if __name__ == "__main__":
    unittest.main()
