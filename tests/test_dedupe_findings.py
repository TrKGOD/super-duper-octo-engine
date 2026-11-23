import tempfile
import unittest
from pathlib import Path

from core.store import StateStore
from scripts.dedupe_findings import find_duplicates
from scripts.migrate import migrate


class DuplicateFindingTests(unittest.TestCase):
    def test_reports_possible_duplicates_without_mutating_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "state.sqlite")
            migrate(db)
            with StateStore(db) as store:
                store.create_engagement("eng-dupes", "AUTH", {"assets": []}, {"execution_enabled": False})
                base = {
                    "engagement_id": "eng-dupes", "status": "hypothesis",
                    "severity": "medium", "asset": "app.example.test",
                    "method": "GET", "parameter": "id",
                    "description": "A user can read another user's object.",
                    "evidence_refs": [], "proposed_by": "vulnerability-agent",
                }
                store.record_finding({
                    **base, "finding_id": "F-1",
                    "title": "Broken object authorization in GET /api/object",
                })
                store.record_finding({
                    **base, "finding_id": "F-2",
                    "title": "Broken object authorization in GET /api/object endpoint",
                })
                before = store.connection.execute(
                    "SELECT status FROM findings ORDER BY finding_id"
                ).fetchall()
                matches = find_duplicates(store, "eng-dupes")
                after = store.connection.execute(
                    "SELECT status FROM findings ORDER BY finding_id"
                ).fetchall()
                self.assertEqual(len(matches), 1)
                self.assertTrue(matches[0]["requires_operator_review"])
                self.assertEqual([row["status"] for row in before], [row["status"] for row in after])


if __name__ == "__main__":
    unittest.main()
