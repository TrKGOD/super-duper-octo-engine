import tempfile
import unittest
from pathlib import Path

from core.evidence import EvidenceVault
from core.evidence_scoring import score_finding
from core.store import StateStore
from scripts.migrate import migrate
from scripts.render_report import render_report
from core.finding_validation import review_finding


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = str(self.root / "state.sqlite")
        migrate(self.db)
        self.store = StateStore(self.db)
        self.store.create_engagement(
            "eng-report", "AUTH-SYNTHETIC", {"allowed_domains": ["app.example.test"]},
            {"execution_enabled": False},
        )
        self.vault = EvidenceVault(self.store, self.root)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def _validated_finding(self, finding_id, title):
        request = self.vault.capture(
            "eng-report", "http_request", finding_id + "-request.txt",
            b"GET /api/object/1 " + finding_id.encode(), "operator", redacted=True,
        )
        response = self.vault.capture(
            "eng-report", "http_response", finding_id + "-response.txt",
            b"HTTP/1.1 200 OK " + finding_id.encode(), "operator", redacted=True,
        )
        self.store.record_finding({
            "finding_id": finding_id, "engagement_id": "eng-report",
            "title": title, "status": "hypothesis", "severity": "high",
            "asset": "app.example.test", "method": "GET", "parameter": "id",
            "description": "Synthetic finding description",
            "impact": "Synthetic impact", "preconditions": ["Synthetic test account"],
            "evidence_refs": [request["evidence_id"], response["evidence_id"]],
            "proposed_by": "vulnerability-agent",
        })
        self.store.transition_finding(finding_id, "validation_pending", "operator")
        contract={"vulnerability_class":"generic","claims":[{"claim_id":"c1",
            "assertion":"The synthetic access-control behavior is reproducible",
            "supporting_refs":[request["evidence_id"],response["evidence_id"]],
            "alternative_explanations":["The object may be intentionally public"]}]}
        review_finding(self.store,self.vault,finding_id,{"reviewer":"validation-agent",
            "evidence_contract":contract,"claim_results":[{"claim_id":"c1","disposition":"supported",
            "rationale":"Paired request and response artifacts support the stated behavior.","evidence_refs":[request["evidence_id"],response["evidence_id"]]}]})
        return request, response

    def test_report_includes_only_validated_findings_with_integrity(self):
        valid_request, valid_response = self._validated_finding("F-VALID", "Validated synthetic BOLA")
        self.assertTrue(self.vault.verify(valid_request["evidence_id"])["valid"])
        self.assertTrue(self.vault.verify(valid_response["evidence_id"])["valid"])
        tampered_request, _ = self._validated_finding("F-TAMPER", "Tampered synthetic finding")
        (self.root / tampered_request["local_path"]).write_bytes(b"modified")
        report, manifest = render_report(self.store, "eng-report", self.root)
        self.assertIn("Validated synthetic BOLA", report)
        self.assertNotIn("Tampered synthetic finding", report)
        self.assertEqual(manifest["included"], ["F-VALID"])
        self.assertEqual(manifest["excluded"][0]["finding_id"], "F-TAMPER")

    def test_evidence_readiness_score_does_not_change_finding_status(self):
        request, response = self._validated_finding("F-SCORE", "Scored finding")
        evidence = self.store.finding_evidence("F-SCORE")
        integrity = {item["evidence_id"]: True for item in evidence}
        finding = self.store.connection.execute(
            "SELECT * FROM findings WHERE finding_id='F-SCORE'"
        ).fetchone()
        score = score_finding(
            {**dict(finding), "evidence_refs": [request["evidence_id"], response["evidence_id"]]},
            evidence, integrity,
        )
        self.assertEqual(score["label"], "evidence_readiness_only")
        self.assertEqual(score["score"], 75)
        self.assertEqual(finding["status"], "validated")


if __name__ == "__main__":
    unittest.main()
