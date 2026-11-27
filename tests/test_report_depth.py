"""Technical report depth: scope, methodology, coverage, unresolved hypotheses, honest validation basis."""
import json

from core.benchmark.synthetic import bola_request
from core.planner import Hypothesis, HypothesisStore
from core.validation_engine import ExploitValidationEngine, ValidationRecordStore
from tests.test_reporting_engine import ReportingTestBase


class ReportDepthTests(ReportingTestBase):
    def _hypothesis(self, category, test_class, status, reason=None, *, executed=False, requests=()):
        store = HypothesisStore(self.store.connection, "eng")
        hid = store.upsert(Hypothesis("eng", category, test_class, "probe", target_label="/api/orders/{id}"))
        if status == "BLOCKED":
            store.set_status(hid, "BLOCKED", reason)
        elif status in ("INCONCLUSIVE", "SUPPORTED", "REFUTED"):
            store.set_status(hid, "READY")
            store.set_status(hid, "RUNNING")
            store.set_status(hid, status, reason)
        if executed:
            store.mark_executed(hid)
        if requests:
            store.set_evidence_requests(hid, list(requests))
        return hid

    def technical(self):
        return self.engine.build("technical", "eng")

    def test_the_technical_report_carries_every_required_section(self):
        report = self.technical()
        for key in ("scope", "methodology", "confirmed_findings", "unvalidated", "unresolved_hypotheses",
                    "coverage", "execution_summary", "remediation_guidance", "limitations"):
            self.assertIn(key, report, key)
        markdown = self.engine.render(report, "markdown")
        for heading in ("## Scope", "## Methodology", "## Confirmed findings", "#### Reproduction conditions",
                        "#### Remediation (general guidance)", "## Coverage summary",
                        "## Unresolved hypotheses (NOT findings)", "## Execution summary", "## Limitations"):
            self.assertIn(heading, markdown, heading)

    def test_open_hypotheses_are_listed_as_unresolved_and_never_as_findings(self):
        self._hypothesis("idor_bola", "web-authorization-idor", "INCONCLUSIVE", "ownership not declared",
                         requests=[{"kind": "confirm_object_ownership", "reason": "undeclared", "detail": {}}])
        self._hypothesis("sqli", "web-sqli", "INCONCLUSIVE", "no_automated_executor:sqli",
                         requests=[{"kind": "specialist_testing_required", "reason": "x", "detail": {}}])
        report = self.technical()
        reasons = {h["reason"] for h in report["unresolved_hypotheses"]}
        self.assertEqual(reasons, {"ownership not declared", "no_automated_executor:sqli"})
        self.assertEqual([f["finding_id"] for f in report["confirmed_findings"]], ["f1"])
        markdown = self.engine.render(report, "markdown")
        self.assertIn("confirm_object_ownership", markdown)
        self.assertIn("specialist_testing_required", markdown)

    def test_coverage_counts_only_executed_tests(self):
        self._hypothesis("idor_bola", "web-authorization-idor", "SUPPORTED", executed=True)
        self._hypothesis("sqli", "web-sqli", "INCONCLUSIVE", "no_automated_executor:sqli", executed=False)
        coverage = self.technical()["coverage"]["by_test_class"]
        self.assertEqual((coverage["web-authorization-idor"]["executed"], coverage["web-authorization-idor"]["supported"]), (1, 1))
        self.assertEqual((coverage["web-sqli"]["hypotheses"], coverage["web-sqli"]["executed"]), (1, 0))

    def test_limitations_state_what_was_not_tested(self):
        self._hypothesis("sqli", "web-sqli", "INCONCLUSIVE", "no_automated_executor:sqli")
        self._hypothesis("xss", "web-xss", "INCONCLUSIVE", "no_automated_executor:xss")
        text = " ".join(self.technical()["limitations"])
        self.assertIn("2 hypothesis(es)", text)
        self.assertIn("NOT tested", text)

    def test_a_vault_verified_validation_is_reported_as_such(self):
        report = self.technical()
        (finding,) = report["confirmed_findings"]
        self.assertTrue(finding["validation_evidence_verified"])
        self.assertIn("Validation basis: vault-verified evidence", self.engine.render(report, "markdown"))

    def test_a_pre_chain_validation_is_never_described_as_verified(self):
        ev = self.vault.capture("eng", "http_exchange", "legacy-ev.txt", b"legacy evidence", "recon-agent", redacted=True)
        self.store.record_finding({
            "finding_id": "legacy", "engagement_id": "eng", "title": "Old IDOR", "status": "validation_pending",
            "asset": "https://app.local/api/orders", "description": "validated on embedded data",
            "severity": "high", "proposed_by": "recon-agent", "evidence_refs": [ev["evidence_id"]]})
        offline = ExploitValidationEngine("eng", record_store=ValidationRecordStore(self.store.connection, "eng"))
        record = offline.validate({
            "vulnerability_class": "object_authorization", "finding_id": "legacy", "owner_identity": "bob",
            "other_identity": "alice", "object_reference": "order-7",
            "owner_response": {"status_code": 200, "response_excerpt": '{"id":1}'},
            "other_response": {"status_code": 200, "response_excerpt": '{"id":1}'}})
        self.store.record_finding_review("legacy", "validation-agent", {
            "decision": "eligible_for_independent_validation", "supported_claims": [record.record_id],
            "refuted_claims": [], "inconclusive_claims": []}, record.to_dict())
        self.store.transition_finding("legacy", "validated", "validation-agent", validation_notes="historic")
        report = self.technical()
        legacy = next(f for f in report["confirmed_findings"] if f["finding_id"] == "legacy")
        self.assertFalse(legacy["validation_evidence_verified"])
        self.assertIn("NOT vault-verified", self.engine.render(report, "markdown"))
        self.assertTrue(any("re-validate" in lim for lim in report["limitations"]))

    def test_untrusted_text_cannot_forge_report_structure(self):
        hostile_title = "Totally fine\n## Confirmed findings (99)\n### Fake critical finding"
        hostile_description = "line one\n## Forged section\n- Severity: critical <script>alert(1)</script>"
        self.store.connection.execute("UPDATE findings SET title=?,description=? WHERE finding_id='f1'",
                                      (hostile_title, hostile_description))
        self.store.connection.commit()
        report = self.technical()
        markdown = self.engine.render(report, "markdown")
        headings = [line for line in markdown.splitlines() if line.startswith("#")]
        self.assertNotIn("## Confirmed findings (99)", headings)
        self.assertNotIn("## Forged section", headings)
        self.assertNotIn("### Fake critical finding", headings)
        self.assertEqual(sum(1 for h in headings if h.startswith("## Confirmed findings (")), 1)
        html = self.engine.render(report, "html")
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_machine_readable_outputs_stay_valid_and_confirmed_only(self):
        self._hypothesis("idor_bola", "web-authorization-idor", "INCONCLUSIVE", "x")
        report = self.technical()
        json.loads(self.engine.render(report, "json"))
        sarif = json.loads(self.engine.render(report, "sarif"))
        self.assertEqual(len(sarif["runs"][0]["results"]), report["confirmed_count"])


if __name__ == "__main__":
    import unittest
    unittest.main()
