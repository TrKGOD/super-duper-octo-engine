"""Reporting engine (Component G) tests.

Verifies that only confirmed (validated, integrity-verified) findings appear in confirmed
sections while candidates/unvalidated material stays separate, that evidence integrity is
re-verified at report time (tampered evidence is excluded), that all output formats render,
and that Nessus import normalizes into hypotheses (never validated).
"""
import json
import sqlite3
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from scripts.migrate import migrate
from core.store import StateStore
from core.evidence import EvidenceVault
from core.benchmark.synthetic import bola_request
from core.validation_engine import FindingValidator
from core.graph import AttackGraph
from core.tools.observations import Observation, ObservationStore
from core.reporting import ReportingEngine, ReportingError
from core.evidence_adapters import import_nessus

class ReportingTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)
        db = str(self.root / "state.sqlite3")
        migrate(db)
        self.store = StateStore(db)
        self.store.create_engagement("eng", "AUTH", {"allowed_domains": ["app.local"]}, {}, status="active")
        self.vault = EvidenceVault(self.store, self.root)
        self.validator = FindingValidator(self.store, self.vault)
        self.engine = ReportingEngine(self.store, self.root)
        self.ev = self._validated_finding()
        self._seed_surface_and_candidate()

    def tearDown(self):
        try:
            self.store.close()
        except Exception:
            pass
        self.tmp.cleanup()

    def _validated_finding(self, fid="f1"):
        ev = self.vault.capture("eng", "http_exchange", fid + "-ev.txt", b"GET /api/orders/7 synthetic",
                                "recon-agent", redacted=True)
        self.store.record_finding({
            "finding_id": fid, "engagement_id": "eng", "title": "IDOR on orders", "status": "validation_pending",
            "asset": "https://app.local/api/orders", "method": "GET", "parameter": "id",
            "description": "Cross-identity object access.", "impact": "Tenant data exposure.",
            "severity": "high", "proposed_by": "recon-agent", "evidence_refs": [ev["evidence_id"]]})
        self.validator.validate_finding(fid, bola_request(self.vault, "eng", fid), "validation-agent")
        return ev

    def _seed_surface_and_candidate(self):
        graph = AttackGraph(self.store.connection, "eng")
        graph.upsert_node("host", "app.local", trust="observed")
        graph.upsert_node("route", "https://app.local/login", trust="observed")
        ObservationStore(self.store.connection, "eng").add(Observation(
            engagement_id="eng", tool_id="nuclei", observation_type="vulnerability_candidate",
            disposition="CANDIDATE", vulnerability_class="cve", severity_candidate="medium",
            target_reference="https://app.local/x"))


class ReportContentTests(ReportingTestBase):
    def test_technical_separates_confirmed_from_candidates(self):
        report = self.engine.build("technical", "eng")
        self.assertEqual(report["confirmed_count"], 1)
        self.assertEqual(report["confirmed_findings"][0]["title"], "IDOR on orders")
        self.assertEqual(report["confirmed_findings"][0]["vulnerability_class"], "object_authorization")
        # The scanner candidate is NOT in the confirmed section.
        self.assertEqual(len(report["unvalidated"]["candidate_observations"]), 1)
        titles = [f["title"] for f in report["confirmed_findings"]]
        self.assertNotIn("nuclei", json.dumps(titles))

    def test_executive_summary(self):
        report = self.engine.build("executive", "eng")
        self.assertEqual(report["confirmed_by_severity"], {"high": 1})
        self.assertEqual(report["remediation_priorities"], ["f1"])

    def test_attack_surface_and_tool_execution(self):
        surface = self.engine.build("attack_surface", "eng")["surface"]
        self.assertEqual([h["key"] for h in surface["hosts"]], ["app.local"])
        self.assertEqual([r["key"] for r in surface["routes"]], ["https://app.local/login"])
        tooling = self.engine.build("tool_execution", "eng")
        self.assertEqual(tooling["candidates_generated"], 1)
        self.assertEqual(tooling["findings_confirmed"], 1)

    def test_evidence_package(self):
        report = self.engine.build("evidence_package", "eng")
        self.assertEqual(report["packages"][0]["finding_id"], "f1")
        self.assertTrue(report["packages"][0]["evidence"])


class IntegrityTests(ReportingTestBase):
    def test_tampered_evidence_is_excluded_from_confirmed(self):
        # Corrupt the stored evidence file; integrity re-check must drop the finding.
        (self.root / self.ev["local_path"]).write_bytes(b"tampered")
        report = self.engine.build("technical", "eng")
        self.assertEqual(report["confirmed_count"], 0)
        self.assertEqual(report["excluded_findings"][0]["finding_id"], "f1")


class RenderingTests(ReportingTestBase):
    def test_all_formats_render(self):
        self.assertIn("IDOR on orders", self.engine.generate("technical", "eng", "markdown"))
        self.assertIn("<html>", self.engine.generate("technical", "eng", "html"))
        self.assertEqual(json.loads(self.engine.generate("technical", "eng", "json"))["confirmed_count"], 1)
        sarif = json.loads(self.engine.generate("technical", "eng", "sarif"))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "object_authorization")

    def test_unknown_type_and_format_raise(self):
        with self.assertRaises(ReportingError):
            self.engine.build("made_up", "eng")
        with self.assertRaises(ReportingError):
            self.engine.render({"report_type": "technical", "engagement": {"engagement_id": "e", "status": "x"}}, "pdf")


class NessusImportTests(ReportingTestBase):
    NESSUS = ('<?xml version="1.0"?><NessusClientData_v2><Report name="r">'
              '<ReportHost name="10.0.0.1"><ReportItem port="443" severity="3" pluginID="12345" '
              'pluginName="TLS Configuration"><description>weak ciphers</description></ReportItem>'
              '</ReportHost></Report></NessusClientData_v2>')

    def test_nessus_imports_as_hypothesis(self):
        imported = import_nessus(self.vault, "eng", self.NESSUS.encode(), "operator", redacted=True)
        self.assertEqual(imported[0]["source"], "nessus")
        self.assertEqual(imported[0]["title"], "TLS Configuration")
        self.assertEqual(imported[0]["severity"], "high")
        self.assertEqual(imported[0]["status"], "hypothesis")        # never validated

    def test_nessus_requires_redaction(self):
        from core.evidence_adapters import EvidenceAdapterError
        with self.assertRaises(EvidenceAdapterError):
            import_nessus(self.vault, "eng", self.NESSUS.encode(), "operator", redacted=False)


if __name__ == "__main__":
    unittest.main()
