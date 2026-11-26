"""Validated Experience Memory (Component C) tests.

Verifies the promotion gate (only independently validated findings with a SUPPORTED
validation record are promoted — never a hypothesis, refuted or unvalidated finding), that
no secrets are persisted, similarity-based advisory retrieval, cross-engagement provenance,
and the versioning/deprecation lifecycle.
"""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from scripts.migrate import migrate
from core.store import StateStore
from core.evidence import EvidenceVault
from core.validation_engine import FindingValidator
from core.experience import ExperienceStore, PromotionError, promote_finding

OWNER_OK = {"status_code": 200, "response_excerpt": '{"id":1}', "evidence_refs": ["o1"]}
OTHER_SAME = {"status_code": 200, "response_excerpt": '{"id":1}', "evidence_refs": ["o2"]}


def bola_request():
    return {"vulnerability_class": "object_authorization", "owner_response": OWNER_OK,
            "other_response": OTHER_SAME, "owner_identity": "bob", "other_identity": "alice",
            "object_reference": "order-7"}


class ExperienceTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)
        db = str(self.root / "state.sqlite3")
        migrate(db)
        self.store = StateStore(db)
        self.store.create_engagement("eng", "AUTH", {}, {}, status="active")
        self.vault = EvidenceVault(self.store, self.root)
        self.validator = FindingValidator(self.store)
        self.exp = ExperienceStore(sqlite3.connect(":memory:"))

    def tearDown(self):
        try:
            self.store.close()
        except Exception:
            pass
        self.tmp.cleanup()

    def _validated_finding(self, fid="f1", description="Vary the object id to another identity's order."):
        ev = self.vault.capture("eng", "http_exchange", fid + "-ev.txt", b"GET /api/orders/7 synthetic",
                                "recon-agent", redacted=True)
        self.store.record_finding({
            "finding_id": fid, "engagement_id": "eng", "title": "IDOR", "status": "validation_pending",
            "asset": "https://app.local/api/orders", "method": "GET", "parameter": "id",
            "description": description, "impact": "Cross-tenant object read.", "severity": "high",
            "proposed_by": "recon-agent", "evidence_refs": [ev["evidence_id"]]})
        self.validator.validate_finding(fid, bola_request(), "validation-agent")
        return fid


class PromotionGateTests(ExperienceTestBase):
    def test_validated_finding_is_promoted(self):
        fid = self._validated_finding()
        experience_id = promote_finding(self.exp, self.store, fid, technology="REST API")
        record = self.exp.get(experience_id)
        self.assertEqual(record["vulnerability_category"], "object_authorization")
        self.assertEqual(record["source_engagement_id"], "eng")
        self.assertEqual(record["final_disposition"], "validated")
        self.assertEqual(record["technology"], "REST API")

    def test_unvalidated_finding_is_refused(self):
        # A finding still in validation_pending must never be promoted.
        self.vault.capture("eng", "http_exchange", "p-ev.txt", b"x", "recon-agent", redacted=True)
        self.store.record_finding({
            "finding_id": "p1", "engagement_id": "eng", "title": "maybe", "status": "hypothesis",
            "asset": "https://app.local", "description": "unproven", "proposed_by": "recon-agent",
            "evidence_refs": []})
        with self.assertRaises(PromotionError):
            promote_finding(self.exp, self.store, "p1")

    def test_refuted_finding_is_refused(self):
        ev = self.vault.capture("eng", "http_exchange", "r-ev.txt", b"x", "recon-agent", redacted=True)
        self.store.record_finding({
            "finding_id": "r1", "engagement_id": "eng", "title": "idor?", "status": "validation_pending",
            "asset": "https://app.local", "method": "GET", "parameter": "id", "description": "check",
            "proposed_by": "recon-agent", "evidence_refs": [ev["evidence_id"]]})
        # Validate with a denial -> REFUTED -> finding rejected.
        self.validator.validate_finding("r1", {**bola_request(), "other_response": {"status_code": 403}},
                                        "validation-agent")
        with self.assertRaises(PromotionError):
            promote_finding(self.exp, self.store, "r1")

    def test_validated_without_supported_record_is_refused(self):
        ev = self.vault.capture("eng", "http_exchange", "v-ev.txt", b"x", "recon-agent", redacted=True)
        self.store.record_finding({  # directly 'validated' but with no validation record
            "finding_id": "v1", "engagement_id": "eng", "title": "x", "status": "validated",
            "asset": "https://app.local", "description": "d", "proposed_by": "recon-agent",
            "validated_by": "operator", "evidence_refs": [ev["evidence_id"]]})
        with self.assertRaises(PromotionError):
            promote_finding(self.exp, self.store, "v1")


class SanitizationTests(ExperienceTestBase):
    def test_no_secrets_are_persisted(self):
        fid = self._validated_finding(description="Reproduced with Authorization: Bearer leaktoken999 header.")
        experience_id = promote_finding(self.exp, self.store, fid)
        blob = json.dumps(self.exp.get(experience_id))
        self.assertNotIn("leaktoken999", blob)                       # redacted
        # Evidence is referenced by id only; no raw body is copied.
        self.assertTrue(self.exp.get(experience_id)["evidence_reference_ids"])
        self.assertNotIn("GET /api/orders/7 synthetic", blob)


class RetrievalTests(ExperienceTestBase):
    def test_similarity_retrieval_is_advisory(self):
        promote_finding(self.exp, self.store, self._validated_finding("a"), technology="REST API")
        results = self.exp.search(category="object_authorization")
        self.assertTrue(results)
        self.assertIn("advisory", results[0])
        self.assertIn("confers no authorization", results[0]["advisory"])
        self.assertEqual(results[0]["source_engagement_id"], "eng")
        self.assertEqual(self.exp.get(results[0]["experience_id"])["retrieval_count"], 1)

    def test_cross_engagement_reuse_keeps_provenance(self):
        promote_finding(self.exp, self.store, self._validated_finding("a"))
        # Another engagement's query still finds it, labelled with its source engagement.
        results = self.exp.search(query="object authorization order")
        self.assertTrue(results)
        self.assertEqual(results[0]["source_engagement_id"], "eng")


class LifecycleTests(ExperienceTestBase):
    def test_versioning_and_confidence_recalculation(self):
        first = promote_finding(self.exp, self.store, self._validated_finding("a"))
        # A second validation of the same signature supersedes and raises confidence.
        second = promote_finding(self.exp, self.store, self._validated_finding("b"))
        self.assertNotEqual(first, second)
        self.assertEqual(self.exp.get(first)["status"], "deprecated")
        self.assertEqual(self.exp.get(second)["status"], "active")
        self.assertEqual(self.exp.get(second)["version"], 2)
        self.assertGreater(self.exp.get(second)["confidence"], self.exp.get(first)["confidence"])

    def test_deprecate_removes_from_active_search(self):
        experience_id = promote_finding(self.exp, self.store, self._validated_finding("a"))
        self.exp.deprecate(experience_id)
        self.assertEqual(self.exp.search(category="object_authorization"), [])


if __name__ == "__main__":
    unittest.main()
