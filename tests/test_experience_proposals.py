"""Validated experience feeds the planner as *leads*; it cannot confirm, authorize or import data."""
import sqlite3
import tempfile
import unittest
from pathlib import Path

from core.benchmark.synthetic import bola_request
from core.evidence import EvidenceVault
from core.experience import (ExperienceError, ExperienceRecord, ExperienceStore, PromotionError,
                             PromotionTicket, promote_finding, propose_from_experience)
from core.experience.store import _MINT_KEY
from core.graph import AttackGraph, GraphIngestor
from core.planner import AdaptivePlanner, Hypothesis, HypothesisStore
from core.store import StateStore
from core.validation_engine import ExploitValidationEngine, FindingValidator, ValidationRecordStore
from scripts.migrate import migrate

SCOPE = {"allowed_domains": ["app.local"], "allowed_http_ports": [443], "allowed_applications": [],
         "allowed_ips": [], "allowed_cidrs": [], "excluded_assets": []}
RULES = {"execution_enabled": True, "authorization_verified": True,
         "allowed_test_classes": ["web-authorization-idor"], "prohibited_test_classes": [],
         "human_approval_required_for_state_changes": True}
ORIGIN = "https://app.local:443"
TEMPLATE = "/api/orders/{id}"


class ExperienceBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)
        db = str(self.root / "state.sqlite3")
        migrate(db)
        self.store = StateStore(db)
        for engagement in ("old", "new"):
            self.store.create_engagement(engagement, "AUTH", SCOPE, RULES, status="active")
        self.vault = EvidenceVault(self.store, self.root)
        self.validator = FindingValidator(self.store, self.vault)
        experience_connection = sqlite3.connect(":memory:")
        self.addCleanup(experience_connection.close)           # the store is handed a connection it does not own
        self.experience = ExperienceStore(experience_connection)
        self.old_graph = AttackGraph(self.store.connection, "old")
        self.new_graph = AttackGraph(self.store.connection, "new")

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def validated_finding(self, fid="f-old"):
        """A finding in engagement 'old', confirmed through the verified-evidence chain."""
        endpoint = GraphIngestor(self.old_graph).register_endpoint("GET", ORIGIN, TEMPLATE)
        hypotheses = HypothesisStore(self.store.connection, "old")
        hid = hypotheses.upsert(Hypothesis("old", "idor_bola", "web-authorization-idor", "probe",
                                           target_node_id=endpoint, target_label=TEMPLATE))
        ev = self.vault.capture("old", "http_exchange", fid + "-x.txt", b"synthetic " + fid.encode(), "recon", redacted=True)
        self.store.record_finding({
            "finding_id": fid, "engagement_id": "old", "title": "IDOR", "status": "validation_pending",
            "asset": ORIGIN, "method": "GET", "description": "Vary the object id across identities.",
            "impact": "Cross-tenant read.", "severity": "high", "proposed_by": "recon", "evidence_refs": [ev["evidence_id"]]})
        self.validator.validate_finding(fid, {**bola_request(self.vault, "old", fid), "hypothesis_id": hid}, "validation-agent")
        return fid

    def new_endpoint(self, origin=ORIGIN, path=TEMPLATE, method="GET"):
        return GraphIngestor(self.new_graph).register_endpoint(method, origin, path, trust="observed", provenance="discovery")


class PromotionGateTests(ExperienceBase):
    def test_direct_writes_that_bypass_the_gate_are_refused(self):
        record = ExperienceRecord(vulnerability_category="object_authorization", source_engagement_id="old")
        with self.assertRaises(TypeError):
            self.experience.add(record)                                  # no ticket at all
        with self.assertRaises(ExperienceError):
            PromotionTicket("f", "r", "old")                             # a ticket cannot be minted outside the gate
        with self.assertRaises(ExperienceError):
            self.experience.add(record, ticket=object())
        wrong_engagement = PromotionTicket("f", "r", "someone-else", _key=_MINT_KEY)
        with self.assertRaises(ExperienceError):
            self.experience.add(record, ticket=wrong_engagement)
        self.assertEqual(self.experience.list(status=None), [])

    def test_promotion_records_which_finding_and_validation_it_came_from(self):
        fid = self.validated_finding()
        experience_id = promote_finding(self.experience, self.store, fid)
        record = self.experience.get(experience_id)
        self.assertEqual(record["promotion_finding_id"], fid)
        self.assertTrue(record["promotion_record_id"].startswith("vrec_"))
        self.assertEqual(record["endpoint_characteristics"]["path_template"], TEMPLATE)

    def test_a_validation_that_ran_on_unverified_data_cannot_be_promoted(self):
        ev = self.vault.capture("old", "http_exchange", "legacy.txt", b"x", "recon", redacted=True)
        self.store.record_finding({
            "finding_id": "legacy", "engagement_id": "old", "title": "legacy", "status": "validation_pending",
            "asset": ORIGIN, "description": "validated before the evidence chain existed",
            "proposed_by": "recon", "evidence_refs": [ev["evidence_id"]]})
        offline = ExploitValidationEngine("old", record_store=ValidationRecordStore(self.store.connection, "old"))
        record = offline.validate({
            "vulnerability_class": "object_authorization", "finding_id": "legacy", "owner_identity": "bob",
            "other_identity": "alice", "object_reference": "order-7",
            "owner_response": {"status_code": 200, "response_excerpt": '{"id":1}'},
            "other_response": {"status_code": 200, "response_excerpt": '{"id":1}'}})
        self.store.record_finding_review("legacy", "validation-agent", {
            "decision": "eligible_for_independent_validation", "supported_claims": [record.record_id],
            "refuted_claims": [], "inconclusive_claims": []}, record.to_dict())
        self.store.transition_finding("legacy", "validated", "validation-agent", validation_notes="historic")
        with self.assertRaisesRegex(PromotionError, "vault-verified"):
            promote_finding(self.experience, self.store, "legacy")


class ProposalTests(ExperienceBase):
    def setUp(self):
        super().setUp()
        self.experience_id = promote_finding(self.experience, self.store, self.validated_finding())

    def test_a_matching_endpoint_in_another_engagement_gets_a_lead_that_is_not_evidence(self):
        self.new_endpoint()
        (proposal,) = propose_from_experience(self.experience, self.new_graph, "new")
        self.assertEqual(proposal["category"], "idor_bola")
        self.assertEqual(proposal["supporting_evidence"], [])            # a lead carries no evidence
        self.assertLessEqual(proposal["confidence"], 0.3)
        self.assertIn(self.experience_id, proposal["proposed_test"])     # provenance is visible
        self.assertFalse(proposal["state_changing"])

    def test_nothing_from_the_source_engagement_is_imported(self):
        self.new_endpoint()
        (proposal,) = propose_from_experience(self.experience, self.new_graph, "new")
        flat = repr(proposal)
        for leaked in ("f-old", "old", "vrec_", "evidence_"):
            self.assertNotIn(leaked, flat.replace("previous engagement", ""), leaked)

    def test_leads_never_create_authorization_or_identities(self):
        self.new_endpoint()
        before = (self.new_graph.counts(), len(self.new_graph.edges("CAN_ACCESS")), len(self.new_graph.nodes("identity")))
        planner = AdaptivePlanner(self.store, "new", self.new_graph)
        planner.add_proposals(propose_from_experience(self.experience, self.new_graph, "new"), source="experience")
        planner.run()
        after = (self.new_graph.counts()["nodes"] - len(self.new_graph.nodes("hypothesis")),
                 len(self.new_graph.edges("CAN_ACCESS")), len(self.new_graph.nodes("identity")))
        self.assertEqual((before[0]["nodes"], before[1], before[2]), after)

    def test_a_lead_is_subject_to_the_same_policy_as_any_other_hypothesis(self):
        self.new_endpoint(origin="https://evil.example:443")             # not in this engagement's scope
        planner = AdaptivePlanner(self.store, "new", self.new_graph)
        planner.add_proposals(propose_from_experience(self.experience, self.new_graph, "new"), source="experience")
        planner.run()
        (row,) = planner.hyp.list()
        self.assertEqual((row["status"], row["status_reason"]), ("BLOCKED", "target_out_of_scope"))

    def test_a_lead_cannot_confirm_anything_without_an_executor(self):
        self.new_endpoint()
        planner = AdaptivePlanner(self.store, "new", self.new_graph)
        planner.add_proposals(propose_from_experience(self.experience, self.new_graph, "new"), source="experience")
        report = planner.run()
        self.assertEqual(report["supported"], [])
        self.assertEqual(report["stop_reason"], "plan_only")

    def test_unrelated_deprecated_and_same_engagement_experience_yields_no_lead(self):
        self.new_endpoint(path="/api/invoices/{id}")                      # different route shape
        self.assertEqual(propose_from_experience(self.experience, self.new_graph, "new"), [])
        self.new_endpoint()
        self.assertEqual(propose_from_experience(self.experience, self.new_graph, "old"), [])   # its own engagement
        self.experience.deprecate(self.experience_id, "superseded")
        self.assertEqual(propose_from_experience(self.experience, self.new_graph, "new"), [])

    def test_state_changing_endpoints_are_never_proposed_from_experience(self):
        self.new_endpoint(method="POST")
        self.assertEqual(propose_from_experience(self.experience, self.new_graph, "new"), [])


if __name__ == "__main__":
    unittest.main()
