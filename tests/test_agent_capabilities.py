import unittest
from core.evidence_contracts import validate_evidence_contract, EvidenceContractError
from core.adversarial_validation import build_challenge, evaluate_review, AdversarialReviewError
from core.subsystem_coverage import summarize_coverage, CoverageError
from core.design_intent import assess_design_intent, DesignIntentError
from core.model_router import select_model, ModelRoutingError

class AgentCapabilityTests(unittest.TestCase):
 def test_evidence_contract_requires_verified_support_and_reports_class_gaps(self):
  contract={"vulnerability_class":"sqli","claims":[{"claim_id":"q1","assertion":"Input reaches query construction","supporting_refs":["e1"],"refuting_refs":[]}]}
  result=validate_evidence_contract(contract,[{"evidence_id":"e1","evidence_type":"http_response"}],{"e1":True})
  self.assertFalse(result["ready_for_independent_review"])
  self.assertIn("http_request",result["missing_artifact_types"])
  with self.assertRaises(EvidenceContractError):
   validate_evidence_contract(contract,[{"evidence_id":"e1"}],{"e1":False})

 def test_adversarial_review_requires_distinct_reviewer_and_all_claims(self):
  finding={"finding_id":"F1","proposed_by":"vulnerability-agent","evidence_contract":{"claims":[{"claim_id":"c1","assertion":"A","supporting_refs":["e1"]}]}}
  self.assertEqual(build_challenge(finding)["claims"][0]["claim_id"],"c1")
  with self.assertRaises(AdversarialReviewError):
   evaluate_review(finding,{"reviewer":"vulnerability-agent","claim_results":[]})
  result=evaluate_review(finding,{"reviewer":"validation-agent","claim_results":[{"claim_id":"c1","disposition":"inconclusive","rationale":"No server-side evidence"}]})
  self.assertEqual(result["decision"],"needs_more_evidence")

 def test_subsystem_coverage_counts_not_applicable_separately(self):
  result=summarize_coverage([{"subsystem_id":"upload","name":"Upload","status":"assessed"},{"subsystem_id":"billing","name":"Billing","status":"not_assessed"},{"subsystem_id":"admin","name":"Admin","status":"not_applicable"}])
  self.assertEqual(result["coverage_percent"],50.0)
  self.assertEqual(result["unassessed"],["billing"])
  with self.assertRaises(CoverageError):
   summarize_coverage([])

 def test_design_intent_is_operator_attributed_and_never_suppresses(self):
  registry=[{"asset":"app.test","feature_key":"public-profile","expected_behavior":"Profiles are public","approved_by":"operator","source_ref":"policy://profiles"}]
  result=assess_design_intent({"asset":"app.test","feature_key":"public-profile"},registry)
  self.assertFalse(result["suppress"])
  self.assertEqual(result["classification"],"design_review_required")
  with self.assertRaises(DesignIntentError):
   assess_design_intent({},[{"asset":"app.test","feature_key":"x"}])

 def test_model_router_escalates_once_only_on_configured_trigger(self):
  policy={"default_model":"economy-v1","escalation_model":"strong-v1","escalate_on":["invalid_output"],"max_escalations":1}
  self.assertEqual(select_model({}, "cli-default",policy)["model"],"economy-v1")
  self.assertEqual(select_model({}, "cli-default",policy,attempt=1,trigger="invalid_output")["model"],"strong-v1")
  self.assertEqual(select_model({}, "cli-default",policy,attempt=1,trigger="timeout")["model"],"economy-v1")
  self.assertEqual(select_model({}, "cli-default",policy,attempt=0,trigger="high_complexity")["model"],"economy-v1")
  high_policy={**policy,"escalate_on":["high_complexity"]}
  self.assertEqual(select_model({}, "cli-default",high_policy,attempt=0,trigger="high_complexity")["model"],"strong-v1")
  with self.assertRaises(ModelRoutingError):
   select_model({}, "cli-default",{"max_escalations":2})

if __name__ == "__main__":
 unittest.main()
