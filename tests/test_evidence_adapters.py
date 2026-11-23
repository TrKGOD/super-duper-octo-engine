import base64
import json
import tempfile
import unittest
from pathlib import Path

from core.evidence import EvidenceVault
from core.evidence_adapters import import_sarif, import_zap_json, import_burp_xml, EvidenceAdapterError
from core.finding_validation import review_finding, FindingReviewError
from core.store import StateStore
from scripts.migrate import migrate


class EvidenceAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=Path(self.tmp.name)
        self.db=str(self.root/"state.sqlite")
        migrate(self.db)
        self.store=StateStore(self.db)
        self.store.create_engagement("eng-adapter","AUTH-SYNTHETIC",
            {"allowed_domains":["app.example.test"]},{"execution_enabled":False})
        self.vault=EvidenceVault(self.store,self.root)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_sarif_import_captures_source_excerpt_and_code_flow(self):
        sarif={"runs":[{"tool":{"driver":{"rules":[{"id":"CWE-89","shortDescription":{"text":"SQL injection"}}]}},
            "results":[{"ruleId":"CWE-89","level":"error","message":{"text":"Untrusted input reaches query"},
                "locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/query.py"},
                    "region":{"startLine":12,"snippet":{"text":"cursor.execute(query)"}}}}],
                "codeFlows":[{"threadFlows":[{"locations":[{"location":{"message":{"text":"source"}}}]}]}]}]}]}
        with self.assertRaises(EvidenceAdapterError):
            import_sarif(self.vault,"eng-adapter",sarif,"operator",False)
        results=import_sarif(self.vault,"eng-adapter",sarif,"operator",True)
        self.assertEqual(len(results),1)
        types={row["evidence_type"] for row in self.store.connection.execute(
            "SELECT evidence_type FROM evidence WHERE engagement_id='eng-adapter'")}
        self.assertEqual(types,{"source_excerpt","call_graph"})
        self.assertEqual(results[0]["status"],"hypothesis")
        self.assertTrue(all(self.vault.verify(ref)["valid"] for ref in results[0]["evidence_refs"]))

    def test_zap_import_captures_request_response_pair(self):
        doc={"site":[{"@name":"https://app.example.test","alerts":[{"name":"BOLA candidate",
            "riskdesc":"High","desc":"Synthetic alert","instances":[{"uri":"https://app.example.test/api/item/1",
            "request":"GET /api/item/1","response":"HTTP/1.1 200 OK"}]}]}]}
        result=import_zap_json(self.vault,"eng-adapter",doc,"operator",True)
        self.assertEqual(len(result),1)
        rows=self.store.connection.execute("SELECT evidence_type FROM evidence").fetchall()
        self.assertEqual({r["evidence_type"] for r in rows},{"http_request","http_response"})

    def test_burp_xml_import_decodes_http_messages(self):
        request=base64.b64encode(b"GET / HTTP/1.1").decode()
        response=base64.b64encode(b"HTTP/1.1 200 OK").decode()
        xml=f"<issues><issue><name>Example</name><host>https://app.example.test</host><path>/</path><severity>High</severity><http-messages><item><request>{request}</request><response>{response}</response></item></http-messages></issue></issues>"
        result=import_burp_xml(self.vault,"eng-adapter",xml.encode(),"operator",True)
        self.assertEqual(len(result),1)
        rows=self.store.connection.execute("SELECT evidence_type FROM evidence").fetchall()
        self.assertEqual({r["evidence_type"] for r in rows},{"http_request","http_response"})

    def test_adversarial_review_is_required_before_validation(self):
        req=self.vault.capture("eng-adapter","http_request","req.txt",b"GET /item/1","operator",True)
        res=self.vault.capture("eng-adapter","http_response","res.txt",b"HTTP/1.1 200 OK","operator",True)
        refs=[req["evidence_id"],res["evidence_id"]]
        self.store.record_finding({"finding_id":"F-REVIEW","engagement_id":"eng-adapter",
            "title":"Synthetic access control candidate","status":"hypothesis","asset":"app.example.test",
            "description":"Synthetic behavior","evidence_refs":refs,"proposed_by":"vulnerability-agent"})
        self.store.transition_finding("F-REVIEW","validation_pending","operator")
        with self.assertRaisesRegex(ValueError,"adversarial review"):
            self.store.transition_finding("F-REVIEW","validated","validation-agent")
        contract={"vulnerability_class":"generic","claims":[{"claim_id":"c1",
            "assertion":"The response is accessible to the test identity","supporting_refs":refs}]}
        decision=review_finding(self.store,self.vault,"F-REVIEW",{"reviewer":"validation-agent",
            "evidence_contract":contract,"claim_results":[{"claim_id":"c1","disposition":"supported",
            "rationale":"The captured paired exchange supports the claim."}]})
        self.assertEqual(decision["decision"],"eligible_for_independent_validation")
        status=self.store.connection.execute("SELECT status,validated_by FROM findings WHERE finding_id='F-REVIEW'").fetchone()
        self.assertEqual(status["status"],"validated")
        self.assertEqual(status["validated_by"],"validation-agent")

    def test_refuted_claim_is_rejected_and_cannot_be_reported(self):
        req=self.vault.capture("eng-adapter","http_request","req2.txt",b"GET /public","operator",True)
        res=self.vault.capture("eng-adapter","http_response","res2.txt",b"HTTP/1.1 200 OK","operator",True)
        refs=[req["evidence_id"],res["evidence_id"]]
        self.store.record_finding({"finding_id":"F-REFUTED","engagement_id":"eng-adapter",
            "title":"False positive candidate","status":"hypothesis","asset":"app.example.test",
            "description":"Synthetic behavior","evidence_refs":refs,"proposed_by":"vulnerability-agent"})
        self.store.transition_finding("F-REFUTED","validation_pending","operator")
        contract={"vulnerability_class":"generic","claims":[{"claim_id":"c1","assertion":"Endpoint requires auth",
            "supporting_refs":refs}]}
        decision=review_finding(self.store,self.vault,"F-REFUTED",{"reviewer":"validation-agent",
            "evidence_contract":contract,"claim_results":[{"claim_id":"c1","disposition":"refuted",
            "rationale":"The documented endpoint is intentionally public and no security boundary is crossed."}]})
        self.assertEqual(decision["decision"],"rejected")
        with self.assertRaises(ValueError):
            self.store.transition_finding("F-REFUTED","reported","reporting-agent")


if __name__=="__main__":
    unittest.main()
