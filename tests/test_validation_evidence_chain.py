"""The validator receives evidence *references* and resolves them itself.

These tests pin the property that closes the "agent validates its own claim" gap: only
vault-verified evidence can confirm, reject or resolve a finding; policy facts come from the
control plane; and an unverifiable request can never degrade a finding that is already confirmed.
"""
import json
import tempfile
import unittest
from pathlib import Path

from core.authorization_testing import response_fingerprint
from core.benchmark.synthetic import (bola_request, capture_http_request, capture_http_response)
from core.evidence import EvidenceVault
from core.graph import AttackGraph, GraphIngestor
from core.protocol_testing import analyze_sqli_pair
from core.store import StateStore
from core.validation_engine import (EvidenceResolutionError, EvidenceResolver, ExploitValidationEngine,
                                    FindingValidator, GraphFacts, INCONCLUSIVE, REFUTED, SUPPORTED,
                                    ValidationError, ValidationRecordStore, build_finding_report)
from scripts.migrate import migrate


class ChainBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)
        self.db = str(self.root / "s.sqlite3")
        migrate(self.db)
        self.store = StateStore(self.db)
        for engagement in ("eng", "other"):
            self.store.create_engagement(engagement, "AUTH", {}, {}, status="active")
        self.vault = EvidenceVault(self.store, self.root)
        self.graph = AttackGraph(self.store.connection, "eng")
        self.ingest = GraphIngestor(self.graph)
        self.records = ValidationRecordStore(self.store.connection, "eng")

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def engine(self, *, with_facts=True):
        return ExploitValidationEngine(
            "eng", record_store=self.records, resolver=EvidenceResolver(self.vault, "eng"),
            facts=GraphFacts(self.graph) if with_facts else None)

    def response(self, name, status=200, body="", headers=None, engagement="eng"):
        return capture_http_response(self.vault, engagement, name, status=status, body=body, headers=headers)

    def callback_log(self, name, events, engagement="eng"):
        """An "other"-typed artifact, exactly as the SSRF orchestration captures a callback log."""
        payload = json.dumps({"events": events}, sort_keys=True).encode()
        stored = self.vault.capture(engagement, "other", name + "-callback.json", payload,
                                    "synthetic-fixture", redacted=True)
        return stored["evidence_id"]

    def finding(self, fid="f1"):
        ev = self.vault.capture("eng", "http_exchange", fid + "-x.txt", b"synthetic " + fid.encode(),
                                "recon-agent", redacted=True)
        self.store.record_finding({
            "finding_id": fid, "engagement_id": "eng", "title": "Possible IDOR", "status": "validation_pending",
            "asset": "https://app.local", "method": "GET", "parameter": "id", "description": "vary id",
            "proposed_by": "recon-agent", "evidence_refs": [ev["evidence_id"]]})
        return fid


class ResolutionTests(ChainBase):
    def test_a_supported_result_records_exactly_which_bytes_it_was_computed_from(self):
        request = bola_request(self.vault, "eng", "chain", other="same")
        record = self.engine().validate(request)
        self.assertEqual(record.disposition, SUPPORTED)
        self.assertTrue(record.evidence_verified)
        roles = {d["role"]: d for d in record.evidence_hashes}
        self.assertEqual(set(roles), {"owner_response", "other_response"})
        for role, descriptor in roles.items():
            stored = self.store.connection.execute(
                "SELECT sha256 FROM evidence WHERE evidence_id=?", (descriptor["evidence_id"],)).fetchone()
            self.assertEqual(descriptor["sha256"], stored["sha256"])
        self.assertTrue(self.records.verify(record.record_id))

    def test_the_recorded_evidence_chain_is_tamper_evident(self):
        record = self.engine().validate(bola_request(self.vault, "eng", "tamper", other="same"))
        self.store.connection.execute(
            "UPDATE validation_records SET evidence_hashes_json='[]' WHERE record_id=?", (record.record_id,))
        self.store.connection.commit()
        self.assertFalse(self.records.verify(record.record_id))

    def test_inline_response_bodies_are_refused_once_evidence_is_resolved_from_the_vault(self):
        request = bola_request(self.vault, "eng", "inline")
        for forged in ({"owner_response": {"status_code": 200, "response_excerpt": "{}"}},
                       {"ownership_confirmed": True}):
            with self.assertRaisesRegex(ValidationError, "Inline"):
                self.engine().validate({**request, **forged})

    def test_unknown_foreign_wrongly_typed_and_missing_references_are_rejected(self):
        good = bola_request(self.vault, "eng", "ref")
        foreign = self.response("foreign", engagement="other")
        request_artifact = capture_http_request(self.vault, "eng", "wrongtype", url="https://app.local/x")
        cases = {
            "unknown id": {**good, "evidence": {**good["evidence"], "other_response": "evidence_nope"}},
            "another engagement's evidence": {**good, "evidence": {**good["evidence"], "other_response": foreign}},
            "wrong evidence type": {**good, "evidence": {**good["evidence"], "other_response": request_artifact}},
            "same artifact for two roles": {**good, "evidence": {"owner_response": good["evidence"]["owner_response"],
                                                                 "other_response": good["evidence"]["owner_response"]}},
            "missing role": {**good, "evidence": {"owner_response": good["evidence"]["owner_response"]}},
            "extra role": {**good, "evidence": {**good["evidence"], "bonus": good["evidence"]["owner_response"]}},
            "no evidence mapping": {k: v for k, v in good.items() if k != "evidence"},
        }
        for label, request in cases.items():
            with self.assertRaises(ValidationError, msg=label):
                self.engine().validate(request)

    def test_evidence_altered_after_capture_fails_integrity_and_cannot_validate(self):
        request = bola_request(self.vault, "eng", "altered", other="same")
        row = self.store.connection.execute(
            "SELECT local_path FROM evidence WHERE evidence_id=?", (request["evidence"]["other_response"],)).fetchone()
        (self.root / row["local_path"]).write_bytes(b'{"status": 403, "body": "forged after the fact"}')
        with self.assertRaisesRegex(EvidenceResolutionError, "integrity"):
            self.engine().validate(request)

    def test_engagement_isolation_hides_foreign_evidence_entirely(self):
        foreign = self.response("hidden", engagement="other")
        with self.assertRaisesRegex(EvidenceResolutionError, "unknown or not part of this engagement"):
            EvidenceResolver(self.vault, "eng").response(foreign, "owner_response")


class ControlPlaneFactsTests(ChainBase):
    def _granted(self, tag="facts"):
        return bola_request(self.vault, "eng", tag, other="granted")

    def test_without_a_declared_owner_a_different_success_is_inconclusive_and_asks_for_the_fact(self):
        record = self.engine().validate(self._granted())
        self.assertEqual(record.disposition, INCONCLUSIVE)
        (request,) = record.evidence_requests
        self.assertEqual(request["kind"], "confirm_object_ownership")
        self.assertEqual(request["detail"]["object"], "order-7")

    def test_an_operator_declared_owner_turns_the_same_evidence_into_a_confirmation(self):
        self.ingest.declare_object_owner("order-7", "bob")
        record = self.engine().validate(self._granted("declared"))
        self.assertEqual(record.disposition, SUPPORTED)
        self.assertEqual(record.evidence_requests, [])

    def test_ambiguous_or_foreign_ownership_is_not_a_fact(self):
        self.ingest.declare_object_owner("order-7", "bob")
        self.ingest.declare_object_owner("order-7", "carol")            # two owners declared
        self.assertIsNone(GraphFacts(self.graph).object_owner("order-7"))
        self.assertEqual(self.engine().validate(self._granted("ambiguous")).disposition, INCONCLUSIVE)

    def test_ownership_by_a_different_identity_than_the_claimed_owner_does_not_confirm(self):
        self.ingest.declare_object_owner("order-7", "carol")            # not the identity the request names
        self.assertEqual(self.engine().validate(self._granted("wrong-owner")).disposition, INCONCLUSIVE)

    def test_function_restriction_comes_from_the_graph_not_the_request(self):
        endpoint = self.ingest.register_endpoint("GET", "https://app.local", "/api/admin/users")
        key = "GET https://app.local/api/admin/users"
        request = {"vulnerability_class": "function_authorization", "baseline_role": "admin",
                   "comparison_role": "user", "function_reference": key,
                   "evidence": {"baseline_response": self.response("adm", 200, "[]"),
                                "lower_privilege_response": self.response("usr", 200, "[]")}}
        first = self.engine().validate(request)
        self.assertEqual(first.disposition, INCONCLUSIVE)
        self.assertEqual(first.evidence_requests[0]["kind"], "confirm_function_role_restriction")
        self.ingest.authorize_role_access("admin", endpoint)            # operator declares the restriction
        request["evidence"] = {"baseline_response": self.response("adm2", 200, "[]"),
                               "lower_privilege_response": self.response("usr2", 200, "[]")}
        self.assertEqual(self.engine().validate(request).disposition, SUPPORTED)

    def test_a_restriction_that_also_grants_the_lower_role_is_not_a_restriction(self):
        endpoint = self.ingest.register_endpoint("GET", "https://app.local", "/api/shared")
        self.ingest.authorize_role_access("admin", endpoint)
        self.ingest.authorize_role_access("user", endpoint)
        self.assertFalse(GraphFacts(self.graph).role_restriction("GET https://app.local/api/shared", "admin", "user"))


class OtherOraclesOnVerifiedEvidenceTests(ChainBase):
    def test_sqli_fingerprints_are_computed_from_the_stored_bodies_not_asserted(self):
        differs = {"vulnerability_class": "sqli", "evidence": {
            "baseline": self.response("b", 200, "<p>3 results</p>"),
            "true_case": self.response("t", 200, "<p>3 results</p>"),
            "false_case": self.response("f", 200, "<p>0 results</p>")}}
        self.assertEqual(self.engine().validate(differs).disposition, SUPPORTED)
        same = {"vulnerability_class": "sqli", "evidence": {
            "baseline": self.response("b2", 200, "<p>3 results</p>"),
            "true_case": self.response("t2", 200, "<p>3 results</p>"),
            "false_case": self.response("f2", 200, "<p>3  results</p>")}}     # whitespace only
        self.assertEqual(self.engine().validate(same).disposition, REFUTED)
        with self.assertRaisesRegex(ValidationError, "Inline"):
            self.engine().validate({**same, "samples": {"baseline": {"normalized_fingerprint": "a"}}})

    def test_security_header_oracle_reads_the_headers_from_evidence(self):
        request = {"vulnerability_class": "security_header", "required_header": "content-security-policy",
                   "evidence": {"response": self.response("h1", 200, "x", headers={"X-Other": "1"})}}
        self.assertEqual(self.engine().validate(request).disposition, SUPPORTED)
        request["evidence"] = {"response": self.response(
            "h2", 200, "x", headers={"Content-Security-Policy": "default-src 'self'"})}
        self.assertEqual(self.engine().validate(request).disposition, REFUTED)

    def test_reflected_input_confirms_only_when_context_is_actually_established(self):
        # core.html_context classifies an unambiguous, unescaped body-text reflection: context IS
        # established, so this one DOES confirm (unlike before core/html_context.py existed).
        marker = "<wh-probe-7f3a>"
        sent = capture_http_request(self.vault, "eng", "reflect-req", url="https://app.local/search?q=" + marker)
        html = self.response("reflect-html", 200, "<p>" + marker + "</p>", headers={"Content-Type": "text/html"})
        record = self.engine().validate({"vulnerability_class": "reflected_input", "marker": marker,
                                         "evidence": {"request": sent, "response": html}})
        self.assertEqual(record.disposition, SUPPORTED)

        escaped_html = self.response("reflect-html-escaped", 200, "<p>&lt;wh-probe-7f3a&gt;</p>",
                                     headers={"Content-Type": "text/html"})
        record = self.engine().validate({"vulnerability_class": "reflected_input", "marker": marker,
                                         "evidence": {"request": sent, "response": escaped_html}})
        self.assertEqual(record.disposition, REFUTED)

        json_response = self.response("reflect-json", 200, '{"q": "' + marker + '"}',
                                      headers={"Content-Type": "application/json"})
        record = self.engine().validate({"vulnerability_class": "reflected_input", "marker": marker,
                                         "evidence": {"request": sent, "response": json_response}})
        self.assertNotEqual(record.disposition, SUPPORTED)

    def test_reflected_input_stays_inconclusive_when_context_cannot_be_established(self):
        # A marker outside the bracket shape core.html_context supports falls back to "unknown"
        # rather than raising, and a marker split across two different HTML regions is genuinely
        # ambiguous - core.html_context never guesses either case into a confirmation.
        bare_marker = "wh-probe-plain"
        sent = capture_http_request(self.vault, "eng", "reflect-req-bare", url="https://app.local/search?q=" + bare_marker)
        html = self.response("reflect-html-bare", 200, "<p>" + bare_marker + "</p>", headers={"Content-Type": "text/html"})
        record = self.engine().validate({"vulnerability_class": "reflected_input", "marker": bare_marker,
                                         "evidence": {"request": sent, "response": html}})
        self.assertEqual(record.disposition, INCONCLUSIVE)
        self.assertEqual(record.evidence_requests[0]["kind"], "determine_execution_context")

        ambiguous_marker = "<wh-probe-ambig1>"
        sent2 = capture_http_request(self.vault, "eng", "reflect-req-ambig",
                                     url="https://app.local/search?q=" + ambiguous_marker)
        ambiguous_html = self.response(
            "reflect-html-ambiguous", 200,
            f"<p>{ambiguous_marker}</p><script>\"{ambiguous_marker}\"</script>",
            headers={"Content-Type": "text/html"})
        record = self.engine().validate({"vulnerability_class": "reflected_input", "marker": ambiguous_marker,
                                         "evidence": {"request": sent2, "response": ambiguous_html}})
        self.assertEqual(record.disposition, INCONCLUSIVE)

    def test_the_marker_must_have_been_part_of_the_executed_request(self):
        sent = capture_http_request(self.vault, "eng", "other-req", url="https://app.local/search?q=something")
        html = self.response("m-html", 200, "<p>wh-probe-9z</p>", headers={"Content-Type": "text/html"})
        with self.assertRaisesRegex(ValidationError, "marker"):
            self.engine().validate({"vulnerability_class": "reflected_input", "marker": "wh-probe-9z",
                                    "evidence": {"request": sent, "response": html}})

    def test_a_percent_encoded_marker_in_the_sent_url_still_counts_as_sent(self):
        # A query VALUE containing "<"/">" is correctly percent-encoded by any URL-encoding
        # client; the request evidence records the URL as actually sent (encoded), so the
        # "was it really sent" check must unquote before comparing, not reject every such marker.
        marker = "<wh-xss-ab12cd34ef56ab12>"
        encoded_url = "https://app.local/search?q=%3Cwh-xss-ab12cd34ef56ab12%3E"
        sent = capture_http_request(self.vault, "eng", "encoded-req", url=encoded_url)
        html = self.response("encoded-html", 200, "<p>" + marker + "</p>", headers={"Content-Type": "text/html"})
        record = self.engine().validate({"vulnerability_class": "reflected_input", "marker": marker,
                                         "evidence": {"request": sent, "response": html}})
        self.assertEqual(record.disposition, SUPPORTED)

    def test_a_marker_absent_even_after_unquoting_still_raises(self):
        marker = "<wh-xss-ab12cd34ef56ab12>"
        sent = capture_http_request(self.vault, "eng", "unrelated-req",
                                    url="https://app.local/search?q=%73omething-else-entirely")
        html = self.response("unrelated-html", 200, "<p>" + marker + "</p>", headers={"Content-Type": "text/html"})
        with self.assertRaisesRegex(ValidationError, "marker"):
            self.engine().validate({"vulnerability_class": "reflected_input", "marker": marker,
                                    "evidence": {"request": sent, "response": html}})

    def test_ssrf_confirms_only_on_a_verified_callback_match(self):
        response = self.response("ssrf-resp", 200, "{}", headers={"Content-Type": "application/json"})
        matched = self.callback_log("ssrf-matched", [{"marker": "wh-ssrf-1", "source_ip": "203.0.113.9"}])
        record = self.engine().validate({"vulnerability_class": "ssrf", "marker": "wh-ssrf-1",
                                         "evidence": {"response": response, "callback_log": matched}})
        self.assertEqual(record.disposition, SUPPORTED)

        empty_log = self.callback_log("ssrf-empty", [])
        record = self.engine().validate({"vulnerability_class": "ssrf", "marker": "wh-ssrf-1",
                                         "evidence": {"response": response, "callback_log": empty_log}})
        self.assertEqual(record.disposition, INCONCLUSIVE)
        self.assertNotEqual(record.disposition, REFUTED)

    def test_ssrf_callback_match_is_recomputed_from_the_verified_log_not_trusted(self):
        # A log that only holds events for OTHER markers must not confirm this one, even though a
        # (differently-filtered) log exists: the resolver re-checks the marker itself.
        response = self.response("ssrf-resp-2", 200, "{}", headers={"Content-Type": "application/json"})
        other_markers_log = self.callback_log("ssrf-other", [{"marker": "wh-ssrf-DIFFERENT"}])
        record = self.engine().validate({"vulnerability_class": "ssrf", "marker": "wh-ssrf-1",
                                         "evidence": {"response": response, "callback_log": other_markers_log}})
        self.assertNotEqual(record.disposition, SUPPORTED)

    def test_ssrf_reflection_without_a_callback_is_inconclusive_not_confirmed(self):
        response = self.response("ssrf-resp-3", 200, "wh-ssrf-1 appears here", headers={"Content-Type": "text/plain"})
        empty_log = self.callback_log("ssrf-empty-2", [])
        record = self.engine().validate({"vulnerability_class": "ssrf", "marker": "wh-ssrf-1",
                                         "evidence": {"response": response, "callback_log": empty_log}})
        self.assertEqual(record.disposition, INCONCLUSIVE)
        self.assertEqual(record.evidence_requests[0]["kind"], "confirm_outbound_fetch")

    def test_ssrf_evidence_must_be_exactly_response_and_callback_log(self):
        response = self.response("ssrf-resp-4", 200, "{}")
        with self.assertRaisesRegex(ValidationError, "Evidence roles"):
            self.engine().validate({"vulnerability_class": "ssrf", "marker": "wh-ssrf-1",
                                    "evidence": {"response": response}})


class LifecycleGateTests(ChainBase):
    def setUp(self):
        super().setUp()
        self.validator = FindingValidator(self.store, self.vault)

    def test_verified_evidence_confirms(self):
        fid = self.finding()
        result = self.validator.validate_finding(fid, bola_request(self.vault, "eng", "ok"), "validation-agent")
        self.assertEqual((result["disposition"], result["finding_status"]), (SUPPORTED, "validated"))

    def test_without_a_vault_nothing_can_be_confirmed(self):
        fid = self.finding()
        blind = FindingValidator(self.store)                    # no vault: cannot resolve anything
        inline = {"vulnerability_class": "object_authorization", "owner_identity": "bob",
                  "other_identity": "alice", "object_reference": "order-7",
                  "owner_response": {"status_code": 200, "response_excerpt": '{"id":1}'},
                  "other_response": {"status_code": 200, "response_excerpt": '{"id":1}'}}
        result = blind.validate_finding(fid, inline, "validation-agent")
        self.assertEqual(result["disposition"], SUPPORTED)      # the oracle's opinion is recorded...
        self.assertEqual(result["gated"], "unverified_evidence")
        self.assertEqual(result["finding_status"], "needs_more_evidence")  # ...but cannot confirm
        record = self.records.for_finding(fid)[0]
        self.assertFalse(record["evidence_verified"])

    def test_a_rejection_on_unverified_evidence_is_also_gated(self):
        fid = self.finding()
        blind = FindingValidator(self.store)
        denied = {"vulnerability_class": "object_authorization", "owner_identity": "bob", "other_identity": "alice",
                  "object_reference": "order-7",
                  "owner_response": {"status_code": 200, "response_excerpt": "{}"},
                  "other_response": {"status_code": 403, "response_excerpt": "{}"}}
        self.assertEqual(blind.validate_finding(fid, denied, "validation-agent")["finding_status"], "needs_more_evidence")

    def test_inline_data_with_a_vault_is_refused_and_leaves_the_finding_untouched(self):
        fid = self.finding()
        inline = {"vulnerability_class": "object_authorization", "owner_identity": "bob", "other_identity": "alice",
                  "object_reference": "order-7",
                  "owner_response": {"status_code": 200, "response_excerpt": "{}"},
                  "other_response": {"status_code": 200, "response_excerpt": "{}"}}
        with self.assertRaises(ValidationError):
            self.validator.validate_finding(fid, inline, "validation-agent")
        status = self.store.connection.execute("SELECT status FROM findings WHERE finding_id=?", (fid,)).fetchone()
        self.assertEqual(status["status"], "validation_pending")

    def test_an_inconclusive_result_carries_its_evidence_request_to_the_caller(self):
        fid = self.finding()
        result = self.validator.validate_finding(fid, bola_request(self.vault, "eng", "inc", other="granted"),
                                                 "validation-agent")
        self.assertEqual(result["finding_status"], "needs_more_evidence")
        self.assertEqual(result["evidence_requests"][0]["kind"], "confirm_object_ownership")

    def test_a_bad_retest_cannot_degrade_a_validated_finding(self):
        fid = self.finding()
        self.validator.validate_finding(fid, bola_request(self.vault, "eng", "first"), "validation-agent")
        for attempt in (FindingValidator(self.store),                         # cannot resolve evidence at all
                        self.validator):                                       # resolves, but the references are bogus
            bogus = {"vulnerability_class": "object_authorization", "owner_identity": "bob", "other_identity": "alice",
                     "object_reference": "order-7",
                     "evidence": {"owner_response": "evidence_x", "other_response": "evidence_y"}}
            with self.assertRaises(ValidationError):
                attempt.retest_finding(fid, bogus, "validation-agent")
            status = self.store.connection.execute("SELECT status FROM findings WHERE finding_id=?", (fid,)).fetchone()
            self.assertEqual(status["status"], "validated")

    def test_a_genuine_retest_still_verifies_a_fix(self):
        fid = self.finding()
        self.validator.validate_finding(fid, bola_request(self.vault, "eng", "before"), "validation-agent")
        result = self.validator.retest_finding(fid, bola_request(self.vault, "eng", "after", other="denied"),
                                               "validation-agent")
        self.assertEqual((result["outcome"], result["finding_status"]), ("FIX_VERIFIED", "resolved"))


class ReportHonestyTests(ChainBase):
    def test_a_verified_finding_reports_its_evidence_chain(self):
        fid = self.finding()
        FindingValidator(self.store, self.vault).validate_finding(
            fid, bola_request(self.vault, "eng", "rep"), "validation-agent")
        report = build_finding_report(self.store, fid)
        self.assertTrue(report["validation"]["evidence_verified"])
        self.assertIn("vault-verified", report["confidence_and_limitations"])
        self.assertTrue(report["validation"]["records"][0]["evidence_hashes"])

    def test_a_pre_chain_record_is_reported_but_never_described_as_verified(self):
        fid = self.finding("legacy")
        # A historical validated finding whose validation record was computed on embedded data.
        engine = ExploitValidationEngine("eng", record_store=self.records)
        record = engine.validate({
            "vulnerability_class": "object_authorization", "finding_id": fid, "owner_identity": "bob",
            "other_identity": "alice", "object_reference": "order-7",
            "owner_response": {"status_code": 200, "response_excerpt": '{"id":1}'},
            "other_response": {"status_code": 200, "response_excerpt": '{"id":1}'}})
        self.store.record_finding_review(fid, "validation-agent", {
            "decision": "eligible_for_independent_validation", "supported_claims": [record.record_id],
            "refuted_claims": [], "inconclusive_claims": []}, record.to_dict())
        self.store.transition_finding(fid, "validated", "validation-agent", validation_notes="historic")
        report = build_finding_report(self.store, fid)
        self.assertFalse(report["validation"]["evidence_verified"])
        self.assertIn("NOT re-resolved", report["confidence_and_limitations"])
        self.assertTrue(report["validation"]["integrity_verified"])      # still a valid, untampered record


class FixedDefectsTests(unittest.TestCase):
    def test_response_fingerprints_ignore_whitespace_differences(self):
        # Regression: the normaliser used a raw string r"\\s+" (a literal backslash followed by
        # "s"), so non-JSON bodies differing only in whitespace never matched.
        self.assertEqual(response_fingerprint("<p>hello   world</p>\n"), response_fingerprint("<p>hello world</p>"))
        self.assertEqual(response_fingerprint('{"a": "x   y"}'), response_fingerprint('{"a":"x y"}'))
        self.assertNotEqual(response_fingerprint("<p>hello</p>"), response_fingerprint("<p>goodbye</p>"))

    def test_sqlite_error_signatures_are_recognised(self):
        # Regression: the pattern contained SQLite\\/JDBC (a literal backslash) and no SQLite signatures.
        for message in ("sqlite3.OperationalError: near \"'\": syntax error", "[SQLITE_ERROR] SQL error", "SQLite/JDBC driver"):
            sample = {"baseline": {"status_code": 200, "body_excerpt": "ok"},
                      "true_case": {"status_code": 500, "body_excerpt": message},
                      "false_case": {"status_code": 200, "body_excerpt": "ok"}}
            self.assertIn("database_error_signature_observed", analyze_sqli_pair(sample)["findings"], message)


if __name__ == "__main__":
    unittest.main()
