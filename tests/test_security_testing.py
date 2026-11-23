import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from core.active_executor import ActiveExecutionError
from core.security_testing import (
    _validate_readonly_pair, analyze_authentication_pair, analyze_cache_pair,
    analyze_http_framing, analyze_race_capture, analyze_ssrf_probe, execute_readonly_pair,
    validate_scoped_callback_url,
)


class SecurityAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.requests = self.root / ".local" / "requests"
        self.requests.mkdir(parents=True)
        self.executor = Mock()
        self.executor.project_root = self.root
        self.first = {
            "request_id": "pair-first-001", "method": "GET",
            "url": "https://app.example.test/account",
            "purpose": "Read synthetic protected resource",
            "secret_headers": {"Authorization": "SYNTH_AUTH_A"},
            "timeout_seconds": 5, "max_response_bytes": 8192, "follow_redirects": False,
        }
        self.second = {**self.first, "request_id": "pair-second-001",
                       "secret_headers": {"Authorization": "SYNTH_AUTH_B"}}
        self.first_path = self._write("first.json", self.first)
        self.second_path = self._write("second.json", self.second)

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, name, value):
        path = self.requests / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return ".local/requests/" + name

    def test_two_identity_pair_executes_sequentially_and_collects_both_evidence_sets(self):
        self.executor.execute_request_file.side_effect = [
            {"status_code": 200, "response_excerpt": "A", "evidence_refs": ["a-req", "a-resp"]},
            {"status_code": 200, "response_excerpt": "B", "evidence_refs": ["b-req", "b-resp"]},
        ]
        pair = execute_readonly_pair(self.executor, "eng", "task", self.first_path,
            self.second_path, identity_mode="two_identities",
            first_label="identity-a", second_label="identity-b")
        self.assertEqual(pair["status"], "comparison_completed")
        self.assertEqual(self.executor.execute_request_file.call_count, 2)
        self.assertEqual(set(pair["evidence_refs"]), {"a-req", "a-resp", "b-req", "b-resp"})

    def test_authenticated_vs_anonymous_pair_requires_one_secret_identity(self):
        anonymous = {**self.first, "request_id": "pair-anon-001"}
        anonymous.pop("secret_headers")
        path = self._write("anonymous.json", anonymous)
        _validate_readonly_pair(self.first, anonymous, "authenticated_vs_anonymous")
        _validate_readonly_pair(anonymous, self.first, "authenticated_vs_anonymous")
        with self.assertRaisesRegex(ActiveExecutionError, "one authenticated"):
            _validate_readonly_pair(self.first, self.second, "authenticated_vs_anonymous")

    def test_pair_rejects_non_get_method_or_changed_request_context(self):
        bad = {**self.second, "method": "POST"}
        with self.assertRaisesRegex(ActiveExecutionError, "only GET"):
            _validate_readonly_pair(self.first, bad, "two_identities")
        bad = {**self.second, "url": self.second["url"] + "?role=admin"}
        with self.assertRaisesRegex(ActiveExecutionError, "must be equivalent"):
            _validate_readonly_pair(self.first, bad, "two_identities")

    def test_partial_pair_does_not_claim_comparison(self):
        self.executor.execute_request_file.side_effect = [
            {"status_code": 200, "evidence_refs": ["first-evidence"]},
            ActiveExecutionError("manifest not pinned"),
        ]
        pair = execute_readonly_pair(self.executor, "eng", "task", self.first_path,
            self.second_path, identity_mode="two_identities",
            first_label="identity-a", second_label="identity-b")
        self.assertEqual(pair["status"], "partial_execution")
        self.assertEqual(pair["evidence_refs"], ["first-evidence"])
        self.assertNotIn("comparison", pair)

    def test_authentication_boundary_flags_anonymous_success_as_candidate(self):
        pair = {"status": "comparison_completed", "first_label": "authenticated",
                "second_label": "anonymous",
                "first_response": {"status_code": 200, "cookie_security_flags": [["secure", "httponly", "samesite=lax"]]},
                "second_response": {"status_code": 200}, "evidence_refs": ["a", "b"]}
        result = analyze_authentication_pair(pair, authenticated_label="authenticated",
            anonymous_label="anonymous", protected_resource="/account")
        self.assertEqual(result["classification"], "potential_authentication_boundary_gap")
        self.assertEqual(result["status"], "candidate_only")
        self.assertEqual(result["cookie_flag_observations"], [])

    def test_authentication_denial_is_observation_not_finding(self):
        pair = {"status": "comparison_completed", "first_label": "authenticated",
                "second_label": "anonymous",
                "first_response": {"status_code": 200, "cookie_security_flags": [["secure"]]},
                "second_response": {"status_code": 401}, "evidence_refs": []}
        result = analyze_authentication_pair(pair, authenticated_label="authenticated",
            anonymous_label="anonymous", protected_resource="/account")
        self.assertEqual(result["classification"], "anonymous_access_denied")
        self.assertEqual(result["status"], "observation")
        self.assertIn("missing_httponly", result["cookie_flag_observations"])

    def test_cache_marker_crossing_identity_is_candidate(self):
        pair = {"status": "comparison_completed",
                "first_response": {"status_code": 200, "response_excerpt": "private-A",
                    "response_headers": {"Cache-Control": "private, no-store"}},
                "second_response": {"status_code": 200, "response_excerpt": "private-A",
                    "response_headers": {"Age": "2", "X-Cache": "HIT"}},
                "evidence_refs": ["a", "b"]}
        result = analyze_cache_pair(pair, first_private_marker="private-A",
            second_private_marker="private-B")
        self.assertEqual(result["classification"], "potential_cross_identity_cache_disclosure")
        self.assertTrue(result["cross_identity_marker_leak"])

    def test_cacheability_header_is_candidate_not_confirmation(self):
        pair = {"status": "comparison_completed",
                "first_response": {"status_code": 200, "response_excerpt": "A",
                    "response_headers": {"Cache-Control": "public, max-age=60"}},
                "second_response": {"status_code": 200, "response_excerpt": "B",
                    "response_headers": {"Cache-Control": "public, max-age=60"}},
                "evidence_refs": []}
        result = analyze_cache_pair(pair, first_private_marker="private-A",
            second_private_marker="private-B")
        self.assertEqual(result["classification"], "potential_sensitive_response_cacheability")
        self.assertEqual(result["status"], "candidate_only")

    def test_ssrf_callback_marker_is_candidate_only_and_reflection_is_not_callback(self):
        response = {"status_code": 200, "response_excerpt": "queued", "evidence_refs": ["http-response"]}
        result = analyze_ssrf_probe(response, marker="marker-unique-1234",
            callback_events=[{"marker": "marker-unique-1234", "source_ip": "203.0.113.8"}])
        self.assertEqual(result["classification"], "potential_ssrf_callback_observed")
        reflected = analyze_ssrf_probe({**response, "response_excerpt": "marker-unique-1234"},
            marker="marker-unique-1234")
        self.assertEqual(reflected["classification"], "marker_reflected_without_callback")

    def test_ssrf_callback_requires_https_and_explicit_scope(self):
        scope = {"allowed_domains": ["*.example.test"], "excluded_assets": []}
        self.assertEqual(validate_scoped_callback_url("https://callback.example.test/canary",
            scope), "callback.example.test")
        with self.assertRaisesRegex(ActiveExecutionError, "HTTPS"):
            validate_scoped_callback_url("http://callback.example.test/canary", scope)
        with self.assertRaisesRegex(ActiveExecutionError, "explicitly listed"):
            validate_scoped_callback_url("https://outside.test/canary", scope)

    def test_passive_framing_analyzer_never_executes_and_flags_te_cl(self):
        result = analyze_http_framing({"headers": [
            {"name": "Transfer-Encoding", "value": "chunked"},
            {"name": "Content-Length", "value": "10"},
        ]})
        self.assertIn("transfer_encoding_and_content_length_present", result["findings"])
        self.assertIn("No ambiguous framing is transmitted", result["limitations"][1])

    def test_race_capture_requires_synthetic_object_and_reports_only_overlap_with_invariant_violation(self):
        events = [
            {"request_id": "race-001", "object_reference": "synthetic-cart-1",
             "started_at": "2026-11-23T10:00:00+00:00", "finished_at": "2026-11-23T10:00:03+00:00",
             "invariant_violation": True},
            {"request_id": "race-002", "object_reference": "synthetic-cart-1",
             "started_at": "2026-11-23T10:00:01+00:00", "finished_at": "2026-11-23T10:00:04+00:00",
             "invariant_violation": False},
        ]
        result = analyze_race_capture(events)
        self.assertEqual(result["classification"], "potential_race_condition")
        self.assertEqual(result["status"], "candidate_only")
        self.assertEqual(result["overlapping_pairs"], [["race-001", "race-002"]])

    def test_race_capture_does_not_infer_vulnerability_from_overlap_alone(self):
        events = [
            {"request_id": "race-003", "object_reference": "synthetic-cart-2",
             "started_at": "2026-11-23T10:00:00+00:00", "finished_at": "2026-11-23T10:00:03+00:00"},
            {"request_id": "race-004", "object_reference": "synthetic-cart-2",
             "started_at": "2026-11-23T10:00:01+00:00", "finished_at": "2026-11-23T10:00:04+00:00"},
        ]
        result = analyze_race_capture(events)
        self.assertEqual(result["classification"], "overlap_without_invariant_violation")
        self.assertEqual(result["status"], "observation")

    def test_race_capture_rejects_real_or_ambiguous_object_references(self):
        events = [
            {"request_id": "race-005", "object_reference": "customer-123",
             "started_at": "2026-11-23T10:00:00+00:00", "finished_at": "2026-11-23T10:00:03+00:00"},
            {"request_id": "race-006", "object_reference": "customer-123",
             "started_at": "2026-11-23T10:00:01+00:00", "finished_at": "2026-11-23T10:00:04+00:00"},
        ]
        with self.assertRaisesRegex(ValueError, "synthetic"):
            analyze_race_capture(events)


    def test_partial_and_empty_ssrf_results_remain_inconclusive(self):
        result = analyze_ssrf_probe({"status_code": 202, "response_excerpt": "",
            "evidence_refs": []}, marker="marker-unique-1234")
        self.assertEqual(result["status"], "observation")
        self.assertEqual(result["classification"], "ssrf_inconclusive")


if __name__ == "__main__":
    unittest.main()
