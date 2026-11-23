import base64
import json
import tempfile
import unittest
from pathlib import Path

from core.protocol_testing import (
    analyze_oidc_discovery, analyze_oauth_flow, analyze_sqli_pair, inspect_jwt,
)


def segment(value):
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


class ProtocolTestingTests(unittest.TestCase):
    def token(self, header, claims):
        return ".".join((segment(header), segment(claims), "signature-not-verified"))

    def test_oidc_metadata_requires_https_and_expected_issuer(self):
        result = analyze_oidc_discovery({
            "issuer": "http://idp.test",
            "authorization_endpoint": "https://idp.test/authorize",
            "token_endpoint": "https://idp.test/token",
            "jwks_uri": "https://idp.test/keys",
        }, expected_issuer="https://idp.test")
        self.assertIn("issuer_missing_or_not_https", result["findings"])
        self.assertIn("issuer_mismatch", result["findings"])

    def test_oauth_flow_detects_state_redirect_pkce_and_nonce_issues(self):
        result = analyze_oauth_flow({
            "registered_redirect_uri": "https://client.test/callback",
            "public_client": True,
            "authorization_request": {
                "redirect_uri": "https://attacker.test/callback",
                "state": "expected-state",
                "code_challenge": "abc",
                "code_challenge_method": "plain",
                "nonce": "expected-nonce",
            },
            "callback": {"state": "different-state"},
            "id_token_claims": {"nonce": "different-nonce"},
            "evidence_refs": ["ev-1"],
        })
        self.assertEqual(result["status"], "candidate_only")
        self.assertEqual(set(result["findings"]), {
            "redirect_uri_differs_from_registered_value", "state_missing_or_mismatch",
            "public_client_missing_pkce_s256", "oidc_nonce_missing_or_mismatch",
        })

    def test_jwt_inspection_flags_none_alg_issuer_audience_and_expiry(self):
        jwt = self.token({"alg": "none", "typ": "JWT"},
                         {"iss": "https://wrong.test", "aud": "other", "exp": 10})
        result = inspect_jwt(jwt, expected_issuer="https://idp.test",
                             expected_audience="api", now=20)
        self.assertEqual(result["status"], "candidate_only")
        self.assertIn("unsigned_algorithm", result["findings"])
        self.assertIn("issuer_mismatch", result["findings"])
        self.assertIn("audience_mismatch", result["findings"])
        self.assertIn("token_expired", result["findings"])
        self.assertTrue(any("NOT verified" in item for item in result["limitations"]))

    def test_jwt_rejects_malformed_compact_tokens(self):
        with self.assertRaisesRegex(ValueError, "three segments"):
            inspect_jwt("not-a-jwt")

    def test_jwks_kid_and_algorithm_mismatch_are_candidates(self):
        jwt = self.token({"alg": "RS256", "kid": "key-a"},
                         {"iss": "https://idp.test", "aud": "api", "exp": 9999999999})
        result = inspect_jwt(jwt, jwks={"keys": [{"kid": "key-a", "use": "enc", "alg": "HS256"}]})
        self.assertIn("jwks_key_not_marked_for_signatures", result["findings"])
        self.assertIn("jwks_algorithm_mismatch", result["findings"])

    def test_sqli_error_signature_is_candidate_only(self):
        result = analyze_sqli_pair({
            "baseline": {"status_code": 200, "body_excerpt": "ok"},
            "true_case": {"status_code": 500, "body_excerpt": "You have an error in your SQL syntax; MySQL"},
            "false_case": {"status_code": 200, "body_excerpt": "no"},
            "evidence_refs": ["base", "true", "false"],
        })
        self.assertEqual(result["classification"], "potential_sqli_signal")
        self.assertIn("database_error_signature_observed", result["findings"])
        self.assertIn("No database contents", result["limitations"][2])

    def test_sqli_boolean_difference_requires_normalized_fingerprints(self):
        result = analyze_sqli_pair({
            "baseline": {"status_code": 200},
            "true_case": {"status_code": 200, "normalized_fingerprint": "a"},
            "false_case": {"status_code": 200, "normalized_fingerprint": "b"},
        })
        self.assertTrue(result["boolean_pair_differs"])
        self.assertEqual(result["status"], "candidate_only")

    def test_sqli_timing_signal_requires_three_samples_each(self):
        weak = analyze_sqli_pair({
            "baseline": {}, "true_case": {}, "false_case": {},
            "timing_samples_ms": {"true_case": [10, 11], "false_case": [3000, 3100]},
        })
        self.assertFalse(weak["timing_signal"])
        strong = analyze_sqli_pair({
            "baseline": {}, "true_case": {}, "false_case": {},
            "timing_samples_ms": {"true_case": [10, 11, 12], "false_case": [3000, 3100, 3200]},
        })
        self.assertTrue(strong["timing_signal"])

    def test_local_input_rejects_paths_outside_workspace(self):
        from core.protocol_testing import _load_local_json
        with self.assertRaisesRegex(ValueError, "relative file under .local"):
            _load_local_json("../secrets.json")


if __name__ == "__main__":
    unittest.main()
