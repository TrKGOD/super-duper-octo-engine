import time
import unittest

from core.redaction import (REDACTED, is_secret_field, is_sensitive_name, redact,
                            redact_value, redact_with_counts)


class FreeTextRedactionTests(unittest.TestCase):
    def test_authorization_headers_are_redacted_but_the_scheme_is_kept(self):
        for text in ("Authorization: Bearer abc123def456", "authorization=basic dXNlcjpwYXNz",
                     '"Authorization": "Bearer abc123def456"'):
            out = redact(text)
            self.assertIn(REDACTED, out, text)
            self.assertNotIn("abc123def456", out)
            self.assertNotIn("dXNlcjpwYXNz", out)

    def test_credential_assignments_in_every_common_encoding(self):
        samples = {
            "password=hunter2&next=/": "hunter2",
            '{"access_token": "tok-12345"}': "tok-12345",
            "client_secret: s3cr3t-value": "s3cr3t-value",
            "api_key = 'k-998877'": "k-998877",
            "PHPSESSID=abcdef0123456789": "abcdef0123456789",
        }
        for text, secret in samples.items():
            self.assertNotIn(secret, redact(text), text)

    def test_tokens_with_recognisable_shapes(self):
        aws = "AKIA" + "ABCDEFGHIJKLMNOP"
        # assembled from parts so that no secret-shaped literal exists in the source for a scanner to flag
        jwt = ".".join(["eyJhbGciOiJSUzI1NiJ9", "eyJzdWIiOiJhbGljZSJ9", "c2lnbmF0dXJl"])
        gh = "ghp_" + "a" * 36
        slack = "xoxb-" + "1234567890-abcdef"
        stripe = "sk_live_" + "A" * 24
        google = "AIza" + "B" * 35
        for secret in (aws, jwt, gh, slack, stripe, google):
            self.assertNotIn(secret, redact("value: " + secret + " end"), secret)

    def test_unsigned_jwt_with_empty_signature_is_redacted(self):
        payload = "eyJzdWIiOiJhbGljZSJ9"
        unsigned = ".".join(["eyJhbGciOiJub25lIn0", payload, ""])
        self.assertNotIn(payload, redact(unsigned))

    def test_private_key_block_and_url_credentials(self):
        key = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJB\n-----END RSA PRIVATE KEY-----"
        self.assertNotIn("MIIBOgIBAAJB", redact("x\n" + key + "\ny"))
        out = redact("see https://admin:p4ssw0rd@db.internal/path")
        self.assertNotIn("p4ssw0rd", out)
        self.assertIn("https://", out)          # scheme is preserved
        self.assertIn("db.internal/path", out)  # the rest of the URL is preserved

    def test_cookie_lines_are_redacted_wholesale(self):
        out = redact("GET / HTTP/1.1\nCookie: sid=abc; theme=dark\nHost: a.test\n")
        self.assertNotIn("abc", out)
        self.assertIn("Host: a.test", out)

    def test_pii_is_opt_in(self):
        self.assertIn("analyst@example.com", redact("mail analyst@example.com"))
        self.assertNotIn("analyst@example.com", redact("mail analyst@example.com", pii=True))

    def test_non_sensitive_text_is_untouched_and_counts_are_empty(self):
        text = "GET /api/v1/orders/7 HTTP/1.1\nHost: app.example.test\nAccept: */*\n"
        clean, counts = redact_with_counts(text)
        self.assertEqual(clean, text)
        self.assertEqual(counts, {})

    def test_redaction_is_idempotent(self):
        text = "password=hunter2 Authorization: Bearer abcdefgh12345"
        once = redact(text)
        self.assertEqual(redact(once), once)

    def test_redaction_is_linear_on_large_input(self):
        big = ("a=b&" * 200_000) + "password=hunter2"
        started = time.monotonic()
        clean = redact(big)
        self.assertLess(time.monotonic() - started, 5.0)
        self.assertNotIn("hunter2", clean)


class StructuredRedactionTests(unittest.TestCase):
    def test_secret_keys_are_redacted_even_when_the_value_has_no_context(self):
        # The regression: {"password": "hunter2"} leaked because "hunter2" matches no pattern.
        data = {"password": "hunter2", "api_key": "k-1", "nested": {"refresh_token": "r-1"},
                "items": [{"client_secret": "cs-1"}]}
        out = redact_value(data)
        flat = repr(out)
        for secret in ("hunter2", "k-1", "r-1", "cs-1"):
            self.assertNotIn(secret, flat)

    def test_identifiers_that_merely_mention_a_secret_stay_visible(self):
        data = {"session_id": "sess_abc", "token_endpoint": "/oauth/token", "identity_id": "alice",
                "credential_count": 2, "authorization_reference": "AUTH-LAB-1"}
        self.assertEqual(redact_value(data), data)

    def test_cors_credentials_header_is_not_mistaken_for_a_secret(self):
        # Regression: "credential" as a sensitive term redacted this header's value, which hid
        # the evidence of a CORS origin-reflection-with-credentials finding.
        self.assertFalse(is_sensitive_name("Access-Control-Allow-Credentials"))
        self.assertFalse(is_secret_field("access_control_allow_credentials"))
        self.assertTrue(is_sensitive_name("X-Api-Key"))
        self.assertTrue(is_sensitive_name("Proxy-Authorization"))

    def test_strict_header_names_vs_structured_field_names(self):
        self.assertTrue(is_sensitive_name("Authorization"))
        self.assertTrue(is_sensitive_name("X-Session-Id"))   # strict: headers
        self.assertFalse(is_secret_field("session_id"))      # structured: an identifier
        self.assertTrue(is_secret_field("session_token"))
        self.assertTrue(is_secret_field("Authorization"))

    def test_non_string_scalars_and_booleans_are_preserved(self):
        self.assertEqual(redact_value({"ok": True, "n": 3, "none": None}), {"ok": True, "n": 3, "none": None})
        self.assertEqual(redact_value({"token": True}), {"token": True})


if __name__ == "__main__":
    unittest.main()
