import unittest

from scripts.redact_text_evidence import redact_text


class TextEvidenceRedactionTests(unittest.TestCase):
    def test_redacts_common_secrets_and_emails(self):
        source = (
            "Authorization: Bearer abcdefghijklmnop\n"
            "Cookie: sessionid=secret-cookie\n"
            "password = hunter2\n"
            "Contact: analyst@example.com\n"
            "AWS key AKIA1234567890ABCDEF\n"
        )
        result, counts = redact_text(source)
        self.assertNotIn("abcdefghijklmnop", result)
        self.assertNotIn("secret-cookie", result)
        self.assertNotIn("hunter2", result)
        self.assertNotIn("analyst@example.com", result)
        self.assertNotIn("AKIA1234567890ABCDEF", result)
        self.assertGreaterEqual(sum(counts.values()), 5)

    def test_preserves_non_sensitive_context(self):
        source = "GET /api/v1/users HTTP/1.1\nHost: app.example.test\n"
        result, counts = redact_text(source)
        self.assertEqual(result, source)
        self.assertEqual(counts, {})


if __name__ == "__main__":
    unittest.main()
