import unittest

from scripts.parse_program_policy import parse_policy


class ProgramPolicyParserTests(unittest.TestCase):
    def test_separates_scope_and_exclusions_and_preserves_quotes(self):
        source = """# Example Disclosure Program

## In Scope
- https://app.example.test
- api.example.test

## Out of Scope
- admin.example.test
- Third-party identity provider

## Prohibited Activities
- Denial of service
- Social engineering

## Rate Limits
- Maximum 2 requests per second

## Testing Window
- Weekdays 09:00-17:00 UTC

## Data Handling
- Do not access or retain personal data

## Safe Harbor
Testing performed in good faith within these rules is covered by the program safe harbor.

## Rewards
Eligible reports must include reproducible evidence and be the first valid report.
"""
        profile = parse_policy(source, "policy.md")
        self.assertEqual(profile["status"], "draft_unverified")
        self.assertTrue(profile["operator_confirmation_required"])
        self.assertEqual(profile["program_name"], "Example Disclosure Program")
        self.assertIn("https://app.example.test", profile["assets_in_scope"])
        self.assertIn("admin.example.test", profile["out_of_scope"])
        self.assertIn("Maximum 2 requests per second", profile["rate_limits"])
        self.assertTrue(profile["safe_harbor"])
        self.assertTrue(profile["bounty_eligibility"])
        self.assertTrue(any(item["field"] == "out_of_scope" and item["line"] > 0 for item in profile["evidence"]))

    def test_missing_scope_and_rate_limits_create_ambiguities(self):
        profile = parse_policy("# Program\n\n## Overview\nText only.", "policy.md")
        self.assertEqual(profile["assets_in_scope"], [])
        self.assertTrue(any("No in-scope assets" in item for item in profile["ambiguities"]))
        self.assertTrue(any("No rate limit" in item for item in profile["ambiguities"]))


if __name__ == "__main__":
    unittest.main()
