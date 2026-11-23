import unittest

from core.execution_policy import MAX_REQUESTS_PER_SECOND, validate_execution_limits


class ExecutionPolicyTests(unittest.TestCase):
    def test_safe_defaults_are_preserved(self):
        self.assertEqual(validate_execution_limits({}), (1, 1.0))

    def test_legacy_cumulative_request_quota_is_ignored(self):
        self.assertEqual(
            validate_execution_limits({
                "max_concurrency": 1,
                "requests_per_second": 4.5,
                "max_requests_per_engagement": 1,
            }),
            (1, 4.5),
        )

    def test_hard_rate_limit_ceiling_is_enforced(self):
        with self.assertRaisesRegex(ValueError, "requests_per_second"):
            validate_execution_limits({"requests_per_second": MAX_REQUESTS_PER_SECOND + 0.01})

    def test_non_finite_and_boolean_values_are_rejected(self):
        for value in (True, False, float("nan"), float("inf"), -float("inf")):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_execution_limits({"requests_per_second": value})
        with self.assertRaisesRegex(ValueError, "requests_per_second"):
            validate_execution_limits({"requests_per_second": 10 ** 1000})

    def test_concurrency_is_not_silently_increased(self):
        with self.assertRaisesRegex(ValueError, "max_concurrency must be 1"):
            validate_execution_limits({"max_concurrency": 2})


if __name__ == "__main__":
    unittest.main()
