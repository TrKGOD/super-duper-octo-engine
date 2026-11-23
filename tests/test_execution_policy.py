import math
import unittest

from core.execution_policy import (
    MAX_REQUESTS_PER_ENGAGEMENT,
    MAX_REQUESTS_PER_SECOND,
    validate_execution_limits,
)


class ExecutionPolicyTests(unittest.TestCase):
    def test_safe_defaults_are_preserved(self):
        self.assertEqual(validate_execution_limits({}), (1, 1.0, 20))

    def test_engagement_can_configure_higher_bounded_throughput_and_budget(self):
        self.assertEqual(
            validate_execution_limits({
                "max_concurrency": 1,
                "requests_per_second": 4.5,
                "max_requests_per_engagement": 400,
            }),
            (1, 4.5, 400),
        )

    def test_hard_ceilings_are_enforced(self):
        with self.assertRaisesRegex(ValueError, "requests_per_second"):
            validate_execution_limits({"requests_per_second": MAX_REQUESTS_PER_SECOND + 0.01})
        with self.assertRaisesRegex(ValueError, "max_requests_per_engagement"):
            validate_execution_limits({"max_requests_per_engagement": MAX_REQUESTS_PER_ENGAGEMENT + 1})

    def test_non_finite_and_boolean_values_are_rejected(self):
        for value in (True, False, float("nan"), float("inf"), -float("inf")):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_execution_limits({"requests_per_second": value})
        with self.assertRaisesRegex(ValueError, "max_requests_per_engagement"):
            validate_execution_limits({"max_requests_per_engagement": True})

    def test_concurrency_is_not_silently_increased(self):
        with self.assertRaisesRegex(ValueError, "max_concurrency must be 1"):
            validate_execution_limits({"max_concurrency": 2})


if __name__ == "__main__":
    unittest.main()
