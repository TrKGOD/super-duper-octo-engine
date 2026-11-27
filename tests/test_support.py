"""The shared test gates behave as documented: skip by default, fail when the environment says it must run."""
import os
import unittest
from unittest.mock import patch

from tests import support
from tests.support import BROWSER_GATE, browser_problem, require_browser_or_skip


class BrowserGateTests(unittest.TestCase):
    def test_a_usable_browser_passes_the_gate(self):
        require_browser_or_skip(None, require=True)
        require_browser_or_skip(None, require=False)

    def test_without_a_browser_the_gate_skips_with_the_reason_by_default(self):
        with self.assertRaisesRegex(unittest.SkipTest, "binary is unavailable"):
            require_browser_or_skip("Playwright browser binary is unavailable: Error", require=False)

    def test_without_a_browser_the_gate_fails_when_the_environment_requires_one(self):
        with self.assertRaisesRegex(AssertionError, "no usable browser: Playwright optional dependency"):
            require_browser_or_skip("Playwright optional dependency is not installed", require=True)

    def test_the_environment_variable_selects_the_mode(self):
        with patch.dict(os.environ, {BROWSER_GATE: "1"}):
            with self.assertRaises(AssertionError):
                require_browser_or_skip("missing")
        with patch.dict(os.environ, {BROWSER_GATE: ""}):
            with self.assertRaises(unittest.SkipTest):
                require_browser_or_skip("missing")

    def test_the_probe_runs_once_and_reports_a_reason_or_none(self):
        saved = list(support._BROWSER_PROBE)
        try:
            support._BROWSER_PROBE[:] = []
            first = browser_problem()
            self.assertTrue(first is None or isinstance(first, str))
            self.assertEqual(browser_problem(), first)
            self.assertEqual(len(support._BROWSER_PROBE), 1, "the browser must be probed only once per process")
        finally:
            support._BROWSER_PROBE[:] = saved


if __name__ == "__main__":
    unittest.main()
