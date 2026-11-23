import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class GitignoreSecurityTests(unittest.TestCase):
    def is_ignored(self, path):
        result = subprocess.run(
            ["git", "check-ignore", "--no-index", "-q", path],
            cwd=ROOT,
            check=False,
        )
        self.assertIn(result.returncode, (0, 1), "git check-ignore failed")
        return result.returncode == 0

    def test_local_engagement_config_is_ignored(self):
        self.assertTrue(self.is_ignored("config/engagement.local.json"))

    def test_other_engagement_configs_are_ignored(self):
        self.assertTrue(self.is_ignored("config/engagement.client-acme.json"))

    def test_example_engagement_config_remains_trackable(self):
        self.assertFalse(self.is_ignored("config/engagement.example.json"))


if __name__ == "__main__":
    unittest.main()
