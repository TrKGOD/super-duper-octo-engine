import unittest

from hooks.command_guard import allowed_argv, passive_framing_args


class ProtocolCommandGuardTests(unittest.TestCase):
    def test_offline_protocol_analyzer_is_allowlisted_for_local_json(self):
        argv = ["python3", "scripts/analyze_protocol_artifacts.py", "sqli-pair", "--input", ".local/sqli-pair.json"]
        self.assertEqual(passive_framing_args(argv), {"input": ".local/sqli-pair.json", "kind": "sqli-pair"})
        self.assertTrue(allowed_argv(argv))

    def test_protocol_analyzer_rejects_unknown_kind_and_path_traversal(self):
        self.assertFalse(allowed_argv(["python3", "scripts/analyze_protocol_artifacts.py", "exec", "--input", ".local/a.json"]))
        self.assertFalse(allowed_argv(["python3", "scripts/analyze_protocol_artifacts.py", "jwt", "--input", ".local/../secret.json"]))

    def test_existing_passive_analyzers_remain_allowlisted(self):
        self.assertTrue(allowed_argv(["python3", "scripts/analyze_http_framing.py", "--input", ".local/framing.json"]))
        self.assertTrue(allowed_argv(["python3", "scripts/analyze_race_capture.py", "--input", ".local/race.json"]))


if __name__ == "__main__":
    unittest.main()
