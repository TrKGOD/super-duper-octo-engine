import ast
import io
import unittest
from pathlib import Path
from contextlib import redirect_stdout
from unittest.mock import patch

from hooks.command_guard import KB_ALLOWED_SUBCOMMANDS, allowed_argv, main, safe_local_json


class CommandGuardTests(unittest.TestCase):
    def test_allows_local_workflow_commands(self):
        self.assertTrue(allowed_argv(["python3", "scripts/migrate.py", "--db", ".local/state.sqlite3"]))
        self.assertTrue(allowed_argv(["python3", "scripts/workflow.py", "--db", ".local/state.sqlite3", "start", "--task-id", "task_1"]))
        self.assertTrue(allowed_argv(["python3", "scripts/workflow.py", "--db", ".local/state.sqlite3", "handoff", "--task-id", "task_1", "--file", ".local/handoff.json"]))

    def test_rejects_arbitrary_commands(self):
        self.assertFalse(allowed_argv(["python3", "-c", "import os"]))
        self.assertFalse(allowed_argv(["nmap", "app.example.test"]))
        self.assertFalse(allowed_argv(["python3", "scripts/workflow.py", "--db", "/tmp/db", "status", "--engagement-id", "e"]))

    def test_hook_defaults_to_deny_on_unparseable_input(self):
        output = io.StringIO()
        with patch("sys.stdin", io.StringIO("not-json")):
            with redirect_stdout(output):
                with self.assertRaises(SystemExit) as raised:
                    main()
        self.assertEqual(raised.exception.code, 0)
        self.assertIn('"permissionDecision": "deny"', output.getvalue())

    def test_local_json_paths_are_confined(self):
        self.assertTrue(safe_local_json(".local/plan.json"))
        self.assertFalse(safe_local_json("../plan.json"))
        self.assertFalse(safe_local_json("/tmp/plan.json"))

    def test_every_allowlisted_kb_command_exists_in_cli(self):
        source = (Path(__file__).resolve().parents[1] / 'scripts' / 'knowledge_base.py').read_text(encoding='utf-8')
        tree = ast.parse(source)
        cli = {node.args[0].value for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'add_parser' and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)}
        self.assertEqual(KB_ALLOWED_SUBCOMMANDS, cli.intersection(KB_ALLOWED_SUBCOMMANDS))
        self.assertTrue(allowed_argv(['python3', 'scripts/knowledge_base.py', '--db', '.local/knowledge-base.sqlite3', 'show', '--document-id', 'KB-' + 'A'*16]))


if __name__ == "__main__":
    unittest.main()
