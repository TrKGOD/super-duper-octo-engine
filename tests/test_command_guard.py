import ast
import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from contextlib import closing, redirect_stdout
from unittest.mock import patch

from hooks.command_guard import KB_ALLOWED_SUBCOMMANDS, active_surface_args, active_security_args, passive_framing_args, allowed_argv, main, orchestrator_args, safe_local_json, safe_db_argument


class CommandGuardTests(unittest.TestCase):
    def test_allows_local_workflow_commands(self):
        self.assertTrue(allowed_argv(["python3", "scripts/migrate.py", "--db", ".local/state.sqlite3"]))
        self.assertTrue(allowed_argv(["python3", "scripts/workflow.py", "--db", ".local/state.sqlite3", "start", "--task-id", "task_1"]))
        self.assertTrue(allowed_argv(["python3", "scripts/workflow.py", "--db", ".local/state.sqlite3", "handoff", "--task-id", "task_1", "--file", ".local/handoff.json"]))

    def test_active_http_broker_is_the_only_network_command(self):
        valid = ["python3", "scripts/active_http.py", "--db", ".local/state.sqlite3",
                 "--engagement-id", "eng-1", "--task-id", "task-1",
                 "--request-file", ".local/requests/request-1.json"]
        self.assertTrue(allowed_argv(valid))
        self.assertFalse(allowed_argv(valid[:-1] + [".local/other/request.json"]))
        self.assertFalse(allowed_argv(valid + ["--extra", "value"]))

    def test_surface_discovery_is_an_explicit_guarded_command(self):
        command = ["python3", "scripts/active_surface.py", "--db", ".local/state.sqlite3",
                   "--engagement-id", "eng-1", "--task-id", "task-1",
                   "--target-url", "https://app.example.test/", "--max-pages", "20", "--max-depth", "2"]
        self.assertTrue(allowed_argv(command))
        self.assertIsNotNone(active_surface_args(command))
        self.assertFalse(allowed_argv(command + ["--extra"]))

    def test_surface_discovery_accepts_only_environment_backed_auth_references(self):
        command = ["python3", "scripts/active_surface.py", "--db", ".local/state.sqlite3",
                   "--engagement-id", "eng-1", "--task-id", "task-1",
                   "--target-url", "https://app.example.test/", "--max-pages", "20", "--max-depth", "2",
                   "--secret-header", "Cookie=TEST_COOKIE", "--secret-header", "X-CSRF-Token=TEST_CSRF",
                   "--user-agent", "Synthetic Browser/1.0"]
        self.assertTrue(allowed_argv(command))
        self.assertFalse(allowed_argv(command + ["--secret-header", "Cookie=OTHER_COOKIE"]))
        bad = command.copy()
        bad[15] = "Cookie=literal-secret"
        self.assertFalse(allowed_argv(bad))

    def test_specialist_security_commands_are_allowlisted_only_with_strict_pinned_manifest_shapes(self):
        ssrf = ["python3", "scripts/active_ssrf_probe.py", "--db", ".local/state.sqlite3",
                "--engagement-id", "eng-123", "--task-id", "task-123",
                "--request-file", ".local/requests/ssrf-001.json",
                "--callback-url", "https://callback.example.test/canary",
                "--marker", "marker-unique-1234"]
        auth = ["python3", "scripts/active_authentication_check.py", "--db", ".local/state.sqlite3",
                "--engagement-id", "eng-123", "--task-id", "task-123",
                "--authenticated-request-file", ".local/requests/auth-001.json",
                "--anonymous-request-file", ".local/requests/auth-002.json",
                "--protected-resource", "/account"]
        cache = ["python3", "scripts/active_cache_check.py", "--db", ".local/state.sqlite3",
                 "--engagement-id", "eng-123", "--task-id", "task-123",
                 "--first-request-file", ".local/requests/cache-001.json",
                 "--second-request-file", ".local/requests/cache-002.json",
                 "--first-private-marker", "private-a", "--second-private-marker", "private-b"]
        for command in (ssrf, auth, cache):
            self.assertTrue(allowed_argv(command))
            self.assertIsNotNone(active_security_args(command))
        self.assertFalse(allowed_argv(ssrf[:-2] + ["--marker", "short"]))
        self.assertFalse(allowed_argv(auth[:-3] + ["--protected-resource", "/account", "--extra"]))
        self.assertFalse(allowed_argv(cache[:-5] + ["--first-private-marker", "a", "--second-private-marker", "private-b"]))

    def test_specialist_security_commands_reject_unpinned_paths_and_non_https_callback(self):
        command = ["python3", "scripts/active_ssrf_probe.py", "--db", ".local/state.sqlite3",
                   "--engagement-id", "eng-123", "--task-id", "task-123",
                   "--request-file", "../request.json", "--callback-url", "http://callback.example.test/",
                   "--marker", "marker-unique-1234"]
        self.assertFalse(allowed_argv(command))
        command[9] = ".local/requests/ssrf-001.json"
        self.assertFalse(allowed_argv(command))


    def test_passive_framing_review_only_reads_local_json(self):
        command = ["python3", "scripts/analyze_http_framing.py", "--input", ".local/http-capture.json"]
        self.assertTrue(allowed_argv(command))
        self.assertEqual(passive_framing_args(command), {"input": ".local/http-capture.json"})
        self.assertFalse(allowed_argv(command[:-1] + ["/etc/passwd"]))
        self.assertFalse(allowed_argv(command[:-1] + ["../capture.json"]))
        race = ["python3", "scripts/analyze_race_capture.py", "--input", ".local/race-capture.json"]
        self.assertTrue(allowed_argv(race))
        self.assertFalse(allowed_argv(race[:-1] + ["/tmp/race.json"]))


    def test_per_engagement_database_paths_are_strictly_mapped(self):
        self.assertTrue(safe_db_argument(".local/state.sqlite3"))
        self.assertTrue(safe_db_argument(".local/engagements/vinted/state.sqlite3"))
        self.assertFalse(safe_db_argument(".local/engagements/../state.sqlite3"))
        self.assertFalse(safe_db_argument("/tmp/state.sqlite3"))

    def test_orchestrator_entrypoint_is_allowlisted_with_exact_arguments(self):
        command = ["python3", "scripts/run_orchestrator.py", "--db", ".local/state.sqlite3",
                   "--engagement-id", "eng-123", "--model", "claude-sonnet-4-5"]
        self.assertTrue(allowed_argv(command))
        self.assertEqual(orchestrator_args(command)["engagement_id"], "eng-123")
        self.assertFalse(allowed_argv(command + ["--extra"]))

    def test_rejects_arbitrary_commands(self):
        self.assertFalse(allowed_argv(["python3", "-c", "import os"]))
        self.assertFalse(allowed_argv(["nmap", "app.example.test"]))
        self.assertFalse(allowed_argv(["python3", "scripts/workflow.py", "--db", "/tmp/db", "status", "--engagement-id", "e"]))

    def test_active_database_state_blocks_workflow_mutations_even_if_local_config_is_false(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".local").mkdir()
            config = root / "engagement.local.json"
            config.write_text(json.dumps({
                "engagement_id": "eng-active",
                "rules_of_engagement": {"execution_enabled": False},
            }), encoding="utf-8")
            # sqlite3's own context manager only commits; it never closes the connection, which
            # on Windows keeps the file locked and breaks temp-dir cleanup. Close explicitly.
            with closing(sqlite3.connect(root / ".local" / "state.sqlite3")) as connection:
                connection.execute(
                    "CREATE TABLE engagements (engagement_id TEXT PRIMARY KEY, status TEXT)"
                )
                connection.execute(
                    "INSERT INTO engagements VALUES (?, ?)", ("eng-active", "active")
                )
                connection.commit()
            payload = {"tool_input": {
                "command": "python3 scripts/workflow.py --db .local/state.sqlite3 start --task-id task_1"
            }}
            output = io.StringIO()
            with patch("hooks.command_guard.ROOT", root), \
                 patch("hooks.command_guard.CONFIG", config), \
                 patch("hooks.command_guard.DB", ".local/state.sqlite3"), \
                 patch("sys.stdin", io.StringIO(json.dumps(payload))):
                with redirect_stdout(output):
                    with self.assertRaises(SystemExit):
                        main()
            self.assertIn('"permissionDecision": "deny"', output.getvalue())

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


class LinkAndJunctionGuardTests(unittest.TestCase):
    """``Path.is_symlink()`` is False for a Windows junction (``mklink /J``, no privilege needed), so a junction at
    ``.local`` used to pass the guard. The hook keeps a self-contained copy of the helper (it must not import project
    code: a crashed hook does not block the call), and these tests pin that copy to ``core.pathsafe``."""

    VALID = ["python3", "scripts/active_http.py", "--db", ".local/state.sqlite3", "--engagement-id", "eng-1",
             "--task-id", "task-1", "--request-file", ".local/requests/request-1.json"]

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.elsewhere = self.root / "elsewhere"
        self.elsewhere.mkdir()
        self.config = self.root / "engagement.local.json"
        self.config.write_text("{}", encoding="utf-8")

    def patched(self):
        from contextlib import ExitStack
        stack = ExitStack()
        stack.enter_context(patch("hooks.command_guard.ROOT", self.root))
        stack.enter_context(patch("hooks.command_guard.CONFIG", self.config))
        stack.enter_context(patch("hooks.command_guard.DB", ".local/state.sqlite3"))
        return stack

    def test_the_hooks_copy_agrees_with_the_core_helper(self):
        from core.pathsafe import is_link_like
        from hooks.command_guard import _is_link_like
        from tests.support import make_dir_link
        regular_dir = self.root / "dir"
        regular_dir.mkdir()
        regular_file = self.root / "file.txt"
        regular_file.write_text("x", encoding="utf-8")
        link = self.root / "link"
        make_dir_link(link, self.elsewhere)
        for path in (regular_dir, regular_file, link, self.root / "missing", self.root / "link" / "child"):
            with self.subTest(path=path.name):
                self.assertEqual(_is_link_like(path), is_link_like(path))
        self.assertTrue(_is_link_like(link))
        self.assertFalse(_is_link_like(regular_dir))

    def test_a_linked_state_directory_is_refused_and_a_real_one_is_accepted(self):
        from hooks.command_guard import safe_db_argument
        from tests.support import make_dir_link
        with self.patched():
            (self.root / ".local").mkdir()
            self.assertTrue(safe_db_argument(".local/state.sqlite3"))
            self.assertTrue(allowed_argv(self.VALID))
        (self.root / ".local").rmdir()
        make_dir_link(self.root / ".local", self.elsewhere)
        with self.patched():
            self.assertFalse(safe_db_argument(".local/state.sqlite3"))
            self.assertFalse(allowed_argv(self.VALID), "a junction at .local must not pass the broker command guard")

    def test_a_linked_config_directory_is_refused(self):
        from hooks.command_guard import safe_db_argument
        from tests.support import make_dir_link
        (self.root / ".local").mkdir()
        make_dir_link(self.root / "config", self.elsewhere)
        with self.patched():
            self.assertFalse(safe_db_argument(".local/state.sqlite3"))


if __name__ == "__main__":
    unittest.main()
