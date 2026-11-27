"""Shared runtime helpers: executable lookup and child-process text encoding.

The original call sites decided "is this a path?" with ``"/" in value``: a Windows path was treated as
a bare name, and anything containing ``/`` skipped every check and was returned unverified, so a typo'd
or non-executable path was reported as found. ``resolve_executable`` replaces five divergent copies.
"""
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.runtime import CHILD_TEXT_ENCODING, resolve_executable
from tests.support import finalize_fake_cli


class ResolveExecutableTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def fake(self, name="fake-cli") -> str:
        script = self.dir / name
        script.write_text("#!%s\nprint('ok')\n" % sys.executable, encoding="utf-8")
        return finalize_fake_cli(script)

    def test_an_explicit_path_to_an_executable_is_resolved(self):
        command = self.fake()
        self.assertTrue(os.path.samefile(resolve_executable(command), command))

    def test_an_explicit_path_that_does_not_exist_is_not_reported_as_found(self):
        self.assertIsNone(resolve_executable(str(self.dir / "no-such-cli")))
        # a forward slash used to short-circuit every check and return the value unverified
        self.assertIsNone(resolve_executable((self.dir / "no-such-cli").as_posix()))
        self.assertIsNone(resolve_executable("./definitely/not/here"))

    def test_a_directory_is_not_an_executable(self):
        self.assertIsNone(resolve_executable(str(self.dir)))
        self.assertIsNone(resolve_executable(self.dir.as_posix()))

    @unittest.skipIf(os.name == "nt", "execute permission bits do not decide executability on Windows")
    def test_a_file_without_execute_permission_is_not_executable(self):
        plain = self.dir / "plain.txt"
        plain.write_text("data", encoding="utf-8")
        plain.chmod(stat.S_IRUSR | stat.S_IWUSR)
        self.assertIsNone(resolve_executable(str(plain)))

    def test_a_bare_name_is_searched_on_path_only(self):
        command = self.fake("path-cli")
        launcher = Path(command)
        with patch.dict(os.environ, {"PATH": str(self.dir) + os.pathsep + os.environ.get("PATH", "")}):
            found = resolve_executable(launcher.stem if os.name == "nt" else launcher.name)
        self.assertIsNotNone(found)
        self.assertTrue(os.path.samefile(found, command))
        with patch.dict(os.environ, {"PATH": ""}):
            self.assertIsNone(resolve_executable("path-cli"))

    def test_empty_blank_nul_and_non_string_values_are_rejected(self):
        for bad in ("", "   ", "claude\x00evil", None, 7, b"claude", ["claude"]):
            with self.subTest(value=repr(bad)):
                self.assertIsNone(resolve_executable(bad))

    def test_the_interpreter_itself_resolves_by_absolute_path(self):
        self.assertTrue(os.path.samefile(resolve_executable(sys.executable), sys.executable))


class ChildEncodingTests(unittest.TestCase):
    def test_non_ascii_text_survives_a_child_process_regardless_of_the_locale_code_page(self):
        text = "café → 日本語 \U0001f512"
        code = "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"
        result = subprocess.run([sys.executable, "-c", code], input=text, capture_output=True, text=True,
                                check=True, **CHILD_TEXT_ENCODING)
        self.assertEqual(result.stdout, text)

    def test_undecodable_child_output_is_replaced_not_raised(self):
        code = "import sys; sys.stdout.buffer.write(b'ok \\xff\\xfe done')"
        result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True,
                                **CHILD_TEXT_ENCODING)
        self.assertIn("ok", result.stdout)
        self.assertIn("done", result.stdout)
        self.assertIn("�", result.stdout)

    def test_the_encoding_is_explicit_utf8(self):
        self.assertEqual(CHILD_TEXT_ENCODING["encoding"], "utf-8")
        self.assertEqual(CHILD_TEXT_ENCODING["errors"], "replace")


if __name__ == "__main__":
    unittest.main()
