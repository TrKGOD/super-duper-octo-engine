import os
import tempfile
import unittest
from pathlib import Path

from core.pathsafe import PathSafetyError, is_link_like, resolve_within, safe_component
from tests.support import make_dir_link


class LinkDetectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        # remove directory redirects first so cleanup never follows them
        for entry in self.root.iterdir():
            if is_link_like(entry):
                try:
                    entry.unlink()
                except (PermissionError, IsADirectoryError):
                    os.rmdir(entry)
        self.tmp.cleanup()

    def test_plain_directory_and_file_are_not_links(self):
        (self.root / "dir").mkdir()
        (self.root / "file.txt").write_text("x", encoding="utf-8")
        self.assertFalse(is_link_like(self.root / "dir"))
        self.assertFalse(is_link_like(self.root / "file.txt"))
        self.assertFalse(is_link_like(self.root / "does-not-exist"))

    def test_symlink_or_junction_redirect_is_detected(self):
        target = self.root / "target"
        target.mkdir()
        link = self.root / "link"
        kind = make_dir_link(link, target)
        self.assertIn(kind, {"symlink", "junction"})
        # The regression: on Windows an unprivileged redirect is a junction, which
        # Path.is_symlink() reports as False. is_link_like must still catch it.
        self.assertTrue(is_link_like(link), "redirect (" + kind + ") was not detected")


class ComponentAndContainmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)

    def tearDown(self):
        for entry in self.base.iterdir():
            if is_link_like(entry):
                try:
                    entry.unlink()
                except (PermissionError, IsADirectoryError):
                    os.rmdir(entry)
        self.tmp.cleanup()

    def test_safe_component_accepts_plain_identifiers(self):
        for value in ("eng-1", "wrk_ab12", "a.b-c_d"):
            self.assertEqual(safe_component(value), value)

    def test_safe_component_rejects_traversal_and_separators(self):
        for value in ("..", "../x", "a/b", "a\b", "C:evil", "", ".hidden", "-flag", "a\x00b",
                      "x" * 200, None, 7, "a..b"):
            with self.assertRaises(PathSafetyError, msg=repr(value)):
                safe_component(value)

    def test_resolve_within_returns_path_inside_base(self):
        (self.base / "eng-1").mkdir()
        self.assertEqual(resolve_within(self.base, "eng-1", "wrk"), self.base / "eng-1" / "wrk")

    def test_resolve_within_rejects_escape_components(self):
        with self.assertRaises(PathSafetyError):
            resolve_within(self.base, "..")
        with self.assertRaises(PathSafetyError):
            resolve_within(self.base, "eng-1/../../etc")

    def test_resolve_within_rejects_a_planted_redirect(self):
        outside = self.base / "outside"
        outside.mkdir()
        make_dir_link(self.base / "eng-evil", outside)
        with self.assertRaises(PathSafetyError):
            resolve_within(self.base, "eng-evil", "wrk")


if __name__ == "__main__":
    unittest.main()
