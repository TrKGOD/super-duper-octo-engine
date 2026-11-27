"""Request-manifest loading: the one implementation shared by the security and authorization runners.

Three copies of this routine used to exist with slightly different checks. Loading proves nothing about a
manifest's content (scope, approval and the SHA-256 pin belong to the broker); it must only guarantee that
the file read is a bounded, regular JSON object inside ``.local/requests/`` reached without any link.
"""
import json
import tempfile
import unittest
from pathlib import Path

from core.active_executor import ActiveExecutionError
from core.manifests import MAX_MANIFEST_BYTES, load_request_manifest
from tests.support import make_dir_link


class ManifestLoaderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.requests = self.root / ".local" / "requests"
        self.requests.mkdir(parents=True)

    def write(self, name, data: bytes) -> str:
        (self.requests / name).write_bytes(data)
        return f".local/requests/{name}"

    def test_a_regular_json_object_inside_the_requests_directory_loads(self):
        relative = self.write("a.json", json.dumps({"request_id": "r1", "method": "GET"}).encode())
        self.assertEqual(load_request_manifest(self.root, relative), {"request_id": "r1", "method": "GET"})

    def test_paths_outside_the_requests_directory_are_refused(self):
        (self.root / "config").mkdir()
        (self.root / "config" / "x.json").write_text("{}", encoding="utf-8")
        (self.root / ".local" / "other").mkdir()
        (self.root / ".local" / "other" / "x.json").write_text("{}", encoding="utf-8")
        outside = (self.root.parent / "outside.json")
        for bad in (str(outside), str(self.requests / "a.json"), "config/x.json", ".local/other/x.json",
                    ".local/requests/../other/x.json", "../outside.json", ".local", ".local/requests"):
            with self.subTest(path=bad):
                with self.assertRaises((ActiveExecutionError, OSError)):
                    load_request_manifest(self.root, bad)

    def test_a_linked_requests_directory_is_refused(self):
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "m.json").write_text('{"request_id": "smuggled"}', encoding="utf-8")
        self.requests.rmdir()
        make_dir_link(self.requests, elsewhere)
        with self.assertRaisesRegex(ActiveExecutionError, "symlinks or junctions"):
            load_request_manifest(self.root, ".local/requests/m.json")

    def test_the_size_limit_is_exact_and_an_unbounded_file_is_never_read(self):
        def padded(size):
            base = json.dumps({"p": ""}).encode()
            return json.dumps({"p": "a" * (size - len(base))}).encode()
        exact = padded(MAX_MANIFEST_BYTES)
        self.assertEqual(len(exact), MAX_MANIFEST_BYTES)
        self.assertEqual(len(load_request_manifest(self.root, self.write("exact.json", exact))["p"]),
                         MAX_MANIFEST_BYTES - len(json.dumps({"p": ""})))
        with self.assertRaisesRegex(ActiveExecutionError, "exceeds 64 KiB"):
            load_request_manifest(self.root, self.write("big.json", padded(MAX_MANIFEST_BYTES + 1)))
        with self.assertRaisesRegex(ActiveExecutionError, "exceeds 64 KiB"):
            load_request_manifest(self.root, self.write("huge.json", b" " * (MAX_MANIFEST_BYTES * 20)))

    def test_malformed_content_is_refused(self):
        cases = {"bad_utf8.json": (b'{"a": "\xff\xfe"}', "UTF-8 JSON"), "bad_json.json": (b"{not json", "UTF-8 JSON"),
                 "array.json": (b"[1, 2]", "JSON object"), "scalar.json": (b'"text"', "JSON object"),
                 "empty.json": (b"", "UTF-8 JSON")}
        for name, (payload, message) in cases.items():
            with self.subTest(file=name):
                with self.assertRaisesRegex(ActiveExecutionError, message):
                    load_request_manifest(self.root, self.write(name, payload))

    def test_a_missing_manifest_is_an_error(self):
        with self.assertRaises((ActiveExecutionError, OSError)):
            load_request_manifest(self.root, ".local/requests/absent.json")

    def test_a_directory_is_not_a_manifest(self):
        (self.requests / "folder.json").mkdir()
        with self.assertRaises((ActiveExecutionError, OSError)):
            load_request_manifest(self.root, ".local/requests/folder.json")

    def test_errors_carry_the_callers_label(self):
        with self.assertRaisesRegex(ActiveExecutionError, "^Authorization manifests must be confined"):
            load_request_manifest(self.root, "config/x.json", label="Authorization")


if __name__ == "__main__":
    unittest.main()
