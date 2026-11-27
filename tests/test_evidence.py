import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.evidence import EvidenceError, EvidenceVault
from core.store import StateStore
from scripts.migrate import migrate
from tests.support import make_dir_link


class EvidenceVaultTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = str(self.root / "state.sqlite")
        migrate(self.db)
        self.store = StateStore(self.db)
        self.store.create_engagement(
            "eng-test", "AUTH-LAB-001", {"assets": []}, {"execution_enabled": False}
        )
        self.vault = EvidenceVault(self.store, self.root, max_bytes=1024)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_capture_writes_bytes_and_records_real_sha256(self):
        payload = b"synthetic lab evidence\n"
        result = self.vault.capture(
            "eng-test", "reproduction_notes", "repro.txt", payload, "operator",
            redacted=True,
        )
        artifact = self.root / result["local_path"]
        self.assertEqual(artifact.read_bytes(), payload)
        self.assertEqual(result["sha256"], __import__("hashlib").sha256(payload).hexdigest())
        row = self.store.connection.execute(
            "SELECT sha256,redacted FROM evidence WHERE evidence_id=?",
            (result["evidence_id"],),
        ).fetchone()
        self.assertEqual(row["sha256"], result["sha256"])
        self.assertEqual(row["redacted"], 1)
        self.assertTrue(self.vault.verify(result["evidence_id"])["valid"])

    def test_aes_gcm_encryption_at_rest_and_key_required_for_read(self):
        key = bytes(range(32))
        encrypted_vault = EvidenceVault(
            self.store, self.root, max_bytes=1024, encryption_key=key
        )
        payload = b"synthetic secret-bearing evidence"
        result = encrypted_vault.capture(
            "eng-test", "reproduction_notes", "encrypted.txt", payload,
            "operator", redacted=True,
        )
        stored = (self.root / result["local_path"]).read_bytes()
        self.assertNotIn(payload, stored)
        self.assertEqual(result["encryption_algorithm"], "AES-256-GCM")
        self.assertTrue(encrypted_vault.verify(result["evidence_id"])["valid"])
        self.assertEqual(encrypted_vault.read(result["evidence_id"]), payload)
        without_key = EvidenceVault(self.store, self.root, max_bytes=1024)
        self.assertTrue(without_key.verify(result["evidence_id"])["valid"])
        with self.assertRaisesRegex(EvidenceError, "key is required"):
            without_key.read(result["evidence_id"])

    def test_tampering_is_detected(self):
        result = self.vault.capture(
            "eng-test", "log", "capture.log", b"original", "operator"
        )
        (self.root / result["local_path"]).write_bytes(b"tampered")
        verification = self.vault.verify(result["evidence_id"])
        self.assertFalse(verification["valid"])
        self.assertNotEqual(verification["expected_sha256"], verification["actual_sha256"])

    def test_the_bytes_returned_are_the_bytes_that_were_verified_even_if_the_file_changes_afterwards(self):
        """Check/use race: ``read()`` used to hash one read of the file and return a second, independent read,
        so a file swapped in between was accepted as verified evidence. One read now feeds both."""
        original = b"original verified evidence"
        result = self.vault.capture("eng-test", "log", "race.log", original, "operator")
        real_read_bytes, reads = Path.read_bytes, []

        def swap_after_first_read(path):
            reads.append(path)
            data = real_read_bytes(path)
            return data if len(reads) == 1 else b"substituted after the integrity check"

        with patch.object(Path, "read_bytes", swap_after_first_read):
            content = self.vault.read(result["evidence_id"])
            verification = self.vault.verify(result["evidence_id"])
        self.assertEqual(content, original)
        self.assertFalse(verification["valid"], "the second call re-reads the substituted file and must not validate it")
        self.assertEqual(len(reads), 2, "read() and verify() must each read the artifact exactly once")

    def test_rejects_traversal_unsupported_types_and_oversize(self):
        with self.assertRaises(EvidenceError):
            self.vault.capture("../outside", "log", "x.txt", b"x", "operator")
        with self.assertRaises(EvidenceError):
            self.vault.capture("eng-test", "log", "../../x.txt", b"x", "operator")
        with self.assertRaises(EvidenceError):
            self.vault.capture("eng-test", "log", "x.exe", b"x", "operator")
        with self.assertRaises(EvidenceError):
            self.vault.capture("eng-test", "log", "large.txt", b"x" * 1025, "operator")

    def test_rejects_symlinked_vault_root(self):
        local = self.root / ".local"
        outside = self.root / "outside"
        outside.mkdir()
        # A real symlink where permitted; an NTFS junction on unprivileged Windows. Both are
        # directory redirects the vault must refuse (is_symlink() alone misses junctions).
        make_dir_link(local, outside)
        with self.assertRaises(EvidenceError):
            self.vault.capture("eng-test", "log", "x.txt", b"x", "operator")


if __name__ == "__main__":
    unittest.main()
