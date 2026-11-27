"""Local evidence artifact vault with atomic writes and SHA-256 verification.

This module stores operator-supplied bytes only. It does not collect data from targets
or perform automatic redaction.
"""
import base64
import hashlib
import os
import re
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.store import StateStore
from core.pathsafe import is_link_like


class EvidenceError(ValueError):
    """Raised when an evidence artifact cannot be safely stored or verified."""


_ALLOWED_SUFFIXES = {
    ".bin", ".csv", ".html", ".jpeg", ".jpg", ".json", ".log", ".pdf",
    ".png", ".txt", ".xml", ".yaml", ".yml",
}


class EvidenceVault:
    MAGIC = b"PTEV1"
    ENCRYPTION_ALGORITHM = "AES-256-GCM"

    def __init__(self, store: StateStore, project_root, max_bytes=25 * 1024 * 1024,
                 encryption_key=None):
        self.store = store
        self.project_root = Path(project_root).resolve()
        self.root = self.project_root / ".local" / "evidence"
        self.max_bytes = int(max_bytes)
        if self.max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        encoded_key = os.environ.get("PENTEST_EVIDENCE_KEY")
        if encryption_key is None and encoded_key:
            try:
                encryption_key = base64.b64decode(encoded_key, validate=True)
            except ValueError as exc:
                raise EvidenceError("PENTEST_EVIDENCE_KEY must be valid base64") from exc
        if encryption_key is not None and len(encryption_key) != 32:
            raise EvidenceError("Evidence encryption key must be exactly 32 bytes")
        self.encryption_key = bytes(encryption_key) if encryption_key is not None else None

    @staticmethod
    def _safe_component(value, label):
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", value):
            raise EvidenceError(label + " contains unsafe characters")
        if value in {".", ".."}:
            raise EvidenceError(label + " is invalid")
        return value

    def _ensure_root(self):
        local_dir = self.project_root / ".local"
        if is_link_like(local_dir):
            raise EvidenceError(".local must not be a symlink")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if is_link_like(self.root) or not self.root.resolve().is_relative_to(self.project_root):
            raise EvidenceError("Evidence directory escapes the project root")
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass

    def capture(
        self, engagement_id, evidence_type, filename, content, captured_by,
        redacted=False, execution_id=None, task_id=None,
    ):
        """Persist already-collected bytes; caller is responsible for prior redaction."""
        engagement_id = self._safe_component(engagement_id, "engagement_id")
        if not isinstance(filename, str) or Path(filename).name != filename or "/" in filename or chr(92) in filename:
            raise EvidenceError("filename must be a plain file name without path components")
        filename = self._safe_component(filename, "filename")
        suffix = Path(filename).suffix.lower()
        if suffix not in _ALLOWED_SUFFIXES:
            raise EvidenceError("Unsupported evidence file extension: " + (suffix or "<none>"))
        if not isinstance(content, (bytes, bytearray, memoryview)):
            raise EvidenceError("content must be bytes-like")
        payload = bytes(content)
        if not payload:
            raise EvidenceError("Empty evidence artifacts are not accepted")
        if len(payload) > self.max_bytes:
            raise EvidenceError("Evidence artifact exceeds max_bytes")
        if not isinstance(redacted, bool):
            raise EvidenceError("redacted must be an explicit boolean")

        self._ensure_root()
        engagement_dir = self.root / engagement_id
        engagement_dir.mkdir(mode=0o700, exist_ok=True)
        if is_link_like(engagement_dir) or not engagement_dir.resolve().is_relative_to(self.root.resolve()):
            raise EvidenceError("Engagement evidence directory escapes the vault")

        encryption_algorithm = "none"
        stored_payload = payload
        if self.encryption_key is not None:
            nonce = os.urandom(12)
            stored_payload = self.MAGIC + nonce + AESGCM(self.encryption_key).encrypt(
                nonce, payload, engagement_id.encode("utf-8")
            )
            encryption_algorithm = self.ENCRYPTION_ALGORITHM
        digest = hashlib.sha256(stored_payload).hexdigest()
        fd, temporary_name = tempfile.mkstemp(prefix=".capture-", dir=str(engagement_dir))
        temporary_path = Path(temporary_name)
        final_path = engagement_dir / (digest + suffix)
        relative_path = final_path.relative_to(self.project_root).as_posix()
        try:
            if hasattr(os, "fchmod"):  # not available on Windows before Python 3.13
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(stored_payload)
                stream.flush()
                os.fsync(stream.fileno())
            if final_path.exists() and is_link_like(final_path):
                raise EvidenceError("Evidence destination must not be a symlink")
            os.replace(temporary_path, final_path)
            evidence_id = self.store.record_evidence(
                engagement_id, evidence_type, relative_path, captured_by,
                sha256=digest, redacted=redacted,
                encryption_algorithm=encryption_algorithm,
                execution_id=execution_id, task_id=task_id,
            )
            return {
                "evidence_id": evidence_id,
                "local_path": relative_path,
                "sha256": digest,
                "size_bytes": len(stored_payload),
                "plaintext_size_bytes": len(payload),
                "encryption_algorithm": encryption_algorithm,
                "redacted": redacted,
                "execution_id": execution_id,
            }
        except Exception:
            try:
                temporary_path.unlink(missing_ok=True)
            finally:
                # Remove the artifact only if no DB row successfully registered it.
                row = self.store.connection.execute(
                    "SELECT 1 FROM evidence WHERE local_path=? AND sha256=?",
                    (relative_path, digest),
                ).fetchone()
                if row is None:
                    final_path.unlink(missing_ok=True)
            raise

    def _load(self, evidence_id):
        """Read an artifact exactly once and verify *that same buffer*.

        ``verify()`` and ``read()`` previously hashed one read of the file and then used a
        second, independent read, so an attacker able to swap the file between the two reads
        got unverified bytes accepted as verified evidence (a check/use race). Every consumer
        now works from the single buffer that was hashed.
        """
        row = self.store.connection.execute(
            """SELECT engagement_id,local_path,sha256,encryption_algorithm FROM evidence
               WHERE evidence_id=?""",
            (evidence_id,),
        ).fetchone()
        if row is None:
            raise EvidenceError("Unknown evidence ID: " + str(evidence_id))
        relative = Path(row["local_path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise EvidenceError("Stored evidence path is invalid")
        candidate = self.project_root / relative
        if is_link_like(candidate):
            raise EvidenceError("Evidence artifact must not be a symlink")
        resolved = candidate.resolve(strict=True)
        vault_root = self.root.resolve(strict=True)
        if not resolved.is_relative_to(vault_root) or not resolved.is_file():
            raise EvidenceError("Evidence artifact is outside the vault or is not a file")
        raw = resolved.read_bytes()
        actual = hashlib.sha256(raw).hexdigest()
        expected = row["sha256"]
        if row["encryption_algorithm"] == self.ENCRYPTION_ALGORITHM and not raw.startswith(self.MAGIC):
            raise EvidenceError("Encrypted evidence header is invalid")
        integrity = {
            "evidence_id": evidence_id,
            "encryption_algorithm": row["encryption_algorithm"],
            "valid": bool(expected and actual == expected),
            "expected_sha256": expected,
            "actual_sha256": actual,
            "size_bytes": len(raw),
        }
        return row, raw, integrity

    def verify(self, evidence_id):
        return self._load(evidence_id)[2]

    def read(self, evidence_id):
        """Return verified plaintext bytes; encrypted artifacts require the external key."""
        row, raw, integrity = self._load(evidence_id)
        if not integrity["valid"]:
            raise EvidenceError("Evidence SHA-256 verification failed")
        if row["encryption_algorithm"] == "none":
            return raw
        if row["encryption_algorithm"] != self.ENCRYPTION_ALGORITHM:
            raise EvidenceError("Unsupported evidence encryption algorithm")
        if self.encryption_key is None:
            raise EvidenceError("Evidence encryption key is required to decrypt this artifact")
        if not raw.startswith(self.MAGIC) or len(raw) < len(self.MAGIC) + 12 + 16:
            raise EvidenceError("Encrypted evidence payload is malformed")
        nonce_start = len(self.MAGIC)
        nonce = raw[nonce_start:nonce_start + 12]
        ciphertext = raw[nonce_start + 12:]
        try:
            return AESGCM(self.encryption_key).decrypt(
                nonce, ciphertext, row["engagement_id"].encode("utf-8")
            )
        except Exception as exc:
            raise EvidenceError("Evidence decryption failed; key or ciphertext is invalid") from exc
