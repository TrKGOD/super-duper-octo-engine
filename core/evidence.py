"""Local evidence artifact vault with atomic writes and SHA-256 verification.

This module stores operator-supplied bytes only. It does not collect data from targets
or perform automatic redaction.
"""
import hashlib
import os
import re
import tempfile
from pathlib import Path

from core.store import StateStore


class EvidenceError(ValueError):
    """Raised when an evidence artifact cannot be safely stored or verified."""


_ALLOWED_SUFFIXES = {
    ".bin", ".csv", ".html", ".jpeg", ".jpg", ".json", ".log", ".pdf",
    ".png", ".txt", ".xml", ".yaml", ".yml",
}


class EvidenceVault:
    def __init__(self, store: StateStore, project_root, max_bytes=25 * 1024 * 1024):
        self.store = store
        self.project_root = Path(project_root).resolve()
        self.root = self.project_root / ".local" / "evidence"
        self.max_bytes = int(max_bytes)
        if self.max_bytes <= 0:
            raise ValueError("max_bytes must be positive")

    @staticmethod
    def _safe_component(value, label):
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", value):
            raise EvidenceError(label + " contains unsafe characters")
        if value in {".", ".."}:
            raise EvidenceError(label + " is invalid")
        return value

    def _ensure_root(self):
        local_dir = self.project_root / ".local"
        if local_dir.is_symlink():
            raise EvidenceError(".local must not be a symlink")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.root.is_symlink() or not self.root.resolve().is_relative_to(self.project_root):
            raise EvidenceError("Evidence directory escapes the project root")
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass

    def capture(
        self, engagement_id, evidence_type, filename, content, captured_by,
        redacted=False,
    ):
        """Persist already-collected bytes; caller is responsible for prior redaction."""
        engagement_id = self._safe_component(engagement_id, "engagement_id")
        filename = self._safe_component(Path(filename).name, "filename")
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
        if engagement_dir.is_symlink() or not engagement_dir.resolve().is_relative_to(self.root.resolve()):
            raise EvidenceError("Engagement evidence directory escapes the vault")

        digest = hashlib.sha256(payload).hexdigest()
        fd, temporary_name = tempfile.mkstemp(prefix=".capture-", dir=str(engagement_dir))
        temporary_path = Path(temporary_name)
        final_path = engagement_dir / (digest + suffix)
        relative_path = final_path.relative_to(self.project_root).as_posix()
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            if final_path.exists() and final_path.is_symlink():
                raise EvidenceError("Evidence destination must not be a symlink")
            os.replace(temporary_path, final_path)
            evidence_id = self.store.record_evidence(
                engagement_id, evidence_type, relative_path, captured_by,
                sha256=digest, redacted=redacted,
            )
            return {
                "evidence_id": evidence_id,
                "local_path": relative_path,
                "sha256": digest,
                "size_bytes": len(payload),
                "redacted": redacted,
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

    def verify(self, evidence_id):
        row = self.store.connection.execute(
            """SELECT engagement_id,local_path,sha256 FROM evidence
               WHERE evidence_id=?""",
            (evidence_id,),
        ).fetchone()
        if row is None:
            raise EvidenceError("Unknown evidence ID: " + str(evidence_id))
        relative = Path(row["local_path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise EvidenceError("Stored evidence path is invalid")
        candidate = self.project_root / relative
        if candidate.is_symlink():
            raise EvidenceError("Evidence artifact must not be a symlink")
        resolved = candidate.resolve(strict=True)
        vault_root = self.root.resolve(strict=True)
        if not resolved.is_relative_to(vault_root) or not resolved.is_file():
            raise EvidenceError("Evidence artifact is outside the vault or is not a file")
        actual = hashlib.sha256(resolved.read_bytes()).hexdigest()
        expected = row["sha256"]
        return {
            "evidence_id": evidence_id,
            "valid": bool(expected and actual == expected),
            "expected_sha256": expected,
            "actual_sha256": actual,
            "size_bytes": resolved.stat().st_size,
        }
