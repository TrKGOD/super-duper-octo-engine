"""Encrypted, engagement-scoped session and identity storage.

Key provisioning
    The vault key is supplied out-of-band via ``WITHERHOARD_AUTH_VAULT_KEY`` (a Fernet key;
    the legacy name ``HACKBOT_AUTH_VAULT_KEY`` is still honoured). It must never be written to
    the repository, the database or a process argument.

Key rotation
    The variable (or the ``key`` argument) may hold several comma-separated Fernet keys. The
    **first** key encrypts; **every** key can decrypt. To rotate: prepend the new key, call
    :meth:`SessionStore.rotate_keys` to re-encrypt every stored session under it, then drop
    the old key from the list.

Isolation
    Sessions are looked up by ``(session_id, engagement_id, identity_id)``. In addition each
    ciphertext carries those three values *inside* the encrypted envelope and they are
    re-checked on decrypt, so a row copied or edited at the database level cannot be replayed
    under a different engagement or identity (Fernet has no associated-data input of its own).

No plaintext credential/session material is written to SQLite or audit logs.
"""
import json
import os
import re
import sqlite3
import time
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

KEY_ENV = "WITHERHOARD_AUTH_VAULT_KEY"
LEGACY_KEY_ENV = "HACKBOT_AUTH_VAULT_KEY"
_ENVELOPE_VERSION = 2


class SessionStoreError(RuntimeError):
    pass


def _build_cipher(raw_key):
    if isinstance(raw_key, (bytes, bytearray)):
        raw_key = bytes(raw_key).decode("ascii", "strict")
    keys = [item.strip() for item in str(raw_key).split(",") if item.strip()]
    if not keys:
        raise SessionStoreError("Invalid authentication vault key")
    try:
        return MultiFernet([Fernet(item.encode("ascii")) for item in keys])
    except (ValueError, TypeError, UnicodeError) as exc:
        raise SessionStoreError("Invalid authentication vault key") from exc


class SessionStore:
    def __init__(self, db_path, key=None):
        raw_key = key or os.environ.get(KEY_ENV) or os.environ.get(LEGACY_KEY_ENV)
        if not raw_key:
            raise SessionStoreError(KEY_ENV + " must be provisioned out-of-band")
        self._cipher = _build_cipher(raw_key)
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.db_path, timeout=5)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS auth_identities (
          engagement_id TEXT NOT NULL, identity_id TEXT NOT NULL, adapter TEXT NOT NULL,
          config_json TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
          PRIMARY KEY (engagement_id, identity_id));
        CREATE TABLE IF NOT EXISTS auth_sessions (
          session_id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL, identity_id TEXT NOT NULL,
          state TEXT NOT NULL, encrypted_material BLOB NOT NULL, expires_at REAL,
          created_at REAL NOT NULL, updated_at REAL NOT NULL,
          FOREIGN KEY (engagement_id, identity_id)
            REFERENCES auth_identities(engagement_id, identity_id));
        CREATE INDEX IF NOT EXISTS idx_auth_sessions_identity
          ON auth_sessions(engagement_id, identity_id, updated_at);
        """)
        self.db.commit()

    def close(self):
        self.db.close()

    # -- sealing -----------------------------------------------------------------------
    @staticmethod
    def _binding(session_id, engagement_id, identity_id):
        return {"session_id": session_id, "engagement_id": engagement_id, "identity_id": identity_id}

    def _seal(self, session_id, engagement_id, identity_id, material):
        envelope = {"v": _ENVELOPE_VERSION,
                    "bind": self._binding(session_id, engagement_id, identity_id),
                    "material": material}
        return self._cipher.encrypt(json.dumps(envelope, sort_keys=True).encode())

    def _open(self, token, session_id, engagement_id, identity_id):
        try:
            data = json.loads(self._cipher.decrypt(token))
        except (InvalidToken, ValueError) as exc:
            raise SessionStoreError("Session vault integrity check failed") from exc
        if isinstance(data, dict) and data.get("v") == _ENVELOPE_VERSION:
            if data.get("bind") != self._binding(session_id, engagement_id, identity_id):
                raise SessionStoreError("Session vault binding check failed")
            return data.get("material", {})
        # Legacy payload written before binding existed: the lookup key is its only binding.
        # It is re-sealed with a binding the next time the session is written.
        return data

    # -- identities --------------------------------------------------------------------
    def register_identity(self, engagement_id, identity_id, adapter, config):
        if not engagement_id or not identity_id or len(identity_id) > 100:
            raise SessionStoreError("Invalid engagement or identity identifier")
        # Config may contain environment-variable references, never literal secrets.
        encoded = json.dumps(config, sort_keys=True)
        forbidden = {"password", "passwd", "secret", "token", "access_token", "refresh_token",
                     "cookie", "authorization", "client_secret", "api_key", "apikey"}
        def contains_literal_secret(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    normalized = str(key).lower()
                    if normalized in forbidden:
                        # A sensitive field is safe only when its value is an explicit
                        # uppercase environment-variable reference, never a literal.
                        if not (isinstance(child, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{1,127}", child)):
                            return True
                    if not normalized.endswith("_env") and normalized not in forbidden and contains_literal_secret(child):
                        return True
            elif isinstance(value, (list, tuple)):
                return any(contains_literal_secret(item) for item in value)
            return False
        if contains_literal_secret(config):
            raise SessionStoreError("Identity config must reference environment variables, not contain secrets")
        with self.db:
            self.db.execute("""INSERT INTO auth_identities
              (engagement_id,identity_id,adapter,config_json,enabled) VALUES(?,?,?,?,1)
              ON CONFLICT(engagement_id,identity_id) DO UPDATE SET
              adapter=excluded.adapter,config_json=excluded.config_json,enabled=1""",
              (engagement_id, identity_id, adapter, encoded))

    def identity(self, engagement_id, identity_id):
        row = self.db.execute("""SELECT adapter,config_json,enabled FROM auth_identities
          WHERE engagement_id=? AND identity_id=?""", (engagement_id, identity_id)).fetchone()
        if row is None or not row["enabled"]:
            raise SessionStoreError("Identity is not configured for this engagement")
        return {"adapter": row["adapter"], "config": json.loads(row["config_json"])}

    # -- sessions ----------------------------------------------------------------------
    def put(self, session_id, engagement_id, identity_id, state, material, expires_at=None):
        payload = self._seal(session_id, engagement_id, identity_id, material)
        now = time.time()
        with self.db:
            cursor = self.db.execute("""INSERT INTO auth_sessions VALUES(?,?,?,?,?,?,?,?)
              ON CONFLICT(session_id) DO UPDATE SET state=excluded.state,
              encrypted_material=excluded.encrypted_material,expires_at=excluded.expires_at,
              updated_at=excluded.updated_at
              WHERE auth_sessions.engagement_id=excluded.engagement_id
                AND auth_sessions.identity_id=excluded.identity_id""",
              (session_id, engagement_id, identity_id, state, payload, expires_at, now, now))
            if cursor.rowcount != 1:
                # The id exists under another engagement/identity: never overwrite it.
                raise SessionStoreError("Session id is already bound to a different engagement or identity")

    def get(self, session_id, engagement_id, identity_id):
        row = self.db.execute("""SELECT state,encrypted_material,expires_at FROM auth_sessions
          WHERE session_id=? AND engagement_id=? AND identity_id=?""",
          (session_id, engagement_id, identity_id)).fetchone()
        if row is None:
            raise SessionStoreError("Session does not exist for this engagement and identity")
        material = self._open(row["encrypted_material"], session_id, engagement_id, identity_id)
        return {"state": row["state"], "material": material, "expires_at": row["expires_at"]}

    def set_state(self, session_id, engagement_id, identity_id, state):
        with self.db:
            cursor = self.db.execute("""UPDATE auth_sessions SET state=?,updated_at=strftime('%s','now')
              WHERE session_id=? AND engagement_id=? AND identity_id=?""",
              (state, session_id, engagement_id, identity_id))
            if cursor.rowcount != 1:
                raise SessionStoreError("Session does not exist")

    def revoke(self, session_id, engagement_id, identity_id):
        with self.db:
            self.db.execute("DELETE FROM auth_sessions WHERE session_id=? AND engagement_id=? AND identity_id=?",
                            (session_id, engagement_id, identity_id))

    def revoke_engagement(self, engagement_id) -> int:
        """Destroy every stored session of an engagement (e.g. when it is closed)."""
        with self.db:
            cursor = self.db.execute("DELETE FROM auth_sessions WHERE engagement_id=?", (engagement_id,))
        return cursor.rowcount

    def purge_expired(self, *, grace_seconds: float = 0.0, now: float | None = None) -> int:
        """Delete sessions whose expiry passed more than ``grace_seconds`` ago (minimisation)."""
        cutoff = (time.time() if now is None else now) - grace_seconds
        with self.db:
            cursor = self.db.execute(
                "DELETE FROM auth_sessions WHERE expires_at IS NOT NULL AND expires_at < ?", (cutoff,))
        return cursor.rowcount

    def rotate_keys(self) -> int:
        """Re-encrypt every stored session under the primary (first) key. Returns the count."""
        rows = self.db.execute("SELECT session_id,encrypted_material FROM auth_sessions").fetchall()
        with self.db:
            for row in rows:
                try:
                    rotated = self._cipher.rotate(row["encrypted_material"])
                except InvalidToken as exc:
                    raise SessionStoreError("Session vault integrity check failed during rotation") from exc
                self.db.execute("UPDATE auth_sessions SET encrypted_material=? WHERE session_id=?",
                                (rotated, row["session_id"]))
        return len(rows)

    def latest(self, engagement_id, identity_id):
        row = self.db.execute("""SELECT session_id FROM auth_sessions
          WHERE engagement_id=? AND identity_id=? ORDER BY updated_at DESC LIMIT 1""",
          (engagement_id, identity_id)).fetchone()
        return row["session_id"] if row else None
