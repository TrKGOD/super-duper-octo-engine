"""Encrypted, engagement-scoped session and identity storage.

The vault key is supplied out-of-band via HACKBOT_AUTH_VAULT_KEY (Fernet key).
No plaintext credential/session material is written to SQLite or audit logs.
"""
import json
import os
import sqlite3
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken


class SessionStoreError(RuntimeError):
    pass


class SessionStore:
    def __init__(self, db_path, key=None):
        raw_key = key or os.environ.get("HACKBOT_AUTH_VAULT_KEY")
        if not raw_key:
            raise SessionStoreError("HACKBOT_AUTH_VAULT_KEY must be provisioned out-of-band")
        try:
            self._cipher = Fernet(raw_key.encode() if isinstance(raw_key, str) else raw_key)
        except (ValueError, TypeError) as exc:
            raise SessionStoreError("Invalid authentication vault key") from exc
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.db_path, timeout=5)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
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
                        return True
                    if not normalized.endswith("_env") and contains_literal_secret(child):
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

    def put(self, session_id, engagement_id, identity_id, state, material, expires_at=None):
        import time
        payload = self._cipher.encrypt(json.dumps(material, sort_keys=True).encode())
        now = time.time()
        with self.db:
            self.db.execute("""INSERT INTO auth_sessions VALUES(?,?,?,?,?,?,?,?)
              ON CONFLICT(session_id) DO UPDATE SET state=excluded.state,
              encrypted_material=excluded.encrypted_material,expires_at=excluded.expires_at,
              updated_at=excluded.updated_at""",
              (session_id, engagement_id, identity_id, state, payload, expires_at, now, now))

    def get(self, session_id, engagement_id, identity_id):
        row = self.db.execute("""SELECT state,encrypted_material,expires_at FROM auth_sessions
          WHERE session_id=? AND engagement_id=? AND identity_id=?""",
          (session_id, engagement_id, identity_id)).fetchone()
        if row is None:
            raise SessionStoreError("Session does not exist for this engagement and identity")
        try:
            material = json.loads(self._cipher.decrypt(row["encrypted_material"]))
        except (InvalidToken, ValueError) as exc:
            raise SessionStoreError("Session vault integrity check failed") from exc
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

    def latest(self, engagement_id, identity_id):
        row = self.db.execute("""SELECT session_id FROM auth_sessions
          WHERE engagement_id=? AND identity_id=? ORDER BY updated_at DESC LIMIT 1""",
          (engagement_id, identity_id)).fetchone()
        return row["session_id"] if row else None
