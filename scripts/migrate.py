#!/usr/bin/env python3
"""Apply baseline schema and ordered SQL migrations to a local SQLite database.

Guarantees
* Ordered, contiguous versions: a missing or duplicated migration number is an error, not a
  silent skip.
* One transaction per migration (DDL is transactional in SQLite): a failing migration leaves
  the database exactly as it was.
* Idempotent: re-running applies nothing.
* Tamper-evident history: each applied migration's SHA-256 is recorded, and a migration file
  that changed after it was applied is refused (databases created before checksums existed
  are back-filled on first run; that back-fill cannot vouch for the past).
* Additive by policy: migrations never rebuild or rewrite existing tables.
"""
import argparse
import hashlib
import re
import sqlite3
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "database" / "migrations"


class MigrationError(RuntimeError):
    pass


def _sha256(path):
    # Normalise line endings so a CRLF checkout and an LF checkout hash identically.
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def discover(directory=MIGRATIONS):
    found = {}
    for path in sorted(Path(directory).glob("[0-9][0-9][0-9]_*.sql")):
        match = re.match(r"^(\d{3})_(.+)\.sql$", path.name)
        version = int(match.group(1))
        if version in found:
            raise MigrationError(f"Duplicate migration version {version:03d}: {found[version][1].name} and {path.name}")
        found[version] = (match.group(2), path)
    versions = sorted(found)
    if versions and versions != list(range(versions[0], versions[-1] + 1)):
        missing = sorted(set(range(versions[0], versions[-1] + 1)) - set(versions))
        raise MigrationError("Migration versions are not contiguous; missing: "
                             + ", ".join(f"{v:03d}" for v in missing))
    return found


def _ensure_checksum_column(con):
    columns = {row[1] for row in con.execute("PRAGMA table_info(schema_migrations)")}
    if "checksum" not in columns:
        con.execute("ALTER TABLE schema_migrations ADD COLUMN checksum TEXT")
        con.commit()


def migrate(db_path, *, up_to=None, directory=MIGRATIONS):
    """Apply pending migrations (optionally only through version ``up_to``); returns what ran."""
    found = discover(directory)
    con = sqlite3.connect(db_path)
    applied = []
    try:
        con.execute("PRAGMA foreign_keys=ON")
        con.execute("CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY,name TEXT NOT NULL,applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)")
        con.commit()
        _ensure_checksum_column(con)
        if con.execute("SELECT 1 FROM schema_migrations WHERE version=1").fetchone() is None:
            con.executescript((ROOT / "database" / "schema.sql").read_text(encoding="utf-8"))
            con.execute("INSERT INTO schema_migrations(version,name,checksum) VALUES(1,'baseline_schema',?)",
                        (_sha256(ROOT / "database" / "schema.sql"),))
            con.commit()
            applied.append("1: baseline_schema")
        for version, (name, path) in sorted(found.items()):
            row = con.execute("SELECT checksum FROM schema_migrations WHERE version=?", (version,)).fetchone()
            if row is not None:
                current = _sha256(path)
                if row[0] is None:
                    con.execute("UPDATE schema_migrations SET checksum=? WHERE version=?", (current, version))
                    con.commit()
                elif row[0] != current:
                    raise MigrationError(f"Migration {version:03d}_{name} was modified after it was applied")
                continue
            if up_to is not None and version > up_to:
                break
            con.executescript("BEGIN IMMEDIATE;\n" + path.read_text(encoding="utf-8") + "\n")
            con.execute("INSERT INTO schema_migrations(version,name,checksum) VALUES(?,?,?)",
                        (version, name, _sha256(path)))
            con.commit()
            applied.append(f"{version}: {name}")
        return applied
    finally:
        con.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True, help="Path to the local SQLite database")
    args = parser.parse_args()
    changes = migrate(args.db)
    print("Applied: " + (", ".join(changes) if changes else "database is up to date"))
