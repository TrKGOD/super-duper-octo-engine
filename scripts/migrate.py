#!/usr/bin/env python3
"""Apply baseline schema and ordered SQL migrations to a local SQLite database."""
import argparse
import re
import sqlite3
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "database" / "migrations"


def migrate(db_path):
    con = sqlite3.connect(db_path)
    applied = []
    try:
        con.execute("PRAGMA foreign_keys=ON")
        con.execute("CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY,name TEXT NOT NULL,applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)")
        con.commit()
        if con.execute("SELECT 1 FROM schema_migrations WHERE version=1").fetchone() is None:
            con.executescript((ROOT / "database" / "schema.sql").read_text(encoding="utf-8"))
            con.execute("INSERT INTO schema_migrations(version,name) VALUES(1,'baseline_schema')")
            con.commit()
            applied.append("1: baseline_schema")
        for path in sorted(MIGRATIONS.glob("[0-9][0-9][0-9]_*.sql")):
            match = re.match(r"^(\d{3})_(.+)\.sql$", path.name)
            version, name = int(match.group(1)), match.group(2)
            if con.execute("SELECT 1 FROM schema_migrations WHERE version=?", (version,)).fetchone():
                continue
            con.executescript("BEGIN IMMEDIATE;\n" + path.read_text(encoding="utf-8") + "\n")
            con.execute("INSERT INTO schema_migrations(version,name) VALUES(?,?)", (version,name))
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
