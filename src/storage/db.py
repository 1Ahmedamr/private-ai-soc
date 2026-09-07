# src/storage/db.py

import sqlite3
from pathlib import Path


def get_connection(db_path: str) -> sqlite3.Connection:
    """
    Creates (or connects to) a SQLite database.

    Why check for ':memory:' specially?
    ':memory:' means "don't write to disk at all" - useful for tests,
    where we want every test to start completely clean. Real usage will
    pass an actual file path, which needs its parent folder to exist first.
    """
    if db_path != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row  # lets us access columns by name, not just index
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    """
    Creates our two tables if they don't already exist.

    Why store events as (a few indexed columns) + one JSON blob column,
    instead of a full relational schema with a column per field?
    Because NormalizedEvent already has a stable Pydantic schema that
    validates everything on the way in. We only need FAST LOOKUPS on the
    fields we actually query by (user, src_ip, host, timestamp) - the
    rest can live in the JSON blob and get reconstructed via Pydantic
    on the way out. This avoids a schema migration every time we add
    a new optional field to NormalizedEvent.
    """
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            user TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            host TEXT,
            raw_json TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_user ON events(user)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_host ON events(host)")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY,
            correlation_key TEXT NOT NULL,
            status TEXT NOT NULL,
            raw_json TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_correlation_key ON incidents(correlation_key)")
    conn.commit()