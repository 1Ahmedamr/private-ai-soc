# src/storage/postgres_db.py

import psycopg2
import psycopg2.extras


def get_pg_connection(
    host: str = "localhost",
    port: int = 5432,
    dbname: str = "private_ai_soc",
    user: str = "soc_user",
    password: str = "soc_dev_password",
):
    """
    Why does this take individual params instead of one connection string?
    Explicit parameters are self-documenting and easy to override in
    tests (e.g. pointing dbname at a throwaway test database) without
    parsing/rebuilding a DSN string by hand.
    """
    conn = psycopg2.connect(host=host, port=port, dbname=dbname, user=user, password=password)
    conn.autocommit = False
    return conn


def init_pg_schema(conn) -> None:
    """
    Same two tables as SQLite's schema, translated to Postgres syntax.
    Key differences from SQLite:
    - SERIAL instead of AUTOINCREMENT
    - JSONB instead of TEXT for raw_json - Postgres can actually INDEX
      and QUERY inside JSONB natively, which SQLite's TEXT blob cannot.
      We're not using that power yet, but JSONB costs nothing extra now
      and unlocks it later without a migration.
    """
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP NOT NULL,
                "user" TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                host TEXT,
                raw_json JSONB NOT NULL
            )
        """)
        cur.execute('CREATE INDEX IF NOT EXISTS idx_events_user ON events("user")')
        cur.execute("CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_events_host ON events(host)")

        cur.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                correlation_key TEXT NOT NULL,
                status TEXT NOT NULL,
                raw_json JSONB NOT NULL
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_incidents_correlation_key ON incidents(correlation_key)")
    conn.commit()