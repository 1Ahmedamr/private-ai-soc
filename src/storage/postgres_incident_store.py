# src/storage/postgres_incident_store.py

from typing import List, Optional
from src.models.incident_schema import Incident, IncidentStatus
from src.storage.postgres_db import get_pg_connection, init_pg_schema


class PostgresIncidentStore:
    """Same interface as IncidentStore (SQLite version)."""

    def __init__(self, **conn_kwargs):
        self.conn = get_pg_connection(**conn_kwargs)
        init_pg_schema(self.conn)

    def save(self, incident: Incident) -> None:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO incidents (incident_id, correlation_key, status, raw_json)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (incident_id) DO UPDATE SET
                    correlation_key = EXCLUDED.correlation_key,
                    status = EXCLUDED.status,
                    raw_json = EXCLUDED.raw_json
                """,
                (incident.incident_id, incident.correlation_key, incident.status.value, incident.model_dump_json()),
            )
        self.conn.commit()

    def get_by_id(self, incident_id: str) -> Optional[Incident]:
        with self.conn.cursor() as cur:
            cur.execute("SELECT raw_json FROM incidents WHERE incident_id = %s", (incident_id,))
            row = cur.fetchone()
        return Incident.model_validate(row[0]) if row else None

    def get_by_correlation_key(self, correlation_key: str) -> Optional[Incident]:
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT raw_json FROM incidents WHERE correlation_key = %s ORDER BY ctid DESC LIMIT 1",
                (correlation_key,),
            )
            row = cur.fetchone()
        return Incident.model_validate(row[0]) if row else None

    def get_all(self) -> List[Incident]:
        with self.conn.cursor() as cur:
            cur.execute("SELECT raw_json FROM incidents")
            rows = cur.fetchall()
        return [Incident.model_validate(row[0]) for row in rows]

    def get_open_incidents(self) -> List[Incident]:
        with self.conn.cursor() as cur:
            cur.execute("SELECT raw_json FROM incidents WHERE status = %s", (IncidentStatus.OPEN.value,))
            rows = cur.fetchall()
        return [Incident.model_validate(row[0]) for row in rows]

    def count(self) -> int:
        with self.conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM incidents")
            return cur.fetchone()[0]