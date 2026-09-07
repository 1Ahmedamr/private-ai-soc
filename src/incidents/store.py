# src/incidents/store.py

from typing import List, Optional
from src.models.incident_schema import Incident, IncidentStatus
from src.storage.db import get_connection, init_schema


class IncidentStore:
    """
    Persistent, SQLite-backed incident storage.

    Why replace the in-memory dict version from Day 6?
    An in-memory store is wiped every time the process restarts - not
    acceptable for a real SOC, where incidents must survive restarts and
    be queryable days later during an investigation.

    Notice: the public interface (save, get_by_id, get_by_correlation_key,
    get_all, get_open_incidents, count) is IDENTICAL to the old version.
    Nothing outside this file needs to change. This is the exact payoff
    of the "Repository Pattern" comment from Day 6 - it wasn't just
    theory, this is what it was for.
    """

    def __init__(self, db_path: str = ":memory:"):
        self.conn = get_connection(db_path)
        init_schema(self.conn)

    def save(self, incident: Incident) -> None:
        self.conn.execute(
            """
            INSERT INTO incidents (incident_id, correlation_key, status, raw_json)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(incident_id) DO UPDATE SET
                correlation_key = excluded.correlation_key,
                status = excluded.status,
                raw_json = excluded.raw_json
            """,
            (incident.incident_id, incident.correlation_key, incident.status.value, incident.model_dump_json()),
        )
        self.conn.commit()

    def get_by_id(self, incident_id: str) -> Optional[Incident]:
        row = self.conn.execute(
            "SELECT raw_json FROM incidents WHERE incident_id = ?", (incident_id,)
        ).fetchone()
        return Incident.model_validate_json(row["raw_json"]) if row else None

    def get_by_correlation_key(self, correlation_key: str) -> Optional[Incident]:
        row = self.conn.execute(
            """
            SELECT raw_json FROM incidents
            WHERE correlation_key = ?
            ORDER BY rowid DESC LIMIT 1
            """,
            (correlation_key,),
        ).fetchone()
        return Incident.model_validate_json(row["raw_json"]) if row else None

    def get_all(self) -> List[Incident]:
        rows = self.conn.execute("SELECT raw_json FROM incidents").fetchall()
        return [Incident.model_validate_json(row["raw_json"]) for row in rows]

    def get_open_incidents(self) -> List[Incident]:
        rows = self.conn.execute(
            "SELECT raw_json FROM incidents WHERE status = ?", (IncidentStatus.OPEN.value,)
        ).fetchall()
        return [Incident.model_validate_json(row["raw_json"]) for row in rows]

    def count(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) as c FROM incidents").fetchone()
        return row["c"]