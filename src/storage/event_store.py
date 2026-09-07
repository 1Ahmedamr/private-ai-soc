# src/storage/event_store.py

from typing import List, Optional
from datetime import datetime
from src.models.event_schema import NormalizedEvent
from src.storage.db import get_connection, init_schema


# Security note (relevant to your background): the column name below is
# never built from raw user input - it's always looked up through this
# fixed whitelist dictionary. NEVER interpolate untrusted strings directly
# into a SQL query string, even for something as small as a column name.
# This is the exact class of bug (SQL injection) that shows up constantly
# in real vulnerability assessments.
_CORRELATION_COLUMN_MAP = {
    "user": "user",
    "ip": "src_ip",
    "host": "host",
}


class EventStore:
    """
    Persistent, disk-backed storage for NormalizedEvents.

    This is the core fix for today's problem: as long as events are
    saved here, they can be queried again days later, by a completely
    different process, and the full pattern becomes visible.
    """

    def __init__(self, db_path: str = ":memory:"):
        self.conn = get_connection(db_path)
        init_schema(self.conn)

    def save_events(self, events: List[NormalizedEvent]) -> None:
        rows = [
            (e.timestamp.isoformat(), e.user, e.src_ip, e.dst_ip, e.host, e.model_dump_json())
            for e in events
        ]
        self.conn.executemany(
            "INSERT INTO events (timestamp, user, src_ip, dst_ip, host, raw_json) VALUES (?, ?, ?, ?, ?, ?)",
            rows,
        )
        self.conn.commit()

    def get_events_by_correlation_key(
        self, correlation_key: str, since: Optional[datetime] = None
    ) -> List[NormalizedEvent]:
        """
        Retrieves all stored events matching a given identity (e.g.
        "user:admin" or "ip:10.0.0.15"), optionally restricted to events
        at or after `since`. This is what lets us reassemble a pattern
        that arrived across multiple separate ingestion calls.
        """
        if ":" not in correlation_key:
            return []
        key_type, key_value = correlation_key.split(":", 1)
        column = _CORRELATION_COLUMN_MAP.get(key_type)
        if not column:
            return []

        query = f"SELECT raw_json FROM events WHERE {column} = ?"
        params: list = [key_value]
        if since:
            query += " AND timestamp >= ?"
            params.append(since.isoformat())
        query += " ORDER BY timestamp ASC"

        rows = self.conn.execute(query, params).fetchall()
        return [NormalizedEvent.model_validate_json(row["raw_json"]) for row in rows]