# src/storage/postgres_event_store.py

from typing import List, Optional
from datetime import datetime
import json
from src.models.event_schema import NormalizedEvent
from src.storage.postgres_db import get_pg_connection, init_pg_schema

_CORRELATION_COLUMN_MAP = {"user": '"user"', "ip": "src_ip", "host": "host"}


class PostgresEventStore:
    """
    Same public interface as EventStore (SQLite version) - save_events,
    get_events_by_correlation_key. This is the Repository Pattern payoff
    proving itself a second time: PipelineOrchestrator doesn't care
    which one it's holding.
    """

    def __init__(self, **conn_kwargs):
        self.conn = get_pg_connection(**conn_kwargs)
        init_pg_schema(self.conn)

    def save_events(self, events: List[NormalizedEvent]) -> None:
        with self.conn.cursor() as cur:
            for e in events:
                cur.execute(
                    'INSERT INTO events (timestamp, "user", src_ip, dst_ip, host, raw_json) '
                    "VALUES (%s, %s, %s, %s, %s, %s)",
                    (e.timestamp, e.user, e.src_ip, e.dst_ip, e.host, e.model_dump_json()),
                )
        self.conn.commit()

    def get_events_by_correlation_key(
        self, correlation_key: str, since: Optional[datetime] = None
    ) -> List[NormalizedEvent]:
        if ":" not in correlation_key:
            return []
        key_type, key_value = correlation_key.split(":", 1)
        column = _CORRELATION_COLUMN_MAP.get(key_type)
        if not column:
            return []

        query = f"SELECT raw_json FROM events WHERE {column} = %s"
        params: list = [key_value]
        if since:
            query += " AND timestamp >= %s"
            params.append(since)
        query += " ORDER BY timestamp ASC"

        with self.conn.cursor() as cur:
            cur.execute(query, params)
            rows = cur.fetchall()
        return [NormalizedEvent.model_validate(row[0]) for row in rows]