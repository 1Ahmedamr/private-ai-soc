# src/ingestion/zeek_parser.py

from datetime import datetime, timezone
from typing import List
from src.models.event_schema import NormalizedEvent, EventSource, EventType, Severity


def parse_zeek_conn_log(raw_event: dict) -> NormalizedEvent:
    """
    Converts a single Zeek conn.log JSON entry into our common schema.

    Key parsing challenges here (different from the Windows parser):
    1. Zeek timestamps are Unix epoch floats (e.g. 1725600000.123456),
       not ISO strings like our Windows sample. Need explicit conversion.
    2. Zeek field names use dots (id.orig_h) - these aren't valid Python
       attribute names, so we access them as dict keys, not attributes.
    3. Zeek doesn't have a "user" concept at the network layer - this
       event type will naturally have user=None, and our fallback
       correlation logic (user -> src_ip -> host) built on Day 4
       handles this automatically without any new code.
    """
    return NormalizedEvent(
        timestamp=datetime.fromtimestamp(raw_event["ts"], tz=timezone.utc),
        source=EventSource.ZEEK,
        event_type=EventType.NETWORK_CONNECTION,
        src_ip=raw_event.get("id.orig_h"),
        dst_ip=raw_event.get("id.resp_h"),
        src_port=raw_event.get("id.orig_p"),
        dst_port=raw_event.get("id.resp_p"),
        protocol=raw_event.get("proto"),
        conn_state=raw_event.get("conn_state"),
        severity=Severity.INFO,  # default - real severity comes from Detection Engine, same as Windows events
        raw_data=raw_event,
    )


def parse_zeek_conn_logs(raw_events: List[dict]) -> List[NormalizedEvent]:
    """Batch version - same pattern as parse_windows_events from Day 2."""
    return [parse_zeek_conn_log(raw) for raw in raw_events]