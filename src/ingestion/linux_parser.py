# src/ingestion/linux_parser.py

from datetime import datetime
from typing import List
from src.models.event_schema import NormalizedEvent, EventSource, EventType, Severity


def parse_linux_ssh_event(raw_event: dict) -> NormalizedEvent:
    """
    Converts a Linux SSH auth log entry (pre-parsed JSON form) into our
    common schema. Same structural pattern as windows_parser.py and
    zeek_parser.py - one function per source, same output type.

    Mapping notes:
    - "action": "failed_password" -> status="failure" (same concept as
      Windows event_id 4625, just a different source's vocabulary)
    - No event_id equivalent in this simplified format - Linux syslog
      doesn't have Windows-style numeric event IDs, so we use the raw
      action string as our event_id substitute for traceability.
    """
    status = "failure" if raw_event.get("action") == "failed_password" else "unknown"

    return NormalizedEvent(
        timestamp=datetime.fromisoformat(raw_event["timestamp"]),
        source=EventSource.LINUX,
        event_type=EventType.AUTHENTICATION,
        user=raw_event.get("user"),
        src_ip=raw_event.get("src_ip"),
        event_id=raw_event.get("action", "unknown"),
        status=status,
        severity=Severity.MEDIUM,
        raw_data=raw_event,
    )


def parse_linux_ssh_events(raw_events: List[dict]) -> List[NormalizedEvent]:
    return [parse_linux_ssh_event(raw) for raw in raw_events]