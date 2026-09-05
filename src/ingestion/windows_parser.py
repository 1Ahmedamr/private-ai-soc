# src/ingestion/windows_parser.py

from src.models.event_schema import NormalizedEvent, EventSource, EventType, Severity
from datetime import datetime


def parse_windows_4625(raw_event: dict) -> NormalizedEvent:
    """
    يحول Windows Event ID 4625 (Failed Logon) للـcommon schema.
    """
    return NormalizedEvent(
        timestamp=datetime.fromisoformat(raw_event["timestamp"]),
        source=EventSource.WINDOWS,
        event_type=EventType.AUTHENTICATION,
        host=raw_event.get("host"),
        user=raw_event.get("username"),
        src_ip=raw_event.get("src_ip"),
        event_id=str(raw_event.get("event_id", "4625")),
        status="failure",
        severity=Severity.MEDIUM,
        raw_data=raw_event,
    )


def parse_windows_events(raw_events: list[dict]) -> list[NormalizedEvent]:
    """
    تاخد list من raw Windows events وترجع list من NormalizedEvent.
    كل event لوحده بيتعالج بـparse_windows_4625 (حاليًا القاعدة الوحيدة عندنا).
    """
    return [parse_windows_4625(raw) for raw in raw_events]