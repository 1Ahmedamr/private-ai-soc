# src/ingestion/suricata_parser.py

from datetime import datetime
from typing import List
from src.models.event_schema import NormalizedEvent, EventSource, EventType, Severity

# Suricata severity: 1=high priority, 2=medium, 3=low (LOWER number =
# MORE severe - opposite of intuition, a common Suricata gotcha).
_SURICATA_SEVERITY_MAP = {1: Severity.HIGH, 2: Severity.MEDIUM, 3: Severity.LOW}


def parse_suricata_alert(raw_event: dict) -> NormalizedEvent:
    """
    Converts a Suricata EVE JSON alert entry into our common schema.
    Unlike our OWN detection rules (which decide severity from scratch),
    Suricata is itself a mature IDS with its OWN severity judgment - we
    trust and pass through its severity rather than re-deriving it,
    since Suricata's signature authors have far more context on a given
    signature's real-world risk than we could infer generically.
    """
    alert = raw_event.get("alert", {})
    suricata_severity = alert.get("severity", 2)

    return NormalizedEvent(
        timestamp=datetime.fromisoformat(raw_event["timestamp"]),
        source=EventSource.SURICATA,
        event_type=EventType.ALERT,
        src_ip=raw_event.get("src_ip"),
        dst_ip=raw_event.get("dest_ip"),
        dst_port=raw_event.get("dest_port"),
        severity=_SURICATA_SEVERITY_MAP.get(suricata_severity, Severity.MEDIUM),
        event_id=alert.get("signature", "unknown"),
        raw_data=raw_event,
    )


def parse_suricata_alerts(raw_events: List[dict]) -> List[NormalizedEvent]:
    return [parse_suricata_alert(raw) for raw in raw_events]