# src/ingestion/suricata_parser.py

from datetime import datetime, timezone
from typing import List
from src.models.event_schema import NormalizedEvent, EventSource, EventType, Severity
from dateutil import parser as date_parser

_SURICATA_SEVERITY_MAP = {1: Severity.HIGH, 2: Severity.MEDIUM, 3: Severity.LOW}


def parse_suricata_alert(raw_event: dict) -> NormalizedEvent:
    alert = raw_event.get("alert", {})
    suricata_severity = alert.get("severity", 2)
    signature = alert.get("signature", "")

    # ET INFO = informational only, never HIGH regardless of Suricata's own rating.
    # An EXE download, DNS lookup, or protocol detection is NOT malicious by default.
    # ET MALWARE = signature matched a known-malware pattern, but does NOT confirm compromise.
    # SURICATA internal = housekeeping signatures, always LOW.
    if signature.startswith("ET INFO") or signature.startswith("SURICATA"):
        mapped_severity = Severity.LOW
    elif signature.startswith("ET MALWARE") or signature.startswith("ET TROJAN"):
        mapped_severity = Severity.HIGH  # deserves attention, but NOT confirmed compromise
    else:
        mapped_severity = _SURICATA_SEVERITY_MAP.get(suricata_severity, Severity.MEDIUM)

    parsed_timestamp = date_parser.isoparse(raw_event["timestamp"])
    if parsed_timestamp.tzinfo is not None:
        parsed_timestamp = parsed_timestamp.astimezone(timezone.utc)

    return NormalizedEvent(
        timestamp=parsed_timestamp,
        source=EventSource.SURICATA,
        event_type=EventType.ALERT,
        src_ip=raw_event.get("src_ip"),
        dst_ip=raw_event.get("dest_ip"),
        dst_port=raw_event.get("dest_port"),
        severity=mapped_severity,
        event_id=signature or "unknown",
        raw_data=raw_event,
    )


def parse_suricata_alerts(raw_events: List[dict]) -> List[NormalizedEvent]:
    return [parse_suricata_alert(raw) for raw in raw_events]
