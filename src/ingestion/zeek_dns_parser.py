# src/ingestion/zeek_dns_parser.py

from datetime import datetime, timezone
from typing import List
from src.models.event_schema import NormalizedEvent, EventSource, EventType, Severity


def parse_zeek_dns_log(raw_event: dict) -> NormalizedEvent:
    """
    Converts a Zeek dns.log JSON entry. Key field: query - the domain
    name requested. This is what lets us detect DGA-like domains
    (long, random-looking strings) or known-bad TLD patterns later.
    """
    return NormalizedEvent(
        timestamp=datetime.fromtimestamp(raw_event["ts"], tz=timezone.utc),
        source=EventSource.ZEEK,
        event_type=EventType.DNS_QUERY,
        src_ip=raw_event.get("id.orig_h"),
        dst_ip=raw_event.get("id.resp_h"),
        event_id=raw_event.get("query", "unknown"),
        severity=Severity.INFO,
        raw_data=raw_event,
    )


def parse_zeek_dns_logs(raw_events: List[dict]) -> List[NormalizedEvent]:
    return [parse_zeek_dns_log(raw) for raw in raw_events]