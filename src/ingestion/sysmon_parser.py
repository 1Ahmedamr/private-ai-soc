# src/ingestion/sysmon_parser.py

"""
Parses Sysmon (System Monitor) JSON events into NormalizedEvent objects.

Sysmon Event IDs we handle:
  1  - Process Creation (CommandLine, ParentImage, Hashes)
  3  - Network Connection (process-to-network mapping)
  7  - Image Load (DLL loading - detects DLL hijacking)
  10 - Process Access (injection detection)
  11 - File Created
  12/13 - Registry events
  22 - DNS Query

Why Sysmon matters: standard Windows Event Log only gives you WHAT
happened (process started, login failed). Sysmon gives you HOW — which
parent process spawned what child, what command line was used, what
DLLs were loaded. This is what the majority of community Sigma rules
for Windows actually need.
"""

from datetime import datetime, timezone
from typing import List, Optional
from dateutil import parser as date_parser
from src.models.event_schema import NormalizedEvent, EventSource, EventType, Severity


def _parse_timestamp(ts: str) -> datetime:
    try:
        return date_parser.isoparse(ts).astimezone(timezone.utc)
    except Exception:
        return datetime.now(tz=timezone.utc)


def _extract_hashes(hashes_str: str) -> Optional[str]:
    """
    Sysmon hashes field format: "MD5=abc123,SHA256=def456,IMPHASH=ghi789"
    We extract SHA256 preferentially since it's the most reliable for
    threat intel lookups. Falls back to MD5.
    """
    if not hashes_str:
        return None
    parts = {kv.split("=")[0].upper(): kv.split("=")[1]
             for kv in hashes_str.split(",") if "=" in kv}
    return parts.get("SHA256") or parts.get("MD5")


def parse_sysmon_event(raw: dict) -> Optional[NormalizedEvent]:
    """
    Routes a single Sysmon JSON event to the correct handler by EventID.
    Returns None for event types we don't yet handle.
    """
    # Support both flat format and nested EventData format
    event_data = raw.get("EventData", raw)
    event_id = str(raw.get("EventID") or raw.get("event_id", ""))
    timestamp = _parse_timestamp(raw.get("TimeCreated") or raw.get("timestamp", ""))
    computer = raw.get("Computer") or raw.get("computer", "")

    if event_id == "1":
        return _parse_process_creation(event_data, timestamp, computer)
    elif event_id == "3":
        return _parse_network_connection(event_data, timestamp, computer)
    elif event_id == "7":
        return _parse_image_load(event_data, timestamp, computer)
    elif event_id == "10":
        return _parse_process_access(event_data, timestamp, computer)
    elif event_id == "22":
        return _parse_dns_query(event_data, timestamp, computer)
    return None


def _parse_process_creation(data: dict, ts: datetime, computer: str) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=ts,
        source=EventSource.WINDOWS,
        event_type=EventType.PROCESS_EXECUTION,
        host=computer,
        user=data.get("User", "").split("\\")[-1] or None,
        process=data.get("Image"),
        command=data.get("CommandLine"),
        parent_process=data.get("ParentImage"),
        parent_command=data.get("ParentCommandLine"),
        process_guid=data.get("ProcessGuid"),
        file_hash=_extract_hashes(data.get("Hashes", "")),
        event_id="1",
        severity=Severity.INFO,
        raw_data=data,
    )


def _parse_network_connection(data: dict, ts: datetime, computer: str) -> NormalizedEvent:
    initiated = data.get("Initiated", "").lower() == "true"
    return NormalizedEvent(
        timestamp=ts,
        source=EventSource.WINDOWS,
        event_type=EventType.NETWORK_CONNECTION,
        host=computer,
        user=data.get("User", "").split("\\")[-1] or None,
        process=data.get("Image"),
        src_ip=data.get("SourceIp"),
        dst_ip=data.get("DestinationIp"),
        dst_port=int(data.get("DestinationPort", 0)) or None,
        protocol=data.get("Protocol", "tcp").lower(),
        network_initiated=initiated,
        event_id="3",
        severity=Severity.INFO,
        raw_data=data,
    )


def _parse_image_load(data: dict, ts: datetime, computer: str) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=ts,
        source=EventSource.WINDOWS,
        event_type=EventType.PROCESS_EXECUTION,
        host=computer,
        process=data.get("Image"),
        command=data.get("ImageLoaded"),  # the DLL being loaded
        file_hash=_extract_hashes(data.get("Hashes", "")),
        event_id="7",
        severity=Severity.INFO,
        raw_data=data,
    )


def _parse_process_access(data: dict, ts: datetime, computer: str) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=ts,
        source=EventSource.WINDOWS,
        event_type=EventType.PROCESS_EXECUTION,
        host=computer,
        process=data.get("SourceImage"),
        target_process=data.get("TargetImage"),
        event_id="10",
        severity=Severity.INFO,
        raw_data=data,
    )


def _parse_dns_query(data: dict, ts: datetime, computer: str) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=ts,
        source=EventSource.WINDOWS,
        event_type=EventType.DNS_QUERY,
        host=computer,
        process=data.get("Image"),
        event_id=data.get("QueryName", "unknown"),  # the domain queried
        severity=Severity.INFO,
        raw_data=data,
    )


def parse_sysmon_events(raw_events: List[dict]) -> List[NormalizedEvent]:
    events = []
    for raw in raw_events:
        result = parse_sysmon_event(raw)
        if result:
            events.append(result)
    return events
