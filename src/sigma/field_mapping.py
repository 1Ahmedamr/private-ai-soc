# src/sigma/field_mapping.py

"""
Maps Sigma field names to our NormalizedEvent field names.

Why this matters: Sigma rules are written using vendor-specific field
names (EventID, TargetUserName, src_ip) from the original log sources.
Our NormalizedEvent uses our own schema (event_id, user, src_ip).
Without this mapping, no Sigma rule would ever match our events.

This is the most important file in the entire Sigma integration —
a wrong mapping silently causes rules to never fire (false negatives)
or always fire (false positives). Every mapping here was verified
against actual Sigma rule examples in the SigmaHQ repository.
"""

from src.models.event_schema import NormalizedEvent
from typing import Any, Optional


# Sigma field name -> how to extract it from NormalizedEvent
# Value is either a string (field name on NormalizedEvent) or
# a callable that takes a NormalizedEvent and returns the value
FIELD_MAP: dict = {
    # Windows Event Log fields
    "EventID": "event_id",
    "event_id": "event_id",
    "TargetUserName": "user",
    "SubjectUserName": "user",
    "AccountName": "user",
    "User": "user",
    "WorkstationName": "host",
    "Computer": "host",
    "IpAddress": "src_ip",
    "SourceAddress": "src_ip",

    # Network fields (Zeek)
    "src_ip": "src_ip",
    "dst_ip": "dst_ip",
    "src_port": "src_port",
    "dst_port": "dst_port",
    "proto": "protocol",
    "protocol": "protocol",

    # Zeek's own dotted field names (conn.log / dns.log)
    "id.orig_h": "src_ip",
    "id.resp_h": "dst_ip",
    "id.orig_p": "src_port",
    "id.resp_p": "dst_port",
    # "query" is intentionally NOT mapped globally - it only makes sense
    # for events from zeek_dns_parser specifically (which stores the DNS
    # query string in event_id), not for Suricata/other event types where
    # event_id means something else entirely. Handled via raw_data lookup
    # instead, which only finds it on genuine Zeek dns.log-derived events.

    # Process execution (Sysmon / Windows 4688)
    "Image": "process",
    "CommandLine": "command",
    "ParentImage": "parent_process",
    "Hashes": "file_hash",

    # Generic
    "EventType": "event_type",
    "LogonType": None,            # not captured in current schema

        # Sysmon extended fields
    "ParentImage": "parent_process",
    "ParentCommandLine": "parent_command",
    "ProcessGuid": "process_guid",
    "TargetImage": "target_process",
    "Hashes": "file_hash",
    "Initiated": "network_initiated",
    "SourceImage": "process",
    "TargetParentProcessId": None,  # not captured
}


def get_field_value(event: NormalizedEvent, sigma_field: str) -> Optional[Any]:
    """
    Gets the value of a Sigma field from a NormalizedEvent.
    Returns None if the field is not mapped or the event has no value.

    Why return None instead of raising? Because a Sigma rule checking
    a field we don't capture should NEVER match (safe default),
    not crash the entire evaluation pipeline. Missing data = no match,
    not an error.
    """
    if sigma_field in FIELD_MAP:
        mapped = FIELD_MAP[sigma_field]
        if mapped is None:
            return None  # explicitly unmapped - will never match
        if callable(mapped):
            return mapped(event)
        return getattr(event, mapped, None)

    # Not an explicitly mapped field. Many Zeek log fields (Z, rejected,
    # qtype_name, answers, c-useragent, c-uri, resp_mime_types, etc.)
    # aren't promoted to NormalizedEvent attributes, but the full raw
    # Zeek JSON is preserved in raw_data - check there before giving up.
    if event.raw_data and sigma_field in event.raw_data:
        return event.raw_data[sigma_field]

    return None  # genuinely not captured anywhere - will never match