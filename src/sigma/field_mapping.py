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

    # Process execution (Sysmon / Windows 4688)
    "Image": "process",
    "CommandLine": "command",
    "ParentImage": None,          # not captured yet - will never match
    "Hashes": None,               # not captured yet - will never match

    # Generic
    "EventType": "event_type",
    "LogonType": None,            # not captured in current schema
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
    mapped = FIELD_MAP.get(sigma_field)
    if mapped is None:
        return None  # field not in our schema - will never match
    if callable(mapped):
        return mapped(event)
    return getattr(event, mapped, None)