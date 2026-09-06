# src/incidents/correlation_key.py

from typing import List
from src.models.event_schema import NormalizedEvent


def extract_correlation_key(events: List[NormalizedEvent]) -> str:
    """
    Determines the shared identity across a group of events,
    used to group them under the same Incident.

    Priority order:
    1. user (if available)
    2. src_ip (fallback)
    3. host (fallback)
    4. "unknown" (last resort)
    """
    if not events:
        return "unknown"

    first_event = events[0]

    if first_event.user:
        return f"user:{first_event.user}"
    if first_event.src_ip:
        return f"ip:{first_event.src_ip}"
    if first_event.host:
        return f"host:{first_event.host}"

    return "unknown"


def filter_events_by_correlation_key(
    events: List[NormalizedEvent], correlation_key: str
) -> List[NormalizedEvent]:
    """
    NEW FUNCTION: filters events down to only those that actually
    match the given correlation key.

    Why do we need this?
    Because in a real pipeline, `events` passed to the Incident Engine
    might contain events from MULTIPLE users/IPs at once (e.g., a batch
    of 10,000 logs per hour). We only want to attach the events that
    actually belong to THIS specific incident's identity — not everything
    that happened to be in the same batch.
    """
    key_type, key_value = correlation_key.split(":", 1) if ":" in correlation_key else (None, None)

    if key_type == "user":
        return [e for e in events if e.user == key_value]
    if key_type == "ip":
        return [e for e in events if e.src_ip == key_value]
    if key_type == "host":
        return [e for e in events if e.host == key_value]

    # "unknown" key - return as-is, nothing to filter by
    return events