import json


from src.models.security_event import SecurityEvent
from src.ingestion.event_mapper import WINDOWS_EVENT_TYPES


def parse_windows_event(file_path: str):

    with open(file_path, "r") as f:
        data = json.load(f)

    event = SecurityEvent(
        timestamp=data["timestamp"],
        source="windows",
        event_id=data["event_id"],
        event_type=WINDOWS_EVENT_TYPES.get(
    data["event_id"],
    "unknown"
),
        username=data.get("username"),
        src_ip=data.get("src_ip"),
        status="failure",
        raw_data=data,
    )

    return event