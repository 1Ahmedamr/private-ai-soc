import json

from src.models.security_event import SecurityEvent
from src.detection.bruteforce_detector import detect_bruteforce


with open(
    "tests/samples/bruteforce_events.json"
) as f:
    raw_events = json.load(f)

events = []

for event in raw_events:

    events.append(
        SecurityEvent(
            timestamp=event["timestamp"],
            source="windows",
            event_id=event["event_id"],
            event_type="authentication_failure",
            username=event["username"],
            src_ip=event["src_ip"],
            status="failure",
            raw_data=event,
        )
    )

alerts = detect_bruteforce(events)

for alert in alerts:
    print(alert.model_dump_json(indent=4))