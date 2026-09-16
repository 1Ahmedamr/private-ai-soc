# src/dashboard/timeline.py

from typing import List, Dict
from src.models.incident_schema import Incident


def build_timeline_entries(incident: Incident) -> List[Dict]:
    """
    Converts an incident's events and detections into a single,
    chronologically sorted list of timeline entries - mixing raw event
    timestamps with detection "moments" so an analyst sees the full
    story in order, not two separate disconnected lists.
    """
    entries = []

    for event in incident.events:
        entries.append({
            "timestamp": event.timestamp,
            "type": "event",
            "label": f"{event.source} {event.event_type}",
            "detail": f"user={event.user or '-'} src_ip={event.src_ip or '-'}",
        })

    for detection in incident.detections:
        entries.append({
            "timestamp": incident.last_seen,  # detections fire at analysis time, not a distinct captured timestamp
            "type": "detection",
            "label": detection.rule_name,
            "detail": detection.description,
        })

    entries.sort(key=lambda e: e["timestamp"])
    return entries