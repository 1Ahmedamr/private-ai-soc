# scripts/test_reopen_and_mitre.py

from datetime import datetime, timedelta
from src.models.event_schema import NormalizedEvent, EventSource, EventType
from src.models.detection_schema import DetectionResult
from src.models.incident_schema import IncidentStatus
from src.incidents.engine import IncidentEngine
from src.incidents.store import IncidentStore
from src.mitre.techniques import get_technique


def make_event(ts):
    return NormalizedEvent(
        timestamp=ts,
        source=EventSource.WINDOWS,
        event_type=EventType.AUTHENTICATION,
        user="admin",
        src_ip="10.0.0.15",
        event_id="4625",
        status="failure",
    )


def make_detection():
    technique = get_technique("T1110")
    return DetectionResult(
        rule_name="Brute Force Detection",
        rule_id="SOC-AUTH-002",
        triggered=True,
        severity="high",
        mitre_technique=technique.technique_id,
        mitre_tactic=technique.tactic,
        description="Simulated brute force for testing reopen logic.",
    )


store = IncidentStore()
engine = IncidentEngine(store)

# --- Day 1: First incident ---
base_time = datetime(2026, 9, 1, 10, 0, 0)
engine.process([make_event(base_time)], [make_detection()])
incident = store.get_all()[0]
print(f"[Day 1] Incident created: {incident.incident_id} | status={incident.status}")

# Analyst closes it
incident.status = IncidentStatus.CLOSED
store.save(incident)
print(f"[Day 1] Incident closed by analyst.\n")

# --- Day 1, 10 hours later: should REOPEN ---
engine.process([make_event(base_time + timedelta(hours=10))], [make_detection()])
reopened = store.get_by_id(incident.incident_id)
print(f"[+10h] Same incident status: {reopened.status} (expected: open)")
print(f"[+10h] Total incidents in store: {store.count()} (expected: 1)\n")

# Close it again
reopened.status = IncidentStatus.CLOSED
store.save(reopened)

# --- 5 days later: should create a NEW incident, linked to the old one ---
engine.process([make_event(base_time + timedelta(days=5))], [make_detection()])
print(f"[+5 days] Total incidents in store: {store.count()} (expected: 2)")

for inc in store.get_all():
    print(f"  - {inc.incident_id} | status={inc.status} | related_to={inc.related_incident_ids}")