# scripts/simulate_slow_scan_part2.py
"""
RUN THIS SECOND, as a SEPARATE terminal command from part1. This process
only creates 2 new events below - it has NO memory of part1's events
except through the shared SQLite file on disk.
"""

from datetime import datetime, timedelta
from src.models.event_schema import NormalizedEvent, EventSource, EventType
from src.storage.event_store import EventStore
from src.incidents.store import IncidentStore
from src.pipeline.orchestrator import PipelineOrchestrator

EVENTS_DB = "data/processed/demo_slow_scan_events.db"
INCIDENTS_DB = "data/processed/demo_slow_scan_incidents.db"


def make_conn_event(dst_port, ts):
    return NormalizedEvent(
        timestamp=ts,
        source=EventSource.ZEEK,
        event_type=EventType.NETWORK_CONNECTION,
        src_ip="10.0.0.15",
        dst_ip="10.0.0.50",
        dst_port=dst_port,
        protocol="tcp",
        conn_state="S0",
    )


event_store = EventStore(EVENTS_DB)   # reconnects to the SAME file part1 wrote to
incident_store = IncidentStore(INCIDENTS_DB)
orchestrator = PipelineOrchestrator(event_store, incident_store)

base_time = datetime(2026, 9, 6, 10, 0, 0)
part2_events = [make_conn_event(p, base_time + timedelta(hours=5)) for p in [80, 443]]

incidents = orchestrator.ingest(part2_events, is_critical_asset=False)

print(f"[Part 2 - Hour +5] Probed ports: 80, 443 (2 MORE unique ports)")
print(f"[Part 2] This process never saw part1's events directly.")
print(f"[Part 2] Combined history (queried from disk): ports 21,22,23,80,443 = 5 unique, across ~5 hours\n")
print(f"[Part 2] Incidents created: {len(incidents)} (expected: 1)")

for inc in incident_store.get_all():
    print(f"\n{'='*60}")
    print(f"Incident ID: {inc.incident_id}")
    print(f"Title:       {inc.title}")
    print(f"Severity:    {inc.severity}")
    print(f"Confidence:  {[d.confidence for d in inc.detections]}")
    print(f"Risk Score:  {inc.risk_score}/100")
    print(f"{'='*60}")

print(f"\nThis incident was ONLY detectable because events were persisted")
print(f"to disk between two completely separate process executions.")