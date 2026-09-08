# scripts/simulate_slow_scan_part1.py
"""
RUN THIS FIRST. Then run simulate_slow_scan_part2.py as a SEPARATE
terminal command afterward - a brand new Python process, with no memory
of this one. Only a shared SQLite file on disk connects them.
"""

from datetime import datetime
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


from src.assets.inventory import AssetInventory

event_store = EventStore(EVENTS_DB)
incident_store = IncidentStore(INCIDENTS_DB)
asset_inventory = AssetInventory()
asset_inventory.load_from_csv("configs/assets.csv")
orchestrator = PipelineOrchestrator(event_store, incident_store, asset_inventory)

base_time = datetime(2026, 9, 6, 10, 0, 0)
part1_events = [make_conn_event(p, base_time) for p in [21, 22, 23]]

incidents = orchestrator.ingest(part1_events)

print(f"[Part 1 - Hour 0] Probed ports: 21, 22, 23 (3 unique ports)")
print(f"[Part 1] Incidents created: {len(incidents)} (expected: 0 - below threshold on its own)")
print(f"[Part 1] Events now persisted to disk at: {EVENTS_DB}")
print(f"\nNow run: python -m scripts.simulate_slow_scan_part2")