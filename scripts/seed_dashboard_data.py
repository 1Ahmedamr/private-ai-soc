# scripts/seed_dashboard_data.py
"""
Seeds data/processed/soc_incidents.db with a realistic mix of incidents
across sources/severities, purely so the dashboard has something
meaningful to show. Safe to re-run - each run adds fresh incidents.
"""

from datetime import datetime, timedelta
from src.models.event_schema import NormalizedEvent, EventSource, EventType
from src.storage.event_store import EventStore
from src.incidents.store import IncidentStore
from src.assets.inventory import AssetInventory
from src.pipeline.orchestrator import PipelineOrchestrator

EVENTS_DB = "data/processed/soc_events.db"
INCIDENTS_DB = "data/processed/soc_incidents.db"

event_store = EventStore(EVENTS_DB)
incident_store = IncidentStore(INCIDENTS_DB)
asset_inventory = AssetInventory()
asset_inventory.load_from_csv("configs/assets.csv")
orchestrator = PipelineOrchestrator(event_store, incident_store, asset_inventory)

base_time = datetime(2026, 9, 10, 9, 0, 0)

# Scenario 1: Windows brute force on a regular workstation
orchestrator.ingest([
    NormalizedEvent(
        timestamp=base_time + timedelta(seconds=i * 20), source=EventSource.WINDOWS,
        event_type=EventType.AUTHENTICATION, user="jsmith", host="WIN-CLIENT",
        event_id="4625", status="failure",
    )
    for i in range(6)
])

# Scenario 2: SSH root brute force (high confidence, HIGH severity)
orchestrator.ingest([
    NormalizedEvent(
        timestamp=base_time + timedelta(seconds=i * 15), source=EventSource.LINUX,
        event_type=EventType.AUTHENTICATION, user="root", src_ip="45.33.12.99",
        event_id="failed_password", status="failure",
    )
    for i in range(5)
])

# Scenario 3: Fast port scan against the Domain Controller (critical asset boost)
orchestrator.ingest([
    NormalizedEvent(
        timestamp=base_time + timedelta(seconds=i), source=EventSource.ZEEK,
        event_type=EventType.NETWORK_CONNECTION, src_ip="10.0.0.15", dst_ip="10.0.0.50",
        dst_port=p, protocol="tcp", conn_state="S0",
    )
    for i, p in enumerate([21, 22, 23, 80, 443, 3389])
])

print(f"Seeded {incident_store.count()} incidents into {INCIDENTS_DB}")
print("Now run: python -m scripts.dashboard")