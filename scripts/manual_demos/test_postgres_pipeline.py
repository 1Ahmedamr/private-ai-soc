# scripts/test_postgres_pipeline.py

from datetime import datetime
from src.models.event_schema import NormalizedEvent, EventSource, EventType
from src.storage.postgres_event_store import PostgresEventStore
from src.storage.postgres_incident_store import PostgresIncidentStore
from src.assets.inventory import AssetInventory
from src.pipeline.orchestrator import PipelineOrchestrator

event_store = PostgresEventStore()
incident_store = PostgresIncidentStore()
asset_inventory = AssetInventory()
asset_inventory.load_from_csv("configs/assets.csv")

orchestrator = PipelineOrchestrator(event_store, incident_store, asset_inventory)

base_time = datetime(2026, 9, 8, 10, 0, 0)
events = [
    NormalizedEvent(
        timestamp=base_time, source=EventSource.LINUX, event_type=EventType.AUTHENTICATION,
        user="root", src_ip="45.33.12.99", event_id="failed_password", status="failure",
    )
    for _ in range(6)
]

incidents = orchestrator.ingest(events)
print(f"Incidents created (Postgres-backed): {len(incidents)}")
for inc in incidents:
    print(f"  {inc.title} | risk={inc.risk_score} | id={inc.incident_id}")

print(f"\nTotal incidents currently in Postgres: {incident_store.count()}")
print("Run this script again - count should NOT double, proving persistence + dedup work over Postgres too.")