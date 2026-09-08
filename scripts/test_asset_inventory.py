# scripts/test_asset_inventory.py

from datetime import datetime
from src.models.event_schema import NormalizedEvent, EventSource, EventType
from src.storage.event_store import EventStore
from src.incidents.store import IncidentStore
from src.assets.inventory import AssetInventory
from src.pipeline.orchestrator import PipelineOrchestrator


def make_scan_events(dst_ip, base_time):
    return [
        NormalizedEvent(
            timestamp=base_time,
            source=EventSource.ZEEK,
            event_type=EventType.NETWORK_CONNECTION,
            src_ip="10.0.0.15",
            dst_ip=dst_ip,
            dst_port=p,
            protocol="tcp",
            conn_state="S0",
        )
        for p in [21, 22, 23, 80, 443, 3389]
    ]


asset_inventory = AssetInventory()
asset_inventory.load_from_csv("configs/assets.csv")

base_time = datetime(2026, 9, 7, 10, 0, 0)

print("=== Scenario A: Same scan pattern, targeting a REGULAR workstation ===")
store_a = IncidentStore()
orchestrator_a = PipelineOrchestrator(EventStore(), store_a, asset_inventory)
orchestrator_a.ingest(make_scan_events("10.0.0.99", base_time))  # not in assets.csv -> STANDARD

for inc in store_a.get_all():
    print(f"Risk Score: {inc.risk_score}/100 | Priority: {inc.priority}")

print("\n=== Scenario B: SAME scan pattern, targeting the Domain Controller ===")
store_b = IncidentStore()
orchestrator_b = PipelineOrchestrator(EventStore(), store_b, asset_inventory)
orchestrator_b.ingest(make_scan_events("10.0.0.50", base_time))  # IS in assets.csv -> CRITICAL

for inc in store_b.get_all():
    print(f"Risk Score: {inc.risk_score}/100 | Priority: {inc.priority}")

print("\nNotice: nobody typed True/False anywhere in this script.")
print("Criticality was derived automatically from configs/assets.csv.")