# scripts/ingest_pcap.py

import sys
from src.storage.event_store import EventStore
from src.incidents.store import IncidentStore
from src.assets.inventory import AssetInventory
from src.pipeline.orchestrator import PipelineOrchestrator

if len(sys.argv) < 2:
    print("Usage: python -m scripts.ingest_pcap <path_to_pcap>")
    sys.exit(1)

pcap_path = sys.argv[1]
print(f"Analyzing {pcap_path}...")

asset_inventory = AssetInventory()
asset_inventory.load_from_csv("configs/assets.csv")
orchestrator = PipelineOrchestrator(EventStore(), IncidentStore(), asset_inventory)

incidents = orchestrator.ingest_pcap(pcap_path)
print(f"\nIncidents created: {len(incidents)}")
for inc in incidents:
    print(f"  {inc.incident_id}: {inc.title}")
    print(f"    Severity: {inc.severity} | Risk: {inc.risk_score}/100")
    print(f"    MITRE: {inc.mitre_techniques}")
    print(f"    Identity: {inc.correlation_key}")
