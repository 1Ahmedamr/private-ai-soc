# scripts/ingest_pcap.py

import sys
from src.pipeline.pcap_processor import process_pcap
from src.storage.event_store import EventStore
from src.incidents.store import IncidentStore
from src.assets.inventory import AssetInventory
from src.pipeline.orchestrator import PipelineOrchestrator

if len(sys.argv) < 2:
    print("Usage: python -m scripts.ingest_pcap <path_to_pcap>")
    sys.exit(1)

pcap_path = sys.argv[1]
print(f"Running Zeek + Suricata against {pcap_path}...")

events = process_pcap(pcap_path)
print(f"Extracted {len(events)} normalized events from PCAP.")

if not events:
    print("No events extracted - check the PCAP is valid and Zeek/Suricata ran correctly.")
    sys.exit(0)

asset_inventory = AssetInventory()
asset_inventory.load_from_csv("configs/assets.csv")
orchestrator = PipelineOrchestrator(EventStore(), IncidentStore(), asset_inventory)

incidents = orchestrator.ingest(events)
print(f"Incidents created: {len(incidents)}")
for inc in incidents:
    print(f"  {inc.incident_id}: {inc.title} | risk={inc.risk_score}")