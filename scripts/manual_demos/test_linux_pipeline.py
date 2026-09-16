# scripts/test_linux_pipeline.py

import json
from src.ingestion.linux_parser import parse_linux_ssh_events
from src.storage.event_store import EventStore
from src.incidents.store import IncidentStore
from src.assets.inventory import AssetInventory
from src.pipeline.orchestrator import PipelineOrchestrator

with open("tests/samples/linux_ssh_sample.json") as f:
    raw_events = json.load(f)

normalized_events = parse_linux_ssh_events(raw_events)
print(f"[1] Normalized {len(normalized_events)} Linux SSH events.")
print(f"    Source: {normalized_events[0].source} | user: {normalized_events[0].user}\n")

asset_inventory = AssetInventory()
asset_inventory.load_from_csv("configs/assets.csv")

orchestrator = PipelineOrchestrator(EventStore(), IncidentStore(), asset_inventory)
incidents = orchestrator.ingest(normalized_events)

print(f"[2] Incident(s) created: {len(incidents)}\n")
for inc in incidents:
    print(f"{'='*60}")
    print(f"Title:      {inc.title}")
    print(f"Severity:   {inc.severity}")
    print(f"MITRE:      {inc.mitre_techniques}")
    print(f"Risk Score: {inc.risk_score}/100")
    print(f"{'='*60}")

print(f"\nThird independent source (Windows, Zeek, now Linux) through")
print(f"the same unmodified Detection/Incident/Risk pipeline.")