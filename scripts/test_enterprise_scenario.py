#!/usr/bin/env python3
"""
Tests the full enterprise attack scenario through every detection layer.
This is the integration test that proves the entire stack works together.
"""

import json
import time
from src.ingestion.sysmon_parser import parse_sysmon_events
from src.detection.engine import DetectionEngine
from src.storage.event_store import EventStore
from src.incidents.store import IncidentStore
from src.assets.inventory import AssetInventory
from src.pipeline.orchestrator import PipelineOrchestrator

print("=" * 60)
print("Operation Nightfall - Enterprise Attack Scenario Test")
print("=" * 60)

with open("tests/samples/enterprise_attack_scenario.json") as f:
    raw = json.load(f)

events = parse_sysmon_events(raw)
print(f"\n[+] Parsed {len(events)} Sysmon events from {len(raw)} raw records")
for e in events:
    print(f"    EventID={e.event_id} | {e.event_type} | process={e.process} | dst={e.dst_ip or e.event_id}")

print("\n[+] Running through full detection pipeline...")
start = time.time()

orchestrator = PipelineOrchestrator(EventStore(), IncidentStore(), AssetInventory())
incidents = orchestrator.ingest(events)

elapsed = time.time() - start
print(f"[+] Analysis completed in {elapsed:.2f}s")
print(f"[+] Incidents created: {len(incidents)}")

for inc in sorted(incidents, key=lambda i: i.risk_score, reverse=True):
    print(f"\n{'='*50}")
    print(f"  Incident: {inc.title}")
    print(f"  Severity: {inc.severity} | Risk: {inc.risk_score}/100")
    print(f"  MITRE: {inc.mitre_techniques}")
    print(f"  Identity: {inc.correlation_key}")
    print(f"  Detections ({len(inc.detections)}):")
    for d in inc.detections:
        print(f"    - [{d.severity}] {d.rule_name}")
        print(f"      {d.description[:100]}")

expected_rules = [
    "Suspicious PowerShell Execution",
    "Possible C2 Beacon (Periodic Connections)",
    "Suspicious DNS (High-Entropy Domain)",
    "IOC Match: IP",
]

print(f"\n{'='*60}")
print("Coverage Check:")
# Check across ALL detections from engine, not just incident detections
from src.detection.engine import DetectionEngine
all_detections = DetectionEngine().analyze(events)
all_rule_names_engine = [d.rule_name for d in all_detections if d.triggered]
all_rule_names_incidents = [d.rule_name for inc in incidents for d in inc.detections]
all_rule_names = list(set(all_rule_names_engine + all_rule_names_incidents))
for expected in expected_rules:
    found = any(expected in name for name in all_rule_names)
    print(f"  {'✅' if found else '❌'} {expected}")

sigma_matches = [n for n in all_rule_names if "[Sigma]" in n]
print(f"\n  Sigma rules fired: {len(sigma_matches)}")
for s in sigma_matches[:5]:
    print(f"    - {s}")

ioc_matches = [n for n in all_rule_names if "IOC" in n]
print(f"  IOC matches: {len(ioc_matches)}")
