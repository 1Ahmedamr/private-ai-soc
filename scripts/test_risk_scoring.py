# scripts/test_risk_scoring.py

from datetime import datetime
from src.ingestion.windows_parser import parse_windows_events
from src.detection.engine import DetectionEngine
from src.incidents.engine import IncidentEngine
from src.incidents.store import IncidentStore
import json

with open("tests/samples/brute_force_sample.json") as f:
    raw_events = json.load(f)

normalized_events = parse_windows_events(raw_events)

detection_engine = DetectionEngine()
detections = detection_engine.analyze(normalized_events)

store = IncidentStore()
incident_engine = IncidentEngine(store)

print("=== Scenario 1: Regular workstation ===")
incidents = incident_engine.process(normalized_events, detections, is_critical_asset=False)
for inc in incidents:
    print(f"Incident: {inc.incident_id}")
    print(f"  Severity:    {inc.severity}")
    print(f"  Risk Score:  {inc.risk_score}/100")
    print(f"  Priority:    {inc.priority}")

print("\n=== Scenario 2: Same attack, but on a Domain Controller (critical asset) ===")
store2 = IncidentStore()
incident_engine_2 = IncidentEngine(store2)
incidents_critical = incident_engine_2.process(normalized_events, detections, is_critical_asset=True)
for inc in incidents_critical:
    print(f"Incident: {inc.incident_id}")
    print(f"  Severity:    {inc.severity}")
    print(f"  Risk Score:  {inc.risk_score}/100")
    print(f"  Priority:    {inc.priority}")