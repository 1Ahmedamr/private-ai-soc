# scripts/test_zeek_pipeline.py

import json
from src.ingestion.zeek_parser import parse_zeek_conn_logs
from src.detection.engine import DetectionEngine
from src.incidents.engine import IncidentEngine
from src.incidents.store import IncidentStore

# --- Step 1: Load raw Zeek data ---
with open("tests/samples/zeek_portscan_sample.json") as f:
    raw_events = json.load(f)

# --- Step 2: Normalization (Zeek-specific parser, same output schema) ---
normalized_events = parse_zeek_conn_logs(raw_events)
print(f"[1] Normalized {len(normalized_events)} Zeek connection events.")
print(f"    Source type: {normalized_events[0].source}")
print(f"    Event type:  {normalized_events[0].event_type}\n")

# --- Step 3: Detection (SAME engine used for Windows events) ---
detection_engine = DetectionEngine()
detections = detection_engine.analyze(normalized_events)
print(f"[2] Detection Engine found {len(detections)} triggered rule(s):")
for d in detections:
    print(f"    - {d.rule_name} | severity={d.severity} | MITRE={d.mitre_technique} ({d.mitre_tactic})")
print()

# --- Step 4: Incident creation (SAME engine, SAME store, SAME risk scoring) ---
store = IncidentStore()
incident_engine = IncidentEngine(store)
incidents = incident_engine.process(normalized_events, detections, is_critical_asset=True)

print(f"[3] Incident(s) created: {len(incidents)}\n")
for incident in store.get_all():
    print(f"{'='*60}")
    print(f"Incident ID:      {incident.incident_id}")
    print(f"Title:            {incident.title}")
    print(f"Severity:         {incident.severity}")
    print(f"Risk Score:       {incident.risk_score}/100")
    print(f"Priority:         {incident.priority}")
    print(f"Correlation Key:  {incident.correlation_key}")
    print(f"MITRE Techniques: {incident.mitre_techniques}")
    print(f"Events attached:  {len(incident.events)}")
    print(f"{'='*60}")

print(f"\nDone. This incident went through the EXACT SAME engine code")
print(f"that processes Windows brute-force events. Zero pipeline changes needed.")