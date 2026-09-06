# scripts/test_incident_engine.py

import json
from src.ingestion.windows_parser import parse_windows_events
from src.detection.engine import DetectionEngine
from src.incidents.engine import IncidentEngine
from src.incidents.store import IncidentStore

# --- الخطوة 1: تحميل الـraw logs ---
with open("tests/samples/brute_force_sample.json") as f:
    raw_events = json.load(f)

# --- الخطوة 2: Normalization ---
normalized_events = parse_windows_events(raw_events)
print(f"[1] Normalized {len(normalized_events)} events.\n")

# --- الخطوة 3: Detection ---
detection_engine = DetectionEngine()
detections = detection_engine.analyze(normalized_events)
print(f"[2] Detection Engine found {len(detections)} triggered rules:")
for d in detections:
    print(f"    - {d.rule_name} | severity={d.severity} | confidence={d.confidence}")
print()

# --- الخطوة 4: Incident Creation ---
store = IncidentStore()
incident_engine = IncidentEngine(store)
incidents = incident_engine.process(normalized_events, detections)

print(f"[3] Incident Engine produced {len(incidents)} incident record(s) "
      f"(after deduplication):\n")

for incident in store.get_all():
    print(f"{'='*60}")
    print(f"Incident ID:     {incident.incident_id}")
    print(f"Title:           {incident.title}")
    print(f"Status:          {incident.status}")
    print(f"Priority:        {incident.priority}")
    print(f"Severity:        {incident.severity}")
    print(f"Correlation Key: {incident.correlation_key}")
    print(f"MITRE:           {incident.mitre_techniques}")
    print(f"Detections:      {len(incident.detections)}")
    print(f"First Seen:      {incident.first_seen}")
    print(f"Last Seen:       {incident.last_seen}")
    print(f"{'='*60}\n")

print(f"Total unique incidents in store: {store.count()}")