# scripts/debug_linux_duplicate.py

import json
from src.ingestion.linux_parser import parse_linux_ssh_events
from src.detection.engine import DetectionEngine
from src.incidents.correlation_key import extract_correlation_key

with open("tests/samples/linux_ssh_sample.json") as f:
    raw_events = json.load(f)

events = parse_linux_ssh_events(raw_events)

print("--- Correlation key ---")
print(extract_correlation_key(events))

print("\n--- Detections ---")
engine = DetectionEngine()
detections = engine.analyze(events)
for d in detections:
    print(f"rule_name={d.rule_name} | severity={d.severity} | confidence={d.confidence}")