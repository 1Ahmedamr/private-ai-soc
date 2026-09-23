# scripts/test_sigma_engine.py

import json
from src.ingestion.windows_parser import parse_windows_events
from src.detection.engine import DetectionEngine

with open("tests/samples/brute_force_sample.json") as f:
    raw = json.load(f)

events = parse_windows_events(raw)
engine = DetectionEngine()

print(f"Events: {len(events)}")
print(f"Sigma rules loaded: {len(engine.run_sigma_rules.__self__.__class__.__dict__)}")

# Run Sigma separately to see what fires
from src.sigma.loader import get_sigma_rules
sigma_rules = get_sigma_rules()
print(f"\nSigma rules loaded: {len(sigma_rules)}")

sigma_results = engine.run_sigma_rules(events)
print(f"Sigma detections: {len(sigma_results)}")
for r in sigma_results:
    print(f"  - {r.rule_name} | {r.severity} | {r.mitre_technique}")

all_results = engine.analyze(events)
print(f"\nTotal detections (all rules): {len(all_results)}")