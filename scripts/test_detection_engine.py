# scripts/test_detection_engine.py

import json
from src.ingestion.windows_parser import parse_windows_events
from src.detection.engine import DetectionEngine

# تحميل الـbrute force sample
with open("tests/samples/brute_force_sample.json") as f:
    raw_events = json.load(f)

# تحويلهم لـNormalizedEvents
normalized_events = parse_windows_events(raw_events)

# تشغيل الـDetection Engine
engine = DetectionEngine()
results = engine.analyze(normalized_events)

print(f"\n{'='*60}")
print(f"Total events analyzed: {len(normalized_events)}")
print(f"Total detections triggered: {len(results)}")
print(f"{'='*60}\n")

for i, result in enumerate(results, 1):
    print(f"[Detection #{i}]")
    print(result.model_dump_json(indent=2))
    print()