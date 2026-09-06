# src/main.py

import json
from src.ingestion.windows_parser import parse_windows_events
from src.detection.engine import DetectionEngine
from src.incidents.engine import IncidentEngine
from src.incidents.store import IncidentStore


def run_pipeline(raw_events_path: str):
    """
    نقطة الدخول الرئيسية للمشروع - الـpipeline الكامل:
    Raw Logs -> Normalization -> Detection -> Incident Creation
    """
    with open(raw_events_path) as f:
        raw_events = json.load(f)

    normalized_events = parse_windows_events(raw_events)

    detection_engine = DetectionEngine()
    detections = detection_engine.analyze(normalized_events)

    store = IncidentStore()
    incident_engine = IncidentEngine(store)
    incident_engine.process(normalized_events, detections)

    return store


if __name__ == "__main__":
    incident_store = run_pipeline("tests/samples/brute_force_sample.json")
    print(f"Pipeline complete. {incident_store.count()} incident(s) created.")
    for incident in incident_store.get_all():
        print(f"  - {incident.incident_id}: {incident.title} [{incident.severity}]")