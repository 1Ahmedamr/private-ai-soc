from datetime import datetime
from src.ingestion.suricata_parser import parse_suricata_alert, parse_suricata_alerts
from src.detection.rules.suricata_signature_match import detect_suricata_alerts
from src.models.event_schema import EventSource, Severity


def test_parse_suricata_alert_maps_severity_correctly():
    raw = {"timestamp": "2026-09-13T11:00:00", "src_ip": "1.2.3.4", "dest_ip": "10.0.0.1",
           "dest_port": 445, "alert": {"signature": "test sig", "severity": 1}}
    event = parse_suricata_alert(raw)
    assert event.severity == "high"
    assert event.source == "suricata"


def test_detect_suricata_alerts_triggers_on_any_alert():
    raw = [{"timestamp": "2026-09-13T11:00:00", "src_ip": "1.2.3.4", "dest_ip": "10.0.0.1",
            "dest_port": 445, "alert": {"signature": "test sig", "severity": 1}}]
    events = parse_suricata_alerts(raw)
    result = detect_suricata_alerts(events)
    assert result.triggered is True


def test_no_suricata_events_does_not_trigger():
    result = detect_suricata_alerts([])
    assert result.triggered is False