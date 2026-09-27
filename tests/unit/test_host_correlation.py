# tests/unit/test_host_correlation.py

from datetime import datetime, timedelta
from src.correlation.host_engine import correlate_by_host, HostSummary
from src.models.incident_schema import Incident, IncidentPriority
from src.models.event_schema import Severity, NormalizedEvent, EventSource, EventType
from src.models.detection_schema import DetectionResult


def make_incident(title, severity, risk, dst_ip, first_seen, detections=None):
    event = NormalizedEvent(
        timestamp=first_seen, source=EventSource.SURICATA,
        event_type=EventType.ALERT, src_ip="51.195.169.87",
        dst_ip=dst_ip,
    )
    return Incident(
        title=title, priority=IncidentPriority.P2_HIGH,
        severity=severity, correlation_key=f"ip:51.195.169.87",
        first_seen=first_seen, last_seen=first_seen + timedelta(minutes=10),
        risk_score=risk, events=[event],
        detections=detections or [
            DetectionResult(rule_name="Test Rule", rule_id="T001",
                          triggered=True, severity=Severity.HIGH,
                          description="test", confidence=0.9,
                          mitre_technique="T1071", mitre_tactic="Command and Control")
        ],
    )


def test_two_incidents_same_host_creates_summary():
    base = datetime(2026, 9, 25, 10, 0, 0)
    incidents = [
        make_incident("C2 Beacon", Severity.HIGH, 76, "172.17.5.135", base),
        make_incident("Malware Download", Severity.MEDIUM, 50, "172.17.5.135",
                     base + timedelta(minutes=30)),
    ]
    summaries = correlate_by_host(incidents)
    assert len(summaries) == 1
    assert summaries[0].victim_ip == "172.17.5.135"
    assert len(summaries[0].incident_ids) == 2
    assert summaries[0].highest_severity == "high"
    assert summaries[0].highest_risk == 76


def test_single_incident_does_not_create_summary():
    base = datetime(2026, 9, 25, 10, 0, 0)
    incidents = [make_incident("C2 Beacon", Severity.HIGH, 76, "172.17.5.135", base)]
    summaries = correlate_by_host(incidents)
    assert len(summaries) == 0


def test_incidents_outside_window_not_grouped():
    base = datetime(2026, 9, 25, 10, 0, 0)
    incidents = [
        make_incident("C2 Beacon", Severity.HIGH, 76, "172.17.5.135", base),
        make_incident("Malware Download", Severity.MEDIUM, 50, "172.17.5.135",
                     base + timedelta(hours=6)),  # outside 4-hour window
    ]
    summaries = correlate_by_host(incidents, window_hours=4)
    assert len(summaries) == 0


def test_different_hosts_create_separate_summaries():
    base = datetime(2026, 9, 25, 10, 0, 0)
    incidents = [
        make_incident("C2 Beacon", Severity.HIGH, 76, "172.17.5.135", base),
        make_incident("C2 Beacon", Severity.HIGH, 76, "172.17.5.135",
                     base + timedelta(minutes=10)),
        make_incident("Port Scan", Severity.MEDIUM, 40, "172.17.5.200", base),
        make_incident("Port Scan", Severity.MEDIUM, 40, "172.17.5.200",
                     base + timedelta(minutes=20)),
    ]
    summaries = correlate_by_host(incidents)
    assert len(summaries) == 2
    victim_ips = {s.victim_ip for s in summaries}
    assert "172.17.5.135" in victim_ips
    assert "172.17.5.200" in victim_ips


def test_mitre_techniques_merged_across_incidents():
    base = datetime(2026, 9, 25, 10, 0, 0)
    inc1 = make_incident("C2", Severity.HIGH, 76, "172.17.5.135", base)
    inc1.mitre_techniques = ["T1071"]
    inc2 = make_incident("VNC", Severity.HIGH, 60, "172.17.5.135",
                        base + timedelta(minutes=30))
    inc2.mitre_techniques = ["T1021.005"]
    summaries = correlate_by_host([inc1, inc2])
    assert len(summaries) == 1
    assert "T1071" in summaries[0].mitre_techniques
    assert "T1021.005" in summaries[0].mitre_techniques
