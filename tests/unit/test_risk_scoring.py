# tests/unit/test_risk_scoring.py

from datetime import datetime
from src.models.incident_schema import Incident, IncidentPriority
from src.models.detection_schema import DetectionResult
from src.models.event_schema import Severity
from src.risk.scoring import calculate_risk_score


def make_incident(severity=Severity.HIGH, detections=None):
    return Incident(
        title="Test Incident",
        priority=IncidentPriority.P2_HIGH,
        severity=severity,
        correlation_key="user:admin",
        detections=detections or [],
        first_seen=datetime.now(),
        last_seen=datetime.now(),
    )


def make_detection(confidence=1.0):
    return DetectionResult(
        rule_name="Test Rule",
        rule_id="TEST-001",
        triggered=True,
        severity=Severity.HIGH,
        description="test",
        confidence=confidence,
    )


def test_higher_severity_gives_higher_base_score():
    low_incident = make_incident(severity=Severity.LOW, detections=[make_detection()])
    high_incident = make_incident(severity=Severity.HIGH, detections=[make_detection()])

    low_score = calculate_risk_score(low_incident)
    high_score = calculate_risk_score(high_incident)

    assert high_score > low_score


def test_more_evidence_increases_score():
    single_detection = make_incident(detections=[make_detection()])
    multiple_detections = make_incident(detections=[make_detection(), make_detection()])

    score_single = calculate_risk_score(single_detection)
    score_multiple = calculate_risk_score(multiple_detections)

    assert score_multiple > score_single


def test_low_confidence_reduces_score():
    high_confidence = make_incident(detections=[make_detection(confidence=1.0)])
    low_confidence = make_incident(detections=[make_detection(confidence=0.3)])

    assert calculate_risk_score(high_confidence) > calculate_risk_score(low_confidence)


def test_critical_asset_boosts_score():
    incident = make_incident(detections=[make_detection()])

    normal_score = calculate_risk_score(incident, is_critical_asset=False)
    critical_score = calculate_risk_score(incident, is_critical_asset=True)

    assert critical_score > normal_score


def test_score_never_exceeds_100():
    incident = make_incident(
        severity=Severity.CRITICAL,
        detections=[make_detection(confidence=1.0) for _ in range(10)],
    )
    score = calculate_risk_score(incident, is_critical_asset=True)
    assert score <= 100


def test_score_never_negative():
    incident = make_incident(severity=Severity.INFO, detections=[])
    score = calculate_risk_score(incident)
    assert score >= 0