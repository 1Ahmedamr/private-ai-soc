# tests/unit/test_ai_policy.py

from datetime import datetime
from src.models.incident_schema import Incident, IncidentPriority, IncidentStatus
from src.models.event_schema import Severity
from src.ai.policy import should_auto_investigate, AUTO_INVESTIGATE_MIN_RISK_SCORE


def make_incident(status=IncidentStatus.OPEN, risk_score=60):
    return Incident(
        title="Test Incident",
        priority=IncidentPriority.P2_HIGH,
        severity=Severity.HIGH,
        status=status,
        correlation_key="user:admin",
        first_seen=datetime.now(),
        last_seen=datetime.now(),
        risk_score=risk_score,
    )


def test_high_risk_open_incident_should_investigate():
    incident = make_incident(status=IncidentStatus.OPEN, risk_score=60)
    assert should_auto_investigate(incident) is True


def test_low_risk_open_incident_should_not_investigate():
    incident = make_incident(status=IncidentStatus.OPEN, risk_score=20)
    assert should_auto_investigate(incident) is False


def test_closed_incident_never_auto_investigated_even_if_high_risk():
    incident = make_incident(status=IncidentStatus.CLOSED, risk_score=95)
    assert should_auto_investigate(incident) is False


def test_false_positive_incident_never_auto_investigated():
    incident = make_incident(status=IncidentStatus.FALSE_POSITIVE, risk_score=95)
    assert should_auto_investigate(incident) is False


def test_investigating_status_still_qualifies():
    """An incident already under active investigation can still receive
    additional AI enrichment - only CLOSED/FALSE_POSITIVE are excluded."""
    incident = make_incident(status=IncidentStatus.INVESTIGATING, risk_score=70)
    assert should_auto_investigate(incident) is True


def test_exact_threshold_boundary_qualifies():
    incident = make_incident(status=IncidentStatus.OPEN, risk_score=AUTO_INVESTIGATE_MIN_RISK_SCORE)
    assert should_auto_investigate(incident) is True


def test_just_below_threshold_does_not_qualify():
    incident = make_incident(status=IncidentStatus.OPEN, risk_score=AUTO_INVESTIGATE_MIN_RISK_SCORE - 1)
    assert should_auto_investigate(incident) is False