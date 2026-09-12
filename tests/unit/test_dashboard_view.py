# tests/unit/test_dashboard_view.py

from datetime import datetime
from src.models.incident_schema import Incident, IncidentPriority, IncidentStatus
from src.models.event_schema import Severity
from src.dashboard.cli_view import render_incident_table, render_incident_detail


def make_incident(status=IncidentStatus.OPEN, risk_score=50, title="Test"):
    return Incident(
        title=title, priority=IncidentPriority.P2_HIGH, severity=Severity.HIGH,
        status=status, correlation_key="user:admin",
        first_seen=datetime.now(), last_seen=datetime.now(), risk_score=risk_score,
    )


def test_empty_incident_list_shows_clear_message():
    result = render_incident_table([])
    assert "No open incidents" in result


def test_closed_incidents_excluded_from_table():
    incidents = [make_incident(status=IncidentStatus.CLOSED, risk_score=99)]
    result = render_incident_table(incidents)
    assert "No open incidents" in result


def test_incidents_sorted_by_risk_descending():
    low = make_incident(risk_score=20, title="Low Risk")
    high = make_incident(risk_score=90, title="High Risk")
    result = render_incident_table([low, high])

    assert result.index("High Risk") < result.index("Low Risk")


def test_detail_view_shows_no_ai_message_when_not_investigated():
    incident = make_incident()
    result = render_incident_detail(incident)
    assert "AI Investigation: not yet run" in result


def test_detail_view_shows_ai_verdict_when_present():
    incident = make_incident()
    incident.ai_verdict = "This looks like a credential stuffing attempt."
    incident.recommended_actions = ["Reset password", "Enable MFA"]
    result = render_incident_detail(incident)
    assert "credential stuffing" in result
    assert "Reset password" in result