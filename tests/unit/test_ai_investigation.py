# tests/unit/test_ai_investigation.py

from unittest.mock import patch
from datetime import datetime
from src.models.incident_schema import Incident, IncidentPriority
from src.models.event_schema import Severity
from src.ai.evidence import build_evidence
from src.ai.verdict import InvestigationVerdict
from src.ai.ollama_client import investigate


def make_incident():
    return Incident(
        title="Brute Force Detection", priority=IncidentPriority.P2_HIGH, severity=Severity.HIGH,
        correlation_key="user:admin", first_seen=datetime.now(), last_seen=datetime.now(), risk_score=57,
    )


def test_build_evidence_excludes_raw_data():
    incident = make_incident()
    evidence = build_evidence(incident)
    assert not hasattr(evidence, "raw_data")
    assert evidence.severity == "high"


@patch("src.ai.ollama_client.requests.post")
def test_investigate_returns_none_on_connection_failure(mock_post):
    mock_post.side_effect = ConnectionError("Ollama not running")
    evidence = build_evidence(make_incident())
    result = investigate(evidence)
    assert result is None


@patch("src.ai.ollama_client.requests.post")
def test_investigate_parses_valid_response(mock_post):
    mock_response = mock_post.return_value
    mock_response.json.return_value = {
        "response": '{"summary": "Brute force detected.", "likely_attack_stage": "Credential Access", "recommended_actions": ["Reset password", "Block source IP"], "analyst_confidence_note": "High confidence based on pattern."}'
    }
    mock_response.raise_for_status = lambda: None

    evidence = build_evidence(make_incident())
    result = investigate(evidence)

    assert result is not None
    assert isinstance(result, InvestigationVerdict)
    assert "Reset password" in result.recommended_actions


@patch("src.ai.ollama_client.requests.post")
def test_investigate_returns_none_on_malformed_json(mock_post):
    mock_response = mock_post.return_value
    mock_response.json.return_value = {"response": "not valid json at all"}
    mock_response.raise_for_status = lambda: None

    evidence = build_evidence(make_incident())
    result = investigate(evidence)
    assert result is None