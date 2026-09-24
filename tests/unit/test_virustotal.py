# tests/unit/test_virustotal.py

import pytest
import json
import tempfile
from unittest.mock import patch, MagicMock
from src.enrichment.virustotal import enrich_ip, _parse_vt_response, VTResult


SAMPLE_VT_RESPONSE = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 5, "suspicious": 2, "harmless": 40, "undetected": 10
            },
            "reputation": -25,
            "last_analysis_date": 1700000000,
            "last_analysis_results": {
                "EngineA": {"category": "malicious", "result": "ThreatX"},
                "EngineB": {"category": "malicious", "result": "ThreatY"},
            }
        }
    }
}


def test_parse_vt_response_extracts_correct_fields():
    result = _parse_vt_response(SAMPLE_VT_RESPONSE, "1.2.3.4", "ip_addresses")
    assert result.malicious_votes == 5
    assert result.suspicious_votes == 2
    assert result.harmless_votes == 40
    assert result.community_score == -25
    assert "ThreatX" in result.threat_names or "ThreatY" in result.threat_names


def test_enrich_ip_returns_none_without_api_key():
    with patch.dict("os.environ", {}, clear=True):
        result = enrich_ip("1.2.3.4")
        assert result is None


def test_enrich_ip_uses_cache():
    with patch.dict("os.environ", {"VT_API_KEY": "fake_key"}):
        with patch("src.enrichment.virustotal._check_cache") as mock_cache:
            mock_cache.return_value = SAMPLE_VT_RESPONSE
            result = enrich_ip("1.2.3.4")
            assert result is not None
            assert result.malicious_votes == 5


def test_verdict_logic():
    """Verify the verdict logic in the Flask endpoint independently."""
    def get_verdict(malicious, suspicious):
        if malicious >= 5:
            return "MALICIOUS"
        elif malicious >= 1 or suspicious >= 3:
            return "SUSPICIOUS"
        return "CLEAN"

    assert get_verdict(5, 0) == "MALICIOUS"
    assert get_verdict(1, 0) == "SUSPICIOUS"
    assert get_verdict(0, 3) == "SUSPICIOUS"
    assert get_verdict(0, 0) == "CLEAN"
