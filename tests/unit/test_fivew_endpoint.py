# tests/unit/test_fivew_endpoint.py

from src.ai.fivew import build_5w

BRUTE = "Brute force pattern detected: 8 failed login attempts for identity 'administrator' within a 5-minute window."
SUCCESS = ("Successful logon (user 'administrator', host 'WIN10-CLIENT', source IP 185.220.101.45) at "
           "2026-10-02T10:17:00 followed 8 failed attempts in the preceding 30 minutes from the same source IP.")


def _incident(source, event_type, detections):
    event = {"timestamp": "2026-10-02T10:15:00", "source": source, "event_type": event_type,
             "src_ip": "185.220.101.45", "dst_ip": None, "user": "administrator", "host": "WIN10-CLIENT",
             "status": "failure", "event_id": "4625"}
    return {
        "incident_id": "INC-435BC147", "title": "Brute Force Detection", "severity": "high", "risk_score": 65,
        "correlation_key": "user:administrator", "mitre_techniques": ["T1110"],
        "first_seen": "2026-10-02T10:15:00", "last_seen": "2026-10-02T10:17:00",
        "detections": [{"rule_name": "x", "description": d} for d in detections],
        "key_events": [event],
    }


def test_windows_incident_is_not_described_as_a_network_capture():
    text = build_5w(_incident("windows", "authentication", [BRUTE, SUCCESS]))
    assert "Network capture only" not in text and "Network evidence only" not in text
    assert "Affected host(s): WIN10-CLIENT" in text and "Account(s): administrator" in text
    assert "185.220.101.45 (external)" in text
    assert "A successful logon for 'administrator' from 185.220.101.45 follows the failed attempts" in text
    assert "Indicators from log data, not confirmed compromise." in text


def test_brute_force_without_success_asks_for_the_4624_search_with_context():
    text = build_5w(_incident("windows", "authentication", [BRUTE]))
    assert "(Event ID 4624) for 'administrator' from 185.220.101.45 after the failed attempts on WIN10-CLIENT" in text


def test_network_incident_keeps_its_original_wording():
    text = build_5w(_incident("zeek", "network_connection", [BRUTE]))
    assert "Network capture only" in text and "Network evidence only" in text
    assert "Affected host(s)" not in text