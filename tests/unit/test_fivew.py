from src.ai.fivew import answer_5w, build_5w

INC = {
    "incident_id": "INC-AAAAAAAA", "title": "Suricata Signature Match", "severity": "medium",
    "risk_score": 40, "correlation_key": "ip:199.127.62.132",
    "first_seen": "2022-12-14T20:36:40.259+00:00", "last_seen": "2022-12-14T20:36:40.672+00:00",
    "mitre_techniques": ["T1105"],
    "key_events": [{"src_ip": "199.127.62.132", "dst_ip": "172.17.5.135"}],
    "detections": [{"rule_name": "Suricata Signature Match",
                    "description": "Suricata matched signature 'ET INFO PE EXE or DLL Windows file download HTTP' (3 occurrence(s))."}],
}


def test_5w_uses_only_evidence_and_assigns_no_roles():
    out = build_5w(INC)
    low = out.lower()
    assert "199.127.62.132 (external)" in out and "172.17.5.135 (internal)" in out
    assert "2022-12-14 20:36:40 UTC" in out
    for banned in ("attacker", "victim", "c2 server", "persistence", "compromised"):
        assert banned not in low
    assert "not determined" in low


def test_answer_orders_by_risk_and_can_target_one_incident():
    other = dict(INC, incident_id="INC-BBBBBBBB", risk_score=90)
    both = answer_5w({"incidents": [INC, other]}, "give me a 5Ws")
    assert both.index("INC-BBBBBBBB") < both.index("INC-AAAAAAAA")
    one = answer_5w({"incidents": [INC, other]}, "5Ws for INC-AAAAAAAA")
    assert "INC-BBBBBBBB" not in one
