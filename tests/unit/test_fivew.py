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


def test_layout_has_all_sections_and_flow_from_detection_text():
    inc = dict(INC, detections=[{"rule_name": "r", "description":
        "Highly periodic connections from '172.17.5.135' to '158.255.211.126': 45 sessions, ~302s intervals."}],
        correlation_key="ip:172.17.5.135", key_events=[])
    out = build_5w(inc)
    for section in ("WHO", "WHAT", "WHEN", "WHERE", "WHY / HOW", "NEXT STEPS", "RISK:"):
        assert section in out
    assert "Source IP (as recorded by the detection): 172.17.5.135 (internal)" in out
    assert "Destination IP (as recorded by the detection): 158.255.211.126 (external)" in out
    assert "block" not in out.lower() and "isolate" not in out.lower()


def test_info_only_incident_is_not_staged_as_c2():
    out = build_5w(INC)
    assert "suspected ingress tool transfer" in out and "does not show the file is malicious" in out


def _inc(iid, title, desc, ck, a, b, risk=50):
    return {"incident_id": iid, "title": title, "severity": "high", "risk_score": risk,
            "correlation_key": ck, "first_seen": a, "last_seen": b, "mitre_techniques": [],
            "key_events": [], "detections": [{"rule_name": "r", "description": desc}]}


def test_host_summary_leads_and_lists_external_peers_without_roles():
    incs = [
        _inc("INC-AAAAAAAA", "Beacon", "Highly periodic connections from '172.17.5.135' to '158.255.211.126': 45 sessions",
             "ip:172.17.5.135", "2022-12-14T18:36:00+00:00", "2022-12-14T22:52:00+00:00", 89),
        _inc("INC-BBBBBBBB", "Sig", "Suricata matched signature 'ET MALWARE BackConnect CnC Activity' (14 occurrence(s)).",
             "ip:51.195.169.87", "2022-12-14T19:06:00+00:00", "2022-12-14T22:52:00+00:00", 76),
    ]
    hs = {"victim_ip": "172.17.5.135", "incident_ids": ["INC-AAAAAAAA", "INC-BBBBBBBB"], "highest_severity": "high"}
    out = answer_5w({"incidents": incs, "host_summaries": [hs]}, "give me a 5Ws")
    assert out.index("HOST 172.17.5.135") < out.index("INC-AAAAAAAA - Beacon")
    assert "158.255.211.126" in out and "ASSESSMENT" in out and "not determined" in out
    low = out.lower()
    for banned in ("attacker", "victim", "compromised host"):
        assert banned not in low


def test_targeted_incident_question_skips_host_block():
    incs = [_inc("INC-AAAAAAAA", "Beacon", "x", "ip:1.1.1.1", "2022-12-14T18:00:00+00:00", "2022-12-14T19:00:00+00:00")]
    hs = {"victim_ip": "10.0.0.1", "incident_ids": ["INC-AAAAAAAA"], "highest_severity": "high"}
    assert "HOST " not in answer_5w({"incidents": incs, "host_summaries": [hs]}, "5Ws for INC-AAAAAAAA")
