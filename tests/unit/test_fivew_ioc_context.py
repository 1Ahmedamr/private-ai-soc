# tests/unit/test_fivew_ioc_context.py
"""Threat-intel listings reach the 5Ws as reputation context, never as a role."""

from types import SimpleNamespace

from src.ai.fivew import build_5w
from src.pipeline import file_analyzer
from src.threat_intel import ioc_store
from src.threat_intel.ioc_store import IOCStore

LISTED = "203.0.113.50"
LISTING = [{"ip": LISTED, "feed": "emerging_threats", "confidence": 0.6}]

INC = {
    "incident_id": "INC-AAAAAAAA", "title": "Suricata Signature Match", "severity": "medium",
    "risk_score": 40, "correlation_key": f"ip:{LISTED}",
    "first_seen": "2022-12-14T20:36:40.259+00:00", "last_seen": "2022-12-14T20:36:40.672+00:00",
    "mitre_techniques": ["T1105"],
    "key_events": [{"src_ip": LISTED, "dst_ip": "172.17.5.135"}],
    "detections": [{"rule_name": "Suricata Signature Match",
                    "description": "Suricata matched signature 'ET INFO PE EXE or DLL Windows file download HTTP' (3 occurrence(s))."}],
}


def who_block(out):
    return out.split("WHO", 1)[1].split("WHAT", 1)[0]


def test_listing_appears_in_who_block_with_feed_and_confidence():
    out = build_5w(dict(INC, ioc_context=LISTING))
    assert f"{LISTED} in 'emerging_threats' (feed confidence 60%)" in who_block(out)


def test_no_listing_line_without_ioc_context():
    assert "Threat-intel listing" not in build_5w(INC)


def test_listing_wording_assigns_no_role():
    low = build_5w(dict(INC, ioc_context=LISTING)).lower()
    for banned in ("attacker", "victim", "c2 server", "persistence", "compromised"):
        assert banned not in low


def test_session_context_keeps_structured_fields_only(monkeypatch):
    store = IOCStore()
    store.malicious_ips.add(LISTED)
    store._ip_metadata[LISTED] = {
        "threat_name": "text from a remote feed", "confidence": 0.6, "source": "emerging_threats"}
    monkeypatch.setattr(ioc_store, "get_ioc_store", lambda: store)
    inc = SimpleNamespace(correlation_key=f"ip:{LISTED}",
                          events=[SimpleNamespace(src_ip=LISTED, dst_ip="172.17.5.135")])
    assert file_analyzer._ioc_context_for(inc) == LISTING   # no "threat" key
