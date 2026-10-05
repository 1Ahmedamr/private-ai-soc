# tests/unit/test_ioc_detection_direction.py
"""
IOC detections must say what a match MEANS, not just that it happened.

  outbound (our host -> known-bad destination or DNS query): possible C2, T1071
  inbound  (known-bad source -> us): reputation context only, no ATT&CK technique
"""

from datetime import datetime

import pytest

from src.detection import engine as engine_module
from src.detection.engine import DetectionEngine
from src.incidents.policy import should_open_incident
from src.models.event_schema import EventSource, EventType, NormalizedEvent, Severity
from src.threat_intel.ioc_store import IOCStore

BAD_IP = "203.0.113.50"
BAD_DOMAIN = "evil.example"
NOW = datetime(2026, 10, 6, 10, 0, 0)


def make_store(ip_confidence=0.9):
    store = IOCStore()
    store.malicious_ips.add(BAD_IP)
    store._ip_metadata[BAD_IP] = {
        "threat_name": "test-ip", "confidence": ip_confidence, "source": "unit-test"}
    store.malicious_domains.add(BAD_DOMAIN)
    store._domain_metadata[BAD_DOMAIN] = {
        "threat_name": "test-domain", "confidence": 0.9, "source": "unit-test"}
    return store


@pytest.fixture
def run_ioc(monkeypatch):
    def _run(events, ip_confidence=0.9):
        store = make_store(ip_confidence)
        monkeypatch.setattr(engine_module, "get_ioc_store", lambda: store)
        return DetectionEngine().run_ioc_checks(events)
    return _run


def event(event_type, host="WS01", src_ip=None, dst_ip=None, event_id=None):
    return NormalizedEvent(
        timestamp=NOW, source=EventSource.ZEEK, event_type=event_type,
        host=host, src_ip=src_ip, dst_ip=dst_ip, event_id=event_id,
    )


def test_outbound_match_is_high_and_mapped_to_c2(run_ioc):
    results = run_ioc([event(EventType.NETWORK_CONNECTION, src_ip="10.0.0.5", dst_ip=BAD_IP)])
    assert len(results) == 1
    d = results[0]
    assert d.rule_name == "IOC Match: IP"
    assert d.severity == Severity.HIGH
    assert (d.mitre_technique, d.mitre_tactic) == ("T1071", "Command and Control")


def test_inbound_match_asserts_no_attack_technique(run_ioc):
    results = run_ioc([event(EventType.AUTHENTICATION, src_ip=BAD_IP)])
    assert len(results) == 1
    d = results[0]
    assert d.rule_name == "IOC Match: IP (inbound)"
    assert d.severity == Severity.MEDIUM
    assert d.mitre_technique is None and d.mitre_tactic is None


def test_weak_inbound_match_is_low_and_does_not_open_an_incident(run_ioc):
    results = run_ioc([event(EventType.AUTHENTICATION, src_ip=BAD_IP)], ip_confidence=0.6)
    assert results[0].severity == Severity.LOW
    assert should_open_incident(results[0]) is False


def test_one_detection_lists_every_affected_host(run_ioc):
    results = run_ioc([
        event(EventType.NETWORK_CONNECTION, host="WS01", dst_ip=BAD_IP),
        event(EventType.NETWORK_CONNECTION, host="WS02", dst_ip=BAD_IP),
    ])
    assert len(results) == 1
    assert "WS01" in results[0].description and "WS02" in results[0].description


def test_domain_is_only_checked_on_dns_events(run_ioc):
    assert run_ioc([event(EventType.AUTHENTICATION, event_id=BAD_DOMAIN)]) == []
    results = run_ioc([event(EventType.DNS_QUERY, event_id=BAD_DOMAIN)])
    assert [d.rule_name for d in results] == ["IOC Match: DOMAIN"]
    assert results[0].severity == Severity.HIGH


def test_inbound_and_outbound_hits_on_same_ip_are_kept_apart(run_ioc):
    results = run_ioc([
        event(EventType.AUTHENTICATION, src_ip=BAD_IP),
        event(EventType.NETWORK_CONNECTION, dst_ip=BAD_IP),
    ])
    assert sorted(d.rule_name for d in results) == ["IOC Match: IP", "IOC Match: IP (inbound)"]


def test_description_quotes_the_ip_for_the_evidence_extractor(run_ioc):
    # src/ai/evidence.py recovers IPs from detection descriptions with a regex
    d = run_ioc([event(EventType.NETWORK_CONNECTION, dst_ip=BAD_IP)])[0]
    assert f"'{BAD_IP}'" in d.description
