# tests/unit/test_suspicious_dns.py

from datetime import datetime
from src.models.event_schema import NormalizedEvent, EventSource, EventType
from src.detection.rules.suspicious_dns import detect_suspicious_dns, _shannon_entropy


def make_dns_event(domain, ts=None):
    return NormalizedEvent(
        timestamp=ts or datetime.now(), source=EventSource.ZEEK,
        event_type=EventType.DNS_QUERY, src_ip="10.0.0.5", event_id=domain,
    )


def test_high_entropy_domain_triggers():
    events = [make_dns_event("a3f8k2p9m1q7.evil.com")]
    result = detect_suspicious_dns(events, entropy_threshold=3.5)
    assert result.triggered is True
    assert result.mitre_technique == "T1568"


def test_normal_domain_does_not_trigger():
    events = [make_dns_event("google.com")]
    result = detect_suspicious_dns(events, entropy_threshold=3.5)
    assert result.triggered is False


def test_short_subdomain_does_not_trigger_even_if_high_entropy():
    events = [make_dns_event("xk7.evil.com")]
    result = detect_suspicious_dns(events, entropy_threshold=3.5)
    assert result.triggered is False


def test_non_dns_events_ignored():
    event = NormalizedEvent(
        timestamp=datetime.now(), source=EventSource.WINDOWS,
        event_type=EventType.AUTHENTICATION, user="admin", event_id="4625", status="failure",
    )
    result = detect_suspicious_dns([event])
    assert result.triggered is False


def test_shannon_entropy_increases_with_randomness():
    assert _shannon_entropy("aaaaaaa") < _shannon_entropy("xk7q9zvbn2")
