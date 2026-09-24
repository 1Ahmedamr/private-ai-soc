# tests/unit/test_ioc_store.py

import tempfile
import json
import os
from datetime import datetime
from src.threat_intel.ioc_store import IOCStore
from src.models.event_schema import NormalizedEvent, EventSource, EventType


def make_store_with_data(ips=None, domains=None) -> IOCStore:
    store = IOCStore()
    if ips:
        for ip in ips:
            store.malicious_ips.add(ip)
            store._ip_metadata[ip] = {"threat_name": "test", "confidence": 0.9, "source": "test"}
    if domains:
        for d in domains:
            store.malicious_domains.add(d)
            store._domain_metadata[d] = {"threat_name": "test", "confidence": 0.8, "source": "test"}
    return store


def make_event(src_ip=None, dst_ip=None, event_id=None):
    return NormalizedEvent(
        timestamp=datetime.now(), source=EventSource.WINDOWS,
        event_type=EventType.AUTHENTICATION,
        src_ip=src_ip, dst_ip=dst_ip, event_id=event_id,
    )


def test_known_malicious_ip_detected():
    store = make_store_with_data(ips=["1.2.3.4"])
    match = store.check_ip("1.2.3.4")
    assert match is not None
    assert match.ioc_value == "1.2.3.4"
    assert match.ioc_type == "ip"


def test_clean_ip_not_detected():
    store = make_store_with_data(ips=["1.2.3.4"])
    match = store.check_ip("10.0.0.1")
    assert match is None


def test_check_event_matches_src_ip():
    store = make_store_with_data(ips=["45.33.12.99"])
    event = make_event(src_ip="45.33.12.99")
    matches = store.check_event(event)
    assert len(matches) == 1
    assert matches[0].ioc_value == "45.33.12.99"


def test_check_event_matches_dst_ip():
    store = make_store_with_data(ips=["78.31.67.7"])
    event = make_event(dst_ip="78.31.67.7")
    matches = store.check_event(event)
    assert len(matches) == 1


def test_check_event_no_match_returns_empty():
    store = make_store_with_data(ips=["1.2.3.4"])
    event = make_event(src_ip="10.0.0.1", dst_ip="192.168.1.1")
    matches = store.check_event(event)
    assert len(matches) == 0


def test_load_json_ioc_file():
    store = IOCStore()
    with tempfile.TemporaryDirectory() as tmpdir:
        from pathlib import Path
        ioc_file = Path(tmpdir) / "test_ips.json"
        ioc_file.write_text(json.dumps([
            {"value": "5.6.7.8", "type": "ip", "threat_name": "TestThreat", "confidence": 0.9}
        ]))
        store.IOC_DIR = Path(tmpdir)
        store._load_json(ioc_file)
    assert "5.6.7.8" in store.malicious_ips


def test_domain_check():
    store = make_store_with_data(domains=["evil.com"])
    match = store.check_domain("evil.com")
    assert match is not None
    assert match.ioc_type == "domain"
