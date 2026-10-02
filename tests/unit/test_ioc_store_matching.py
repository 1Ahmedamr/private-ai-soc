# tests/unit/test_ioc_store_matching.py

from types import SimpleNamespace
from src.threat_intel.ioc_store import IOCStore


def make_store():
    s = IOCStore()
    meta = {"threat_name": "test-threat", "confidence": 0.9, "source": "unit-test"}
    s.malicious_domains.add("evil.com")
    s._domain_metadata["evil.com"] = dict(meta)
    s.malicious_hashes.add("abc123")
    s._hash_metadata["abc123"] = dict(meta)
    return s


def test_subdomain_matches_parent_domain_ioc():
    m = make_store().check_domain("login.sub.evil.com")
    assert m is not None
    assert m.ioc_value == "evil.com"


def test_lookalike_domain_does_not_match():
    assert make_store().check_domain("notevil.com") is None


def test_hash_check_is_case_insensitive():
    assert make_store().check_hash("ABC123") is not None


def test_check_event_matches_file_hash():
    event = SimpleNamespace(src_ip=None, dst_ip=None, event_id=None, file_hash="ABC123")
    matches = make_store().check_event(event)
    assert len(matches) == 1
    assert matches[0].ioc_type == "hash"
