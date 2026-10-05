# tests/unit/test_ioc_context.py
"""IOC reputation context is enrichment: visible to the analyst, invisible to scoring."""

from src.ai.evidence import InvestigationEvidence, build_ioc_context
from src.threat_intel.ioc_store import IOCStore

LISTED = "203.0.113.50"


def make_store():
    store = IOCStore()
    store.malicious_ips.add(LISTED)
    store._ip_metadata[LISTED] = {
        "threat_name": "test-threat", "confidence": 0.6, "source": "unit-test-feed"}
    return store


def test_listed_ip_gets_reputation_context():
    ctx = build_ioc_context([LISTED], store=make_store())
    assert ctx == [{"ip": LISTED, "feed": "unit-test-feed",
                    "threat": "test-threat", "confidence": 0.6}]


def test_unlisted_ip_gets_no_context():
    assert build_ioc_context(["198.51.100.7"], store=make_store()) == []


def test_duplicates_and_empty_values_are_ignored():
    ctx = build_ioc_context([LISTED, None, "", LISTED], store=make_store())
    assert len(ctx) == 1


def test_evidence_defaults_to_no_ioc_context():
    ev = InvestigationEvidence(
        incident_id="INC-AAAAAAAA", title="t", severity="high", risk_score=50,
        correlation_key="ip:1.2.3.4", mitre_techniques=[], detection_descriptions=[],
        event_count=1, first_seen="2026-10-06T10:00:00", last_seen="2026-10-06T10:00:00",
        is_reopened_incident=False,
    )
    assert ev.ioc_context == []
