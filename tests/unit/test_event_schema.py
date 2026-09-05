# tests/unit/test_event_schema.py

import pytest
from datetime import datetime
from src.models.event_schema import NormalizedEvent, EventSource, EventType, Severity


def test_valid_normalized_event():
    event = NormalizedEvent(
        timestamp=datetime.now(),
        source=EventSource.WINDOWS,
        event_type=EventType.AUTHENTICATION,
        user="administrator",
        src_ip="10.0.0.50",
        event_id="4625",
        status="failure",
        severity=Severity.MEDIUM,
    )
    assert event.source == "windows"
    assert event.status == "failure"


def test_invalid_ip_raises_error():
    with pytest.raises(ValueError):
        NormalizedEvent(
            timestamp=datetime.now(),
            source=EventSource.WINDOWS,
            event_type=EventType.AUTHENTICATION,
            src_ip="999.999.999.999",  # IP غلط عمدًا
        )


def test_raw_data_preserved():
    raw = {"TargetUserName": "admin", "IpAddress": "10.0.0.5"}
    event = NormalizedEvent(
        timestamp=datetime.now(),
        source=EventSource.WINDOWS,
        event_type=EventType.AUTHENTICATION,
        raw_data=raw,
    )
    assert event.raw_data == raw