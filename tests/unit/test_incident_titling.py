from src.incidents.titling import strongest_title
from src.models.detection_schema import DetectionResult
from src.models.event_schema import Severity


def det(name, sev, conf):
    return DetectionResult(rule_name=name, rule_id=name, triggered=True,
                           severity=sev, description="d", confidence=conf)


def test_highest_severity_wins_over_first_detection():
    ds = [det("Suricata Signature Match", Severity.HIGH, 0.9),
          det("Possible C2 Beacon (Periodic Connections)", Severity.CRITICAL, 0.85)]
    assert strongest_title(ds, "x") == "Possible C2 Beacon (Periodic Connections)"


def test_confidence_breaks_severity_ties():
    ds = [det("A", Severity.HIGH, 0.6), det("B", Severity.HIGH, 0.9)]
    assert strongest_title(ds, "x") == "B"


def test_no_detections_keeps_fallback():
    assert strongest_title([], "keep me") == "keep me"
