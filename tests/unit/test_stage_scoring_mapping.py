# tests/unit/test_stage_scoring_mapping.py

from datetime import datetime
from types import SimpleNamespace

from src.ai.evidence import compute_attack_stage
from src.detection.engine import DetectionEngine
from src.models.detection_schema import DetectionResult
from src.models.event_schema import Severity
from src.risk.scoring import calculate_risk_score


def _det(name, tactic, confidence):
    return DetectionResult(
        rule_name=name, rule_id=name, triggered=True, severity=Severity.HIGH,
        mitre_tactic=tactic, description=name, confidence=confidence,
    )


def _incident(detections):
    return SimpleNamespace(
        severity=Severity.HIGH, detections=detections, events=[],
        first_seen=datetime(2026, 10, 2, 10, 15), last_seen=datetime(2026, 10, 2, 10, 18),
    )


CHAIN = [
    _det("ps", "Execution", 0.85),
    _det("task", "Persistence", 0.9),
    _det("admin", "Credential Access", 0.8),
    _det("public", "Credential Access", 0.8),
    _det("enc", "Execution", 0.8),
]
ONE_STAGE = [_det(f"d{i}", "Execution", c) for i, c in enumerate([0.85, 0.9, 0.8, 0.8, 0.8])]


def test_stage_lists_persistence_first():
    assert compute_attack_stage(CHAIN) == "Persistence + Execution + Credential Access"


def test_single_tactic_gives_no_override():
    assert compute_attack_stage(ONE_STAGE) == ""


def test_multi_stage_chain_scores_higher_than_single_stage():
    chain, single = calculate_risk_score(_incident(CHAIN)), calculate_risk_score(_incident(ONE_STAGE))
    assert 75 <= chain <= 85
    assert chain > single


def test_failed_logon_t1078_becomes_t1110_without_success():
    match = SimpleNamespace(rule_name="Failed Logon From Public IP", mitre_technique="T1078", mitre_tactic="Defense Evasion")
    events = [SimpleNamespace(event_type="authentication", status="failure")]
    assert DetectionEngine._adjust_logon_mapping(match, events) == ("T1110", "Credential Access")


def test_t1078_kept_when_a_successful_logon_exists():
    match = SimpleNamespace(rule_name="Failed Logon From Public IP", mitre_technique="T1078", mitre_tactic="Defense Evasion")
    events = [SimpleNamespace(event_type="authentication", status="success")]
    assert DetectionEngine._adjust_logon_mapping(match, events) == ("T1078", "Defense Evasion")


def test_comma_separated_tactics_are_split():
    dets = [
        _det("task", "Execution, Persistence, Privilege Escalation", 0.9),
        _det("svc", "Persistence, Privilege Escalation", 0.85),
        _det("bf", "Credential Access", 0.8),
    ]
    assert compute_attack_stage(dets) == "Persistence + Privilege Escalation + Execution + Credential Access"