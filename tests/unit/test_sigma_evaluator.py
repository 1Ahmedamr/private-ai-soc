# tests/unit/test_sigma_evaluator.py

import tempfile
import os
from datetime import datetime
from src.models.event_schema import NormalizedEvent, EventSource, EventType
from src.sigma.evaluator import SigmaRule
from src.sigma.loader import load_sigma_rules


SAMPLE_RULE = {
    "id": "test-rule-001",
    "title": "Test Failed Logon Detection",
    "description": "Detects failed login attempts",
    "status": "stable",
    "level": "medium",
    "tags": ["attack.t1110", "attack.credential_access"],
    "logsource": {"product": "windows", "service": "security"},
    "detection": {
        "selection": {"EventID": "4625"},
        "condition": "selection",
    },
}


def make_event(source=EventSource.WINDOWS, event_id="4625", user="admin"):
    return NormalizedEvent(
        timestamp=datetime.now(), source=source,
        event_type=EventType.AUTHENTICATION, user=user,
        event_id=event_id, status="failure",
    )


def test_sigma_rule_matches_correct_event():
    rule = SigmaRule(SAMPLE_RULE)
    event = make_event(event_id="4625")
    match = rule.evaluate(event)
    assert match is not None
    assert match.rule_name == "Test Failed Logon Detection"
    assert match.mitre_technique == "T1110"


def test_sigma_rule_does_not_match_wrong_event_id():
    rule = SigmaRule(SAMPLE_RULE)
    event = make_event(event_id="4624")  # successful login, not 4625
    match = rule.evaluate(event)
    assert match is None


def test_sigma_rule_skips_wrong_log_source():
    rule = SigmaRule(SAMPLE_RULE)
    event = make_event(source=EventSource.LINUX, event_id="4625")
    match = rule.evaluate(event)
    assert match is None  # Windows rule should not fire on Linux events


def test_sigma_loader_loads_yaml_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        rule_file = os.path.join(tmpdir, "test_rule.yml")
        import yaml
        with open(rule_file, "w") as f:
            yaml.dump(SAMPLE_RULE, f)
        rules = load_sigma_rules(tmpdir)
        assert len(rules) == 1
        assert rules[0].title == "Test Failed Logon Detection"


def test_sigma_loader_skips_invalid_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        bad_file = os.path.join(tmpdir, "bad.yml")
        with open(bad_file, "w") as f:
            f.write("not: valid: yaml: [{")
        rules = load_sigma_rules(tmpdir)
        assert len(rules) == 0


def test_contains_modifier_matches_substring():
    rule_dict = {**SAMPLE_RULE, "detection": {
        "selection": {"User|contains": "admin"},
        "condition": "selection",
    }}
    rule = SigmaRule(rule_dict)
    event = make_event(user="administrator")
    match = rule.evaluate(event)
    assert match is not None


def test_contains_modifier_does_not_match_absent_substring():
    rule_dict = {**SAMPLE_RULE, "detection": {
        "selection": {"User|contains": "hacker"},
        "condition": "selection",
    }}
    rule = SigmaRule(rule_dict)
    event = make_event(user="administrator")
    match = rule.evaluate(event)
    assert match is None