# tests/unit/test_mitre_naming.py

from src.mitre.naming import format_tactic
from src.sigma.evaluator import SigmaRule


def test_format_tactic_unifies_all_spellings():
    assert format_tactic("command-and-control") == "Command and Control"
    assert format_tactic("Command And Control") == "Command and Control"
    assert format_tactic("defense_evasion") == "Defense Evasion"
    assert format_tactic("initial-access") == "Initial Access"


def test_sigma_tags_split_correctly_and_ignore_groups_and_software():
    rule = SigmaRule({"title": "t", "tags": [
        "attack.g0047", "attack.s0002", "attack.execution",
        "attack.t1059.001", "attack.command-and-control",
    ]})
    assert rule.mitre_techniques == ["T1059.001"]
    assert rule.mitre_tactics == ["Execution", "Command and Control"]
