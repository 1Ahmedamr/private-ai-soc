from src.ai.guard import sanitize_ai_text
from src.correlation.assessment import build_assessment


def test_roles_and_compromise_wording_removed_and_noted():
    out = sanitize_ai_text("**Attacker:** 1.2.3.4. Victim: 10.0.0.5, a compromised endpoint. Immediate containment advised.")
    low = out.lower()
    assert "attacker" not in low and "victim" not in low
    assert "compromised endpoint" not in low and "immediate containment" not in low
    assert "Wording adjusted" in out


def test_clean_text_is_untouched():
    t = "Communication observed between 1.2.3.4 and 10.0.0.5."
    assert sanitize_ai_text(t) == t


def test_informational_phrase_stripped_only_for_et_malware():
    s = "Traffic matched. Informational signature matched. More."
    assert "Informational" not in sanitize_ai_text(s, "ET MALWARE BackConnect", add_note=False)
    assert "Informational" in sanitize_ai_text(s, "ET INFO PE EXE", add_note=False)


def test_assessment_counts_indicators_and_never_attributes():
    entries = [
        {"title": "Possible C2 Beacon (Periodic Connections)", "evidence": ["High-entropy domain queried: 'x.com'"]},
        {"title": "Suricata Signature Match", "evidence": ["ET MALWARE BackConnect CnC"]},
        {"title": "Suricata Signature Match", "evidence": ["ET INFO PE EXE or DLL Windows file download"]},
    ]
    a = build_assessment(entries, "172.17.5.135")
    assert a["confidence"] == "Medium-High" and len(a["indicators"]) == 4
    assert "not determined" in a["attribution"] and "172.17.5.135" in a["text"]
