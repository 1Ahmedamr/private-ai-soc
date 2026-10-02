# tests/unit/test_ai_guard.py

from src.ai.guard import sanitize_ai_text

WINDOWS_EVIDENCE = (
    "Scheduled task '\\WindowsUpdateCheck' was created on host 'WIN10-CLIENT'; "
    "Sigma rule matched: Detects a failed logon attempt from a public IP."
)
SUMMARY = (
    "A scheduled task was created with an encoded PowerShell command. "
    "The presence of multiple Sigma rules indicates potential reconnaissance or lateral movement."
)


def test_unsupported_lateral_movement_sentence_is_removed():
    out = sanitize_ai_text(SUMMARY, WINDOWS_EVIDENCE, add_note=False)
    assert "lateral movement" not in out.lower()
    assert "scheduled task was created" in out


def test_claim_is_kept_when_evidence_supports_it():
    evidence = "Port scan detected: 12 ports probed on 10.0.0.5"
    out = sanitize_ai_text("This looks like reconnaissance activity.", evidence, add_note=False)
    assert "reconnaissance" in out


def test_without_evidence_text_nothing_is_dropped():
    out = sanitize_ai_text("Possible lateral movement.", add_note=False)
    assert "lateral movement" in out


def test_text_is_kept_if_every_sentence_would_be_removed():
    out = sanitize_ai_text("Possible lateral movement.", WINDOWS_EVIDENCE, add_note=False)
    assert out == "Possible lateral movement."


def test_existing_word_replacements_still_work():
    out = sanitize_ai_text("The attacker used a compromised host.", add_note=False)
    assert "attacker" not in out.lower() and "potentially affected host" in out


def test_informational_signature_sentence_removed_for_windows_evidence():
    text = ("Observed facts: a task was created. "
            "Informational signature matched for failed logons from a public IP. "
            "Interpretation: possible persistence.")
    out = sanitize_ai_text(text, WINDOWS_EVIDENCE, add_note=False)
    assert "Informational signature" not in out
    assert "a task was created" in out and "Interpretation" in out


def test_informational_signature_kept_for_et_info_evidence():
    out = sanitize_ai_text("Informational signature matched twice.", "ET INFO Something", add_note=False)
    assert "Informational signature matched" in out


def test_newlines_and_bullets_are_preserved():
    text = "**POSSIBLE INTERPRETATION**\n- Task created.\n- Could indicate lateral movement.\n- Review the task."
    out = sanitize_ai_text(text, WINDOWS_EVIDENCE, add_note=False)
    assert out == "**POSSIBLE INTERPRETATION**\n- Task created.\n- Review the task."


def test_credential_stuffing_claim_removed_without_evidence():
    out = sanitize_ai_text("Failed logons were seen. This may be credential stuffing.", WINDOWS_EVIDENCE, add_note=False)
    assert "stuffing" not in out and "Failed logons were seen" in out