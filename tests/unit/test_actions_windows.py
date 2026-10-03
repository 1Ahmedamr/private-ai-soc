# tests/unit/test_actions_windows.py

from src.ai.actions import build_actions, _decode_encoded_command

TASK = ("Scheduled task '\\WindowsUpdateCheck' was created on host 'WIN10-CLIENT' by user 'administrator'; "
        "PowerShell with suspicious flags ['-enc', '-encodedcommand']. "
        "Command: powershell.exe -EncodedCommand SQBFAFgA")
BRUTE = "Sigma rule matched: Detects multiple failed Windows logon attempts indicating brute force activity"


def test_encoded_command_is_decoded():
    assert _decode_encoded_command("powershell.exe -EncodedCommand SQBFAFgA") == "IEX"


def test_garbage_payload_is_not_decoded():
    assert _decode_encoded_command("powershell -enc not-base64!!") is None


def test_windows_chain_actions():
    actions = build_actions([TASK, BRUTE], ["185.220.101.45"], [])
    joined = " ".join(actions)
    assert "4624" in joined and "185.220.101.45" in joined
    assert "Decoded PowerShell payload: IEX" in joined
    assert "scheduled task definition on WIN10-CLIENT" in joined
    assert len(actions) <= 5


def test_generic_fallback_still_works():
    assert build_actions([], [], [])[0].startswith("Review the raw events")



BF_DESC = "Brute force pattern detected: 8 failed login attempts for identity 'administrator' within a 5-minute window. [events: 9]"
OK_DESC = ("Successful logon (user 'administrator', host 'WIN10-CLIENT', source IP 185.220.101.45) at "
           "2026-10-02T10:17:00 followed 8 failed attempts in the preceding 30 minutes from the same source IP.")


def test_brute_force_only_uses_known_context():
    actions = build_actions([BF_DESC], ["185.220.101.45"], [], hosts=["WIN10-CLIENT"], users=["administrator"])
    assert actions[0] == (
        "Search the Security log for a successful logon (Event ID 4624) for 'administrator' from 185.220.101.45 "
        "after the failed attempts on WIN10-CLIENT. Failed logons alone do not show the account was accessed."
    )


def test_recorded_success_replaces_the_search_for_one():
    actions = build_actions([BF_DESC, OK_DESC], ["185.220.101.45"], [], hosts=["WIN10-CLIENT"], users=["administrator"])
    assert actions[0].startswith("A successful logon for 'administrator' from 185.220.101.45 follows the failed attempts")
    assert "on WIN10-CLIENT" in actions[0]
    assert "Search the Security log for a successful logon" not in " ".join(actions)