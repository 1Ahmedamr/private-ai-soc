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