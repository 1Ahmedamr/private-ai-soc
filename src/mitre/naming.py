# src/mitre/naming.py

_LOWERCASE_WORDS = {"and", "of"}


def format_tactic(raw: str) -> str:
    """
    One canonical spelling for ATT&CK tactic names, whatever the source
    wrote ("command-and-control", "defense_evasion", "Command And Control").
    Matches ATT&CK's own style: "Command and Control", "Defense Evasion".
    """
    words = raw.replace("-", " ").replace("_", " ").split()
    return " ".join(
        w.lower() if w.lower() in _LOWERCASE_WORDS else w.capitalize()
        for w in words
    )
