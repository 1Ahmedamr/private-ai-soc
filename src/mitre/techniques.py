# src/mitre/techniques.py

from pydantic import BaseModel
from typing import Dict, Optional


class MitreTechnique(BaseModel):
    """
    Structured representation of a single MITRE ATT&CK technique.
    """
    technique_id: str      # e.g. "T1110"
    name: str               # e.g. "Brute Force"
    tactic: str             # e.g. "Credential Access"
    sub_technique: Optional[str] = None   # e.g. "T1110.001" for "Password Guessing"
    url: str


# This is a small local knowledge base of techniques relevant to our
# current detection rules. In a later phase (RAG / Knowledge Base),
# we'll expand this by pulling the full MITRE ATT&CK dataset (via their
# public STIX/JSON feed) instead of hardcoding entries manually.
MITRE_TECHNIQUES: Dict[str, MitreTechnique] = {
    "T1110": MitreTechnique(
        technique_id="T1110",
        name="Brute Force",
        tactic="Credential Access",
        url="https://attack.mitre.org/techniques/T1110/",
    ),
    "T1110.001": MitreTechnique(
        technique_id="T1110.001",
        name="Password Guessing",
        tactic="Credential Access",
        sub_technique="T1110.001",
        url="https://attack.mitre.org/techniques/T1110/001/",
    ),
    "T1078": MitreTechnique(
        technique_id="T1078",
        name="Valid Accounts",
        tactic="Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        url="https://attack.mitre.org/techniques/T1078/",
    ),
}


def get_technique(technique_id: str) -> Optional[MitreTechnique]:
    """
    Safe lookup function. Returns None instead of raising an error
    if the technique isn't in our local knowledge base yet.

    Why return None instead of raising an exception?
    Because a missing MITRE mapping shouldn't crash the whole detection
    pipeline. If a rule references a technique ID we haven't added yet,
    we want the system to keep working (perhaps logging a warning) rather
    than failing the entire analysis.
    """
    return MITRE_TECHNIQUES.get(technique_id)