# src/mitre/techniques.py

from pydantic import BaseModel
from src.mitre.models import MitreTechnique
from typing import Dict, Optional
from src.mitre.import_dataset import load_full_mitre_dataset

_FULL_DATASET_CACHE: dict = {}





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
        "T1046": MitreTechnique(
        technique_id="T1046",
        name="Network Service Discovery",
        tactic="Discovery",
        url="https://attack.mitre.org/techniques/T1046/",
    ),
}


def get_technique(technique_id: str):
    """
    Looks up a technique - tries the full imported MITRE dataset first
    (if available), falls back to our small hardcoded set otherwise.

    Why keep the hardcoded 4 at all now? Because the full dataset is a
    ~50MB file a fresh clone won't have until someone runs the download
    step from INSTALLATION.md. The hardcoded fallback means the 4
    techniques our OWN detection rules actually reference (T1110,
    T1110.001, T1078, T1046) always work, even before that setup step -
    the system degrades gracefully rather than breaking.
    """
    global _FULL_DATASET_CACHE
    if not _FULL_DATASET_CACHE:
        _FULL_DATASET_CACHE = load_full_mitre_dataset()

    if technique_id in _FULL_DATASET_CACHE:
        return _FULL_DATASET_CACHE[technique_id]
    return MITRE_TECHNIQUES.get(technique_id)