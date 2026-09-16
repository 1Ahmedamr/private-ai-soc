# src/mitre/techniques.py

from typing import Dict, Optional
from src.mitre.models import MitreTechnique
from src.mitre.import_dataset import load_full_mitre_dataset

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
    "T1568": MitreTechnique(
        technique_id="T1568",
        name="Dynamic Resolution",
        tactic="Command and Control",
        url="https://attack.mitre.org/techniques/T1568/",
    ),
    "T1059.001": MitreTechnique(
        technique_id="T1059.001",
        name="PowerShell",
        tactic="Execution",
        url="https://attack.mitre.org/techniques/T1059/001/",
    ),
    "T1071": MitreTechnique(
        technique_id="T1071",
        name="Application Layer Protocol",
        tactic="Command and Control",
        url="https://attack.mitre.org/techniques/T1071/",
    ),
}

_FULL_DATASET_CACHE: dict = {}


def get_technique(technique_id: str) -> Optional[MitreTechnique]:
    global _FULL_DATASET_CACHE
    if not _FULL_DATASET_CACHE:
        _FULL_DATASET_CACHE = load_full_mitre_dataset()

    if technique_id in _FULL_DATASET_CACHE:
        return _FULL_DATASET_CACHE[technique_id]
    return MITRE_TECHNIQUES.get(technique_id)
