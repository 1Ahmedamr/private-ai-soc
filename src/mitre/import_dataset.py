# src/mitre/import_dataset.py

import json
from pathlib import Path
from typing import Dict
from src.mitre.models import MitreTechnique

DATASET_PATH = Path("data/mitre/enterprise-attack.json")


def load_full_mitre_dataset() -> Dict[str, MitreTechnique]:
    """
    Parses the official MITRE ATT&CK STIX bundle into our simple
    MitreTechnique lookup format. STIX is a verbose, deeply-nested
    format designed for full threat-intel tooling - we only need
    technique_id, name, tactic, and URL, so this function's whole job
    is extracting just that from a much larger structure.
    """
    if not DATASET_PATH.exists():
        return {}

    with open(DATASET_PATH) as f:
        bundle = json.load(f)

    techniques: Dict[str, MitreTechnique] = {}

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        # Extract the T-number from external_references (STIX buries it there)
        technique_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                break
        if not technique_id:
            continue

        tactics = [phase["phase_name"].replace("-", " ").title() for phase in obj.get("kill_chain_phases", [])]

        techniques[technique_id] = MitreTechnique(
            technique_id=technique_id,
            name=obj.get("name", "Unknown"),
            tactic=", ".join(tactics) if tactics else "Unknown",
            url=f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
        )

    return techniques