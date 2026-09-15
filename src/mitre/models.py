# src/mitre/models.py

from pydantic import BaseModel
from typing import Optional


class MitreTechnique(BaseModel):
    """
    Structured representation of a single MITRE ATT&CK technique.
    Lives in its own file (not techniques.py or import_dataset.py)
    specifically to avoid a circular import: both techniques.py and
    import_dataset.py need this class, but must not import each other.
    """
    technique_id: str
    name: str
    tactic: str
    sub_technique: Optional[str] = None
    url: str