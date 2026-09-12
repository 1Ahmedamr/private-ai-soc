# src/ai/verdict.py

from pydantic import BaseModel, Field
from typing import List


class InvestigationVerdict(BaseModel):
    """
    What we REQUIRE the LLM to return - validated, not trusted blindly.
    If the model's response doesn't fit this shape, we treat it as a
    failed investigation, not a false incident verdict.
    """
    summary: str = Field(max_length=1000)
    likely_attack_stage: str          # e.g. "Initial Access", "Credential Access" - descriptive, non-authoritative
    recommended_actions: List[str] = Field(max_length=6)
    analyst_confidence_note: str      # AI's OWN stated uncertainty - not a number we treat as ground truth