# src/models/detection_schema.py

from pydantic import BaseModel, Field
from typing import Optional
from src.models.event_schema import Severity


class DetectionResult(BaseModel):
    """
    نتيجة تحليل event واحد أو مجموعة events عن طريق الـDetection Engine.
    ده الـoutput اللي هيتبعت بعدين للـcorrelation والـAI.
    """

    rule_name: str                     # اسم القاعدة اللي طلقت (fired)
    rule_id: str                       # معرّف فريد للقاعدة (زي Sigma rule id)
    triggered: bool                    # هل القاعدة اتفعّلت ولا لأ
    severity: Severity                 # الـseverity الناتجة من القاعدة نفسها
    mitre_technique: Optional[str] = None   # مثلاً "T1110"
    mitre_tactic: Optional[str] = None      # مثلاً "Credential Access"
    description: str                   # شرح مختصر ليه القاعدة اتفعّلت
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)  # ثقة القاعدة (deterministic rules غالبًا 1.0)
    reopen_window_hours: int = Field(
        default=48,
        description=(
            "How many hours after closure this incident type can be reopened "
            "instead of creating a new incident. Based on typical attacker "
            "behavior for this specific technique (e.g., brute force retries "
            "fast, C2 beacons may retry after weeks)."
        ),
    )