# src/models/incident_schema.py

from pydantic import BaseModel, Field
from datetime import datetime
from typing import List, Optional
from enum import Enum
import uuid

from src.models.event_schema import NormalizedEvent, Severity
from src.models.detection_schema import DetectionResult


class IncidentStatus(str, Enum):
    """
    حالات دورة حياة الـIncident.

    ليه مهم نحدد الحالات دي من الأول؟
    لأن أي SOC platform حقيقي (Splunk, QRadar, Sentinel) عنده
    workflow واضح لكل incident - مش مجرد "موجود" أو "مش موجود".
    ده بيسمح للـanalyst يعرف "إيه اللي محتاج اهتمام دلوقتي؟"
    """
    OPEN = "open"                    # لسه محدش شافه
    INVESTIGATING = "investigating"  # analyst شغال عليه دلوقتي
    ESCALATED = "escalated"          # اتصعّد لمستوى أعلى (Tier 2/3)
    RESOLVED = "resolved"            # اتحل - كان تهديد حقيقي واتعالج
    FALSE_POSITIVE = "false_positive" # اتفحص وطلع مش خطر فعلي
    CLOSED = "closed"                # مقفول نهائيًا (بعد resolved أو false_positive)


class IncidentPriority(str, Enum):
    """
    الأولوية - مختلفة عن الـseverity.

    الفرق المهم:
    - Severity = مدى خطورة التهديد نفسه (تقني)
    - Priority = ترتيب الاستجابة (عملي/تشغيلي) - بيتأثر بالـseverity
      لكن كمان بعوامل تانية زي: الأصل المتأثر (Domain Controller أهم من
      جهاز موظف عادي) أو وقت الاكتشاف
    """
    P1_CRITICAL = "p1_critical"   # استجابة فورية (دقائق)
    P2_HIGH = "p2_high"           # استجابة سريعة (ساعة)
    P3_MEDIUM = "p3_medium"       # استجابة خلال يوم عمل
    P4_LOW = "p4_low"             # مراجعة دورية


class Incident(BaseModel):
    """
    الـIncident هو الـcontainer الرئيسي اللي بيجمع:
    - الـevents الأصلية (الدليل الخام)
    - الـdetections اللي أدت لفتحه
    - معلومات وصفية (severity, status, priority, timeline)
    """

    incident_id: str = Field(default_factory=lambda: f"INC-{uuid.uuid4().hex[:8].upper()}")
    title: str
    status: IncidentStatus = IncidentStatus.OPEN
    priority: IncidentPriority
    severity: Severity

    # --- Correlation identity - إيه اللي بيربط الأحداث دي مع بعض ---
    correlation_key: str    # مثلاً "user:admin" أو "ip:10.0.0.15"

    # --- Evidence ---
    events: List[NormalizedEvent] = Field(default_factory=list)
    detections: List[DetectionResult] = Field(default_factory=list)

    # --- MITRE Mapping (من الـdetections) ---
    mitre_techniques: List[str] = Field(default_factory=list)

    # --- Timeline ---
    first_seen: datetime
    last_seen: datetime
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)

    # --- Assignment (هنستخدمها بعدين لما نعمل multi-analyst support) ---
    assigned_to: Optional[str] = None

    # --- AI investigation output (هنملاها بعد ما نوصل لمرحلة الـAI investigation) ---
    ai_verdict: Optional[str] = None
    ai_confidence: Optional[float] = None
    recommended_actions: List[str] = Field(default_factory=list)

    def add_detection(self, detection: DetectionResult) -> None:
        """إضافة detection جديد للـincident وتحديث الـmetadata المرتبطة."""
        self.detections.append(detection)
        if detection.mitre_technique and detection.mitre_technique not in self.mitre_techniques:
            self.mitre_techniques.append(detection.mitre_technique)
        self.updated_at = datetime.now()

    def escalate_severity_if_needed(self, new_severity: Severity) -> None:
        """
        لو جاله detection جديد بseverity أعلى من الموجودة، نرفّع الـincident.
        ليه بالطريقة دي مش بنخليها تنزل تاني؟
        لأن الـincident لازم يعكس "أعلى خطر شوهد فيه طول عمره" - 
        النزول للأسفل يخفي تاريخ الخطورة الحقيقي.
        """
        severity_order = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        if severity_order[new_severity] > severity_order[self.severity]:
            self.severity = new_severity
            self.updated_at = datetime.now()