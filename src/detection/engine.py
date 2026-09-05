# src/detection/engine.py

from typing import List
from src.models.event_schema import NormalizedEvent
from src.models.detection_schema import DetectionResult
from src.detection.rules.failed_login import detect_failed_login
from src.detection.rules.brute_force import detect_brute_force


class DetectionEngine:
    """
    المايسترو اللي بيشغل كل الـrules على الـevents الجاية.

    ليه عملنا class بدل دالة واحدة كبيرة؟
    عشان بكرة لما نضيف عشرات الـrules (Sigma-based)، نضيفها هنا
    من غير ما نلمس أي حتة تانية في المشروع. ده تطبيق مباشر
    لمبدأ Separation of Concerns اللي اتكلمنا عنه من Day 1.
    """

    def __init__(self):
        # لسه الـrules قليلة، هنسردها يدويًا. بعدين هتتحمل ديناميكيًا من ملفات Sigma
        self.single_event_rules = [detect_failed_login]

    def run_single_event_rules(self, event: NormalizedEvent) -> List[DetectionResult]:
        """يشغل كل القواعد اللي بتشتغل على event واحد بس."""
        results = []
        for rule_func in self.single_event_rules:
            result = rule_func(event)
            if result.triggered:
                results.append(result)
        return results

    def run_batch_rules(self, events: List[NormalizedEvent]) -> List[DetectionResult]:
        """يشغل القواعد اللي محتاجة تشوف مجموعة events مع بعض (زي brute force)."""
        results = []

        brute_force_result = detect_brute_force(events)
        if brute_force_result.triggered:
            results.append(brute_force_result)

        return results

    def analyze(self, events: List[NormalizedEvent]) -> List[DetectionResult]:
        """
        نقطة الدخول الرئيسية: تاخد كل الـevents وترجع كل الـdetections اللي حصلت.
        """
        all_results: List[DetectionResult] = []

        # نشغل single-event rules على كل event لوحده
        for event in events:
            all_results.extend(self.run_single_event_rules(event))

        # نشغل batch rules على كل الـevents مع بعض
        all_results.extend(self.run_batch_rules(events))

        return all_results