# src/detection/engine.py

from typing import List
from src.models.event_schema import NormalizedEvent
from src.models.detection_schema import DetectionResult
from src.detection.rules.failed_login import detect_failed_login
from src.detection.rules.brute_force import detect_brute_force
from src.detection.rules.port_scan import detect_port_scan, detect_slow_port_scan
from src.detection.rules.ssh_root_brute_force import detect_ssh_root_brute_force


class DetectionEngine:
    def __init__(self):
        self.single_event_rules = [detect_failed_login]

    def run_single_event_rules(self, event: NormalizedEvent) -> List[DetectionResult]:
        results = []
        for rule_func in self.single_event_rules:
            result = rule_func(event)
            if result.triggered:
                results.append(result)
        return results

    def run_batch_rules(self, events: List[NormalizedEvent]) -> List[DetectionResult]:
        results = []

        brute_force_result = detect_brute_force(events)
        if brute_force_result.triggered:
            results.append(brute_force_result)

        ssh_root_result = detect_ssh_root_brute_force(events)
        if ssh_root_result.triggered:
            results.append(ssh_root_result)

        fast_scan_result = detect_port_scan(events)
        if fast_scan_result.triggered:
            results.append(fast_scan_result)
        else:
            slow_scan_result = detect_slow_port_scan(events)
            if slow_scan_result.triggered:
                results.append(slow_scan_result)

        return results

    def analyze(self, events: List[NormalizedEvent]) -> List[DetectionResult]:
        all_results: List[DetectionResult] = []
        for event in events:
            all_results.extend(self.run_single_event_rules(event))
        all_results.extend(self.run_batch_rules(events))
        return all_results