# src/detection/engine.py

from typing import List
from src.models.event_schema import NormalizedEvent
from src.models.detection_schema import DetectionResult
from src.detection.rules.failed_login import detect_failed_login
from src.detection.rules.brute_force import detect_brute_force
from src.detection.rules.port_scan import detect_port_scan, detect_slow_port_scan
from src.detection.rules.ssh_root_brute_force import detect_ssh_root_brute_force
from src.detection.rules.suricata_signature_match import detect_suricata_alerts
from src.detection.rules.suspicious_dns import detect_suspicious_dns
from src.detection.rules.suspicious_powershell import detect_suspicious_powershell
from src.detection.rules.c2_beacon import detect_c2_beacon
from src.sigma.loader import get_sigma_rules
from src.sigma.evaluator import SigmaMatch


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

        suricata_result = detect_suricata_alerts(events)
        if suricata_result.triggered:
            results.append(suricata_result)

        dns_result = detect_suspicious_dns(events)
        if dns_result.triggered:
            results.append(dns_result)

        powershell_result = detect_suspicious_powershell(events)
        if powershell_result.triggered:
            results.append(powershell_result)

        c2_result = detect_c2_beacon(events)
        if c2_result.triggered:
            results.append(c2_result)

        return results

    def analyze(self, events: List[NormalizedEvent]) -> List[DetectionResult]:
        all_results: List[DetectionResult] = []
        for event in events:
            all_results.extend(self.run_single_event_rules(event))
        all_results.extend(self.run_batch_rules(events))
        all_results.extend(self.run_sigma_rules(events))
        return all_results

    
    def run_sigma_rules(self, events: List[NormalizedEvent]) -> List[DetectionResult]:
        """
        Runs all loaded Sigma rules against each event.
        Pre-filtered by log source inside each rule's evaluate() method,
        so Windows rules never run against Zeek events and vice versa.
        This is what keeps the O(events × rules) cost manageable.
        """
        sigma_rules = get_sigma_rules()
        if not sigma_rules:
            return []

        results = []
        seen_rule_ids = set()  # deduplicate: same rule firing on multiple events = one result

        for event in events:
            for rule in sigma_rules:
                match = rule.evaluate(event)
                if match and match.rule_id not in seen_rule_ids:
                    seen_rule_ids.add(match.rule_id)
                    results.append(DetectionResult(
                        rule_name=f"[Sigma] {match.rule_name}",
                        rule_id=match.rule_id,
                        triggered=True,
                        severity=self._map_sigma_severity(match.severity),
                        mitre_technique=match.mitre_technique,
                        mitre_tactic=match.mitre_tactic,
                        description=f"Sigma rule matched: {match.description}",
                        confidence=0.8,  # slightly lower than hand-written rules
                        reopen_window_hours=48,
                    ))
        return results

    @staticmethod
    def _map_sigma_severity(sigma_level: str):
        from src.models.event_schema import Severity
        return {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "informational": Severity.INFO,
        }.get(sigma_level.lower(), Severity.MEDIUM)