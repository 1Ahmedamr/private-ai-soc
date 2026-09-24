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
from src.sigma.loader import get_sigma_index
from src.sigma.evaluator import SigmaMatch
from src.threat_intel.ioc_store import get_ioc_store


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
        from src.detection.rule_analytics import record_rule_fires
        all_results: List[DetectionResult] = []
        for event in events:
            all_results.extend(self.run_single_event_rules(event))
        all_results.extend(self.run_batch_rules(events))
        all_results.extend(self.run_sigma_rules(events))
        all_results.extend(self.run_ioc_checks(events))
        record_rule_fires(all_results)
        return all_results

    
    def run_sigma_rules(self, events: List[NormalizedEvent]) -> List[DetectionResult]:
        """
        Evaluates Sigma rules using the pre-built source index.
        Each event only runs against rules for its specific log source,
        not all rules — this is the critical optimization for large PCAPs.
        """
        index = get_sigma_index()
        results = []
        seen_rule_ids = set()

        for event in events:
            relevant_rules = index.get_rules_for_source(event.source)
            for rule in relevant_rules:
                match = rule.evaluate(event)
                if match and match.rule_id not in seen_rule_ids and match.severity not in ("low", "informational"):
                    seen_rule_ids.add(match.rule_id)
                    results.append(DetectionResult(
                        rule_name=f"[Sigma] {match.rule_name}",
                        rule_id=match.rule_id,
                        triggered=True,
                        severity=self._map_sigma_severity(match.severity),
                        mitre_technique=match.mitre_technique,
                        mitre_tactic=match.mitre_tactic,
                        description=f"Sigma rule matched: {match.description}",
                        confidence=0.8,
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


    def run_ioc_checks(self, events: List[NormalizedEvent]) -> List[DetectionResult]:
        """
        Checks every event's IPs and domains against the local IOC store.
        A single IOC match per unique (src_ip, ioc_value) pair creates one
        DetectionResult — not one per matching event, to avoid noise.
        """
        from src.models.event_schema import Severity
        store = get_ioc_store()
        results = []
        seen = set()

        for event in events:
            matches = store.check_event(event)
            for match in matches:
                dedup_key = (match.ioc_value, match.ioc_type)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                severity = Severity.HIGH if match.confidence >= 0.8 else Severity.MEDIUM
                results.append(DetectionResult(
                    rule_name=f"IOC Match: {match.ioc_type.upper()}",
                    rule_id=f"SOC-IOC-{match.ioc_type.upper()}-001",
                    triggered=True,
                    severity=severity,
                    mitre_technique=None,
                    mitre_tactic=None,
                    description=(
                        f"IOC match: {match.ioc_type} '{match.ioc_value}' found in local "
                        f"threat intel feed '{match.source}'. "
                        f"Threat: {match.threat_name}. "
                        f"Confidence: {match.confidence:.0%}. "
                        f"This IP/domain has been associated with malicious activity — "
                        f"verify against current threat intel before concluding."
                    ),
                    confidence=match.confidence,
                    reopen_window_hours=168,
                ))
        return results