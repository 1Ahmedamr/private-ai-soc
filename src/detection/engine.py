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
from src.detection.rules.windows_persistence import detect_windows_persistence
from src.detection.rules.success_after_failures import detect_success_after_failures

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

        
        results.extend(detect_windows_persistence(events))

        success_after_failures = detect_success_after_failures(events)
        if success_after_failures.triggered:
            results.append(success_after_failures)
        
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

    
    # Sigma rules that match a single event but only mean something in volume.
    # key (rule id or rule name) -> minimum matching events before reporting.
    _SIGMA_MIN_MATCHES = {
        "bf532b66-5a9d-4b4a-b3d4-7c8e5f3a2d1c": 5,
        "Multiple Failed Logon Attempts (Brute Force)": 5,
    }

    def run_sigma_rules(self, events: List[NormalizedEvent]) -> List[DetectionResult]:
        """
        Evaluates Sigma rules using the pre-built source index.
        Each event only runs against rules for its specific log source,
        not all rules - this is the critical optimization for large PCAPs.
        Count-based rules (see _SIGMA_MIN_MATCHES) only report once enough
        events matched.
        """
        index = get_sigma_index()
        first_match = {}
        match_count = {}

        for event in events:
            for rule in index.get_rules_for_source(event.source, event.event_type):
                match = rule.evaluate(event)
                if not match or match.severity in ("low", "informational"):
                    continue
                match_count[match.rule_id] = match_count.get(match.rule_id, 0) + 1
                first_match.setdefault(match.rule_id, match)

        results = []
        for rule_id, match in first_match.items():
            needed = max(
                self._SIGMA_MIN_MATCHES.get(rule_id, 1),
                self._SIGMA_MIN_MATCHES.get(match.rule_name, 1),
            )
            if match_count[rule_id] < needed:
                continue
            technique, tactic = self._adjust_logon_mapping(match, events)
            results.append(DetectionResult(
                rule_name=f"[Sigma] {match.rule_name}",
                rule_id=match.rule_id,
                triggered=True,
                severity=self._map_sigma_severity(match.severity),
                mitre_technique=technique,
                mitre_tactic=tactic,
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

    @staticmethod
    def _adjust_logon_mapping(match, events):
        """T1078 (Valid Accounts) needs a successful logon. A 'failed logon' rule
        without any successful authentication in the data is credential access."""
        technique, tactic = match.mitre_technique, match.mitre_tactic
        if technique and technique.upper().startswith("T1078") and "failed" in match.rule_name.lower():
            has_success = any(
                e.event_type == "authentication" and e.status == "success" for e in events
            )
            if not has_success:
                return "T1110", "Credential Access"
        return technique, tactic
    
    def run_ioc_checks(self, events: List[NormalizedEvent]) -> List[DetectionResult]:
        """
        Checks events against the local IOC store.

        Direction decides what a match means:
          outbound (dst_ip, DNS query): one of our hosts reached a known-bad
            destination - possible C2 or malware delivery (T1071).
          inbound (src_ip): a known-bad address contacted us - reputation
            context only, so no ATT&CK technique is asserted.
          host (file hash): a known-bad file was observed on a host.

        One detection per (ioc_value, ioc_type, direction), listing every
        affected host, so the scope of a match is not hidden.
        """
        from src.models.event_schema import EventType, Severity
        store = get_ioc_store()
        direction_by_field = {
            "src_ip": "inbound",
            "dst_ip": "outbound",
            "event_id": "outbound",
            "file_hash": "host",
        }
        groups = {}

        for event in events:
            for match in store.check_event(event):
                # The queried domain is stored in event_id only for DNS events;
                # on any other event it is just an ID such as "4625".
                if match.matched_field == "event_id" and event.event_type != EventType.DNS_QUERY:
                    continue
                direction = direction_by_field.get(match.matched_field, "outbound")
                if direction == "inbound":
                    affected = event.host or event.dst_ip
                else:
                    affected = event.host or event.src_ip

                group = groups.setdefault(
                    (match.ioc_value, match.ioc_type, direction),
                    {"match": match, "affected": [], "events": 0},
                )
                group["events"] += 1
                if affected and affected not in group["affected"]:
                    group["affected"].append(affected)

        results = []
        for (value, ioc_type, direction), group in groups.items():
            match = group["match"]
            strong = match.confidence >= 0.8
            type_label = ioc_type.upper()

            if direction == "inbound":
                severity = Severity.MEDIUM if strong else Severity.LOW
                technique, tactic = None, None
                name = f"IOC Match: {type_label} (inbound)"
                rule_id = f"SOC-IOC-{type_label}-IN-001"
                reopen_hours = 48
                meaning = (
                    f"A known-bad {ioc_type} contacted this environment. This is reputation "
                    f"context only; it does not show what the activity achieved."
                )
            elif direction == "outbound":
                severity = Severity.HIGH if strong else Severity.MEDIUM
                technique, tactic = "T1071", "Command and Control"
                name = f"IOC Match: {type_label}"
                rule_id = f"SOC-IOC-{type_label}-001"
                reopen_hours = 168
                meaning = (
                    f"A host in this environment reached a known-bad {ioc_type}: possible "
                    f"command and control or malware delivery. Verify against current threat "
                    f"intel before concluding."
                )
            else:
                severity = Severity.HIGH if strong else Severity.MEDIUM
                technique, tactic = None, None
                name = f"IOC Match: {type_label}"
                rule_id = f"SOC-IOC-{type_label}-001"
                reopen_hours = 168
                meaning = f"A file with a known-bad {ioc_type} was observed on a host."

            shown = group["affected"][:10]
            extra = len(group["affected"]) - len(shown)
            affected_text = ", ".join(shown) + (f" (+{extra} more)" if extra > 0 else "")

            results.append(DetectionResult(
                rule_name=name,
                rule_id=rule_id,
                triggered=True,
                severity=severity,
                mitre_technique=technique,
                mitre_tactic=tactic,
                description=(
                    f"IOC match ({direction}): {ioc_type} '{value}' found in local threat intel "
                    f"feed '{match.source}'. Threat: {match.threat_name}. "
                    f"Confidence: {match.confidence:.0%}. "
                    f"Seen in {group['events']} event(s); affected: {affected_text or 'unknown'}. "
                    f"{meaning}"
                ),
                confidence=match.confidence,
                reopen_window_hours=reopen_hours,
            ))
        return results
