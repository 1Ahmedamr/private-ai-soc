# src/pipeline/file_analyzer.py

import json
from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass, field

from src.models.event_schema import NormalizedEvent
from src.models.incident_schema import Incident
from src.ingestion.format_detector import detect_format
from src.ingestion.windows_parser import parse_windows_events
from src.ingestion.linux_parser import parse_linux_ssh_events
from src.ingestion.zeek_parser import parse_zeek_conn_logs
from src.ingestion.zeek_dns_parser import parse_zeek_dns_logs
from src.ingestion.suricata_parser import parse_suricata_alerts
from src.ingestion.firewall_parser import parse_firewall_logs
from src.storage.event_store import EventStore
from src.incidents.store import IncidentStore
from src.assets.inventory import AssetInventory
from src.pipeline.orchestrator import PipelineOrchestrator
from src.ai.evidence import build_evidence
from src.ai.ollama_client import investigate


@dataclass
class AnalysisResult:
    filename: str
    format_detected: str
    events_parsed: int
    incidents: List[Incident] = field(default_factory=list)
    ai_summaries: dict = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    parse_warning: Optional[str] = None

    def to_session_dict(self) -> dict:
        """
        Serializes the analysis result for Flask session storage.
        Only stores structured evidence - never raw log content.
        The AI chat will only ever see this structured form,
        preserving the prompt-injection protection from Day 3.
        """
        return {
            "filename": self.filename,
            "format_detected": self.format_detected,
            "events_parsed": self.events_parsed,
            "errors": self.errors,
            "parse_warning": self.parse_warning,
            "incidents": [
                {
                    "incident_id": inc.incident_id,
                    "title": inc.title,
                    "severity": inc.severity,
                    "risk_score": inc.risk_score,
                    "priority": str(inc.priority),
                    "correlation_key": inc.correlation_key,
                    "mitre_techniques": inc.mitre_techniques,
                    "first_seen": inc.first_seen.isoformat(),
                    "last_seen": inc.last_seen.isoformat(),
                    "detections": [
                        {
                            "rule_name": d.rule_name,
                            "description": d.description,
                            "severity": d.severity,
                            "confidence": d.confidence,
                            "mitre_technique": d.mitre_technique,
                        }
                        for d in inc.detections
                    ],
                    "key_events": [
                        {
                            "timestamp": e.timestamp.isoformat(),
                            "source": e.source,
                            "event_type": e.event_type,
                            "src_ip": e.src_ip,
                            "dst_ip": e.dst_ip,
                            "user": e.user,
                            "host": e.host,
                            "status": e.status,
                            "event_id": e.event_id,
                        }
                        for e in inc.events[:20]  # cap at 20 events to avoid session size limits
                    ],
                }
                for inc in self.incidents
            ],
            "ai_summaries": {
                inc_id: {
                    "summary": v.summary,
                    "likely_attack_stage": v.likely_attack_stage,
                    "recommended_actions": v.recommended_actions,
                    "analyst_confidence_note": v.analyst_confidence_note,
                }
                for inc_id, v in self.ai_summaries.items()
            },
        }


def analyze_file(file_path: str, original_filename: str) -> AnalysisResult:
    result = AnalysisResult(
        filename=original_filename,
        format_detected="unknown",
        events_parsed=0,
    )

    fmt = detect_format(file_path, original_filename)
    result.format_detected = fmt

    if fmt == "unknown":
        result.errors.append(
            f"Could not recognize the format of '{original_filename}'. "
            f"Supported: Windows Event JSON, Linux SSH JSON, Zeek conn.log JSON, "
            f"Suricata EVE JSON, firewall text logs, PCAP files."
        )
        return result

    try:
        events = _parse_by_format(file_path, fmt, result)
    except Exception as e:
        result.errors.append(f"Parsing failed: {str(e)}")
        return result

    if not events:
        result.parse_warning = f"File was recognized as {fmt} but produced no parseable events."
        return result

    result.events_parsed = len(events)

    orchestrator = PipelineOrchestrator(EventStore(), IncidentStore(), _load_asset_inventory())
    incidents = orchestrator.ingest(events)
    result.incidents = incidents

    for incident in incidents:
        evidence = build_evidence(incident)
        verdict = investigate(evidence)
        if verdict:
            result.ai_summaries[incident.incident_id] = verdict

    return result


def _parse_by_format(file_path: str, fmt: str, result: AnalysisResult) -> List[NormalizedEvent]:
    if fmt == "pcap":
        from src.pipeline.pcap_processor import process_pcap
        return process_pcap(file_path)

    with open(file_path) as f:
        content = f.read()

    if fmt == "windows_json":
        data = json.loads(content)
        if not isinstance(data, list):
            data = [data]
        return parse_windows_events(data)

    if fmt == "linux_ssh_json":
        data = json.loads(content)
        if not isinstance(data, list):
            data = [data]
        return parse_linux_ssh_events(data)

    if fmt == "zeek_conn_json":
        data = json.loads(content)
        if not isinstance(data, list):
            lines = [l for l in content.splitlines() if l.strip()]
            data = [json.loads(l) for l in lines]
        return parse_zeek_conn_logs(data)

    if fmt == "suricata_eve_json":
        lines = [l for l in content.splitlines() if l.strip()]
        data = [json.loads(l) for l in lines]
        return parse_suricata_alerts(data)

    if fmt == "firewall_text":
        result.parse_warning = (
            "Firewall log parser supports Cisco ASA and generic DENY/BLOCK patterns. "
            "Unrecognized lines are skipped silently."
        )
        return parse_firewall_logs(content)

    return []


def _load_asset_inventory() -> AssetInventory:
    inventory = AssetInventory()
    inventory.load_from_csv("configs/assets.csv")
    return inventory
