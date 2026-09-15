# src/pipeline/pcap_processor.py

import subprocess
import json
import tempfile
from pathlib import Path
from typing import List
from src.models.event_schema import NormalizedEvent
from src.ingestion.zeek_parser import parse_zeek_conn_logs
from src.ingestion.suricata_parser import parse_suricata_alerts


def run_zeek_on_pcap(pcap_path: str, output_dir: Path) -> List[dict]:
    """..."""
    absolute_pcap_path = str(Path(pcap_path).resolve())
    result = subprocess.run(
        ["zeek", "-C", "-r", absolute_pcap_path, "LogAscii::use_json=T"],
        cwd=output_dir, capture_output=True, timeout=120, text=True,
    )
    if result.returncode != 0:
        print(f"[Zeek error] {result.stderr}")
        return []

    conn_log = output_dir / "conn.log"
    if not conn_log.exists():
        print("[Zeek warning] Ran successfully but produced no conn.log (no TCP/UDP/ICMP connections found in PCAP).")
        return []

    events = []
    with open(conn_log) as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def run_suricata_on_pcap(pcap_path: str, output_dir: Path) -> List[dict]:
    """Runs real Suricata against a PCAP, producing eve.json alerts."""
    result = subprocess.run(
        ["suricata", "-r", pcap_path, "-l", str(output_dir), "--runmode=single"],
        capture_output=True, timeout=120, text=True,
    )
    if result.returncode != 0:
        print(f"[Suricata error] {result.stderr}")
        return []

    eve_log = output_dir / "eve.json"
    if not eve_log.exists():
        print("[Suricata warning] Ran successfully but produced no eve.json.")
        return []

    alerts = []
    with open(eve_log) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            if entry.get("event_type") == "alert":
                alerts.append(entry)
    return alerts


def process_pcap(pcap_path: str) -> List[NormalizedEvent]:
    """
    End-to-end: raw PCAP -> real Zeek + Suricata -> NormalizedEvents,
    using the SAME parsers already built and tested for live Zeek/
    Suricata output. Detection, correlation, risk, and AI remain
    completely untouched, exactly like every prior source addition.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        zeek_raw = run_zeek_on_pcap(pcap_path, tmp_path)
        suricata_raw = run_suricata_on_pcap(pcap_path, tmp_path)

        zeek_events = parse_zeek_conn_logs(zeek_raw) if zeek_raw else []
        suricata_events = parse_suricata_alerts(suricata_raw) if suricata_raw else []

        return zeek_events + suricata_events
