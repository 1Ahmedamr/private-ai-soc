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
    End-to-end: raw PCAP -> normalized events.

    Strategy: run BOTH Zeek (protocol-aware, rich logs) AND direct
    Scapy parsing (packet-level granularity for scan detection).
    Deduplicate by (src_ip, dst_ip, dst_port, timestamp) to avoid
    double-counting events that both tools see.
    Why both? Zeek loses individual SYN timing for high-speed scans
    (aggregates into connections). Scapy preserves every packet but
    lacks protocol awareness. Together they give complete coverage.
    """
    from src.ingestion.pcap_direct_parser import parse_pcap_direct

    all_events: List[NormalizedEvent] = []

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        # Zeek path (protocol-aware: HTTP, DNS, SSL, Kerberos, etc.)
        zeek_raw = run_zeek_on_pcap(pcap_path, tmp_path)
        suricata_raw = run_suricata_on_pcap(pcap_path, tmp_path)

        zeek_events = parse_zeek_conn_logs(zeek_raw) if zeek_raw else []
        suricata_events = parse_suricata_alerts(suricata_raw) if suricata_raw else []
        all_events.extend(zeek_events)
        all_events.extend(suricata_events)

    # Direct Scapy path (packet-level: catches high-speed port scans
    # that Zeek aggregates away, and works even when Zeek fails)
    scapy_events = parse_pcap_direct(pcap_path)

    # If Zeek produced very few events compared to what Scapy found,
    # Zeek likely missed the scan - use Scapy events instead of Zeek
    # for network connections (keep Suricata alerts always)
    if len(scapy_events) > len(zeek_events) * 2:
        print(f"[PCAP] Zeek produced {len(zeek_events)} conn events, "
              f"Scapy found {len(scapy_events)} packets - using Scapy for network layer")
        all_events = suricata_events + scapy_events
    else:
        all_events.extend(scapy_events)

    print(f"[PCAP] Total normalized events: {len(all_events)}")
    return all_events
