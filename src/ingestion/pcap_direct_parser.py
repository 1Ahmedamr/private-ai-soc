# src/ingestion/pcap_direct_parser.py

"""
Direct PCAP parser using Scapy - bypasses Zeek for cases where
Zeek's conn.log aggregation loses individual SYN packet granularity
needed for port scan detection.

Why not use this for everything and skip Zeek entirely?
Zeek produces richer protocol-aware logs (HTTP, DNS, SSL, Kerberos)
that Scapy can't easily replicate. We use Scapy specifically for
the raw TCP/IP layer where individual packet timing matters most -
like port scan detection. Both tools feed into the same normalized
schema downstream.
"""

from datetime import datetime, timezone
from typing import List
from src.models.event_schema import NormalizedEvent, EventSource, EventType, Severity


def parse_pcap_direct(pcap_path: str) -> List[NormalizedEvent]:
    """
    Reads a PCAP directly via Scapy and extracts individual TCP SYN
    connections as NormalizedEvents. Each SYN packet becomes one event,
    preserving the timing granularity that Zeek's connection aggregation
    loses for high-speed port scans.
    """
    try:
        from scapy.all import rdpcap, TCP, IP, UDP, ICMP
    except ImportError:
        print("[Direct PCAP] scapy not installed - run: pip install scapy")
        return []

    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"[Direct PCAP] Failed to read {pcap_path}: {e}")
        return []

    events = []
    for pkt in packets:
        try:
            if not pkt.haslayer(IP):
                continue

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                ip = pkt[IP]
                flags = tcp.flags

                # SYN only (flag=2) = connection attempt, no response yet
                # SYN+ACK (flag=18) = server responded = port is open
                # RST (flag=4 or 20) = port closed/rejected
                conn_state = "unknown"
                if flags == 2:    # SYN
                    conn_state = "S0"
                elif flags == 18:  # SYN+ACK
                    conn_state = "SF"
                elif flags & 4:   # RST bit set
                    conn_state = "REJ"

                events.append(NormalizedEvent(
                    timestamp=datetime.fromtimestamp(float(pkt.time), tz=timezone.utc),
                    source=EventSource.ZEEK,  # same source tag so detection rules don't need changing
                    event_type=EventType.NETWORK_CONNECTION,
                    src_ip=ip.src,
                    dst_ip=ip.dst,
                    src_port=tcp.sport,
                    dst_port=tcp.dport,
                    protocol="tcp",
                    conn_state=conn_state,
                    severity=Severity.INFO,
                    raw_data={
                        "src": ip.src, "dst": ip.dst,
                        "sport": tcp.sport, "dport": tcp.dport,
                        "flags": str(tcp.flags), "ts": float(pkt.time),
                    },
                ))

            elif pkt.haslayer(UDP):
                ip = pkt[IP]
                udp = pkt[UDP]
                events.append(NormalizedEvent(
                    timestamp=datetime.fromtimestamp(float(pkt.time), tz=timezone.utc),
                    source=EventSource.ZEEK,
                    event_type=EventType.NETWORK_CONNECTION,
                    src_ip=ip.src,
                    dst_ip=ip.dst,
                    src_port=udp.sport,
                    dst_port=udp.dport,
                    protocol="udp",
                    conn_state="SF",
                    severity=Severity.INFO,
                    raw_data={"src": ip.src, "dst": ip.dst},
                ))

        except Exception:
            continue

    print(f"[Direct PCAP] Extracted {len(events)} packet-level events from {pcap_path}")
    return events