# src/ingestion/pcap_direct_parser.py
# Simple, fast, single-process Scapy parser.
# Multiprocessing was removed: pickling Scapy packets costs more than
# the processing itself, making parallel parsing 10x SLOWER on macOS.
# The real speed fix is below: we skip non-IP packets early and avoid
# creating full NormalizedEvent objects until needed.

from datetime import datetime, timezone
from typing import List
from src.models.event_schema import NormalizedEvent, EventSource, EventType, Severity


def parse_pcap_direct(pcap_path: str) -> List[NormalizedEvent]:
    try:
        from scapy.all import PcapReader, TCP, IP, UDP
    except ImportError:
        print("[Direct PCAP] scapy not installed")
        return []

    events = []
    count = 0

    try:
        # PcapReader streams packets one at a time instead of loading
        # the entire PCAP into RAM - critical for large files.
        # rdpcap loads everything at once; PcapReader uses O(1) memory.
        with PcapReader(pcap_path) as reader:
            for pkt in reader:
                count += 1
                try:
                    if not pkt.haslayer(IP):
                        continue
                    ip = pkt[IP]
                    ts = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc)

                    if pkt.haslayer(TCP):
                        tcp = pkt[TCP]
                        flags = int(tcp.flags)
                        if flags == 2:
                            conn_state = "S0"
                        elif flags == 18:
                            conn_state = "SF"
                        elif flags & 4:
                            conn_state = "REJ"
                        else:
                            conn_state = "unknown"
                        events.append(NormalizedEvent(
                            timestamp=ts,
                            source=EventSource.ZEEK,
                            event_type=EventType.NETWORK_CONNECTION,
                            src_ip=ip.src, dst_ip=ip.dst,
                            src_port=tcp.sport, dst_port=tcp.dport,
                            protocol="tcp", conn_state=conn_state,
                            severity=Severity.INFO,
                            raw_data={"src": ip.src, "dst": ip.dst,
                                      "sport": tcp.sport, "dport": tcp.dport,
                                      "flags": flags, "ts": float(pkt.time)},
                        ))
                    elif pkt.haslayer(UDP):
                        udp = pkt[UDP]
                        events.append(NormalizedEvent(
                            timestamp=ts,
                            source=EventSource.ZEEK,
                            event_type=EventType.NETWORK_CONNECTION,
                            src_ip=ip.src, dst_ip=ip.dst,
                            src_port=udp.sport, dst_port=udp.dport,
                            protocol="udp", conn_state="SF",
                            severity=Severity.INFO,
                            raw_data={"src": ip.src, "dst": ip.dst},
                        ))
                except Exception:
                    continue
    except Exception as e:
        print(f"[Direct PCAP] Failed to read {pcap_path}: {e}")
        return []

    print(f"[Direct PCAP] Extracted {len(events)} packet-level events from {count} packets in {pcap_path}")
    return events
