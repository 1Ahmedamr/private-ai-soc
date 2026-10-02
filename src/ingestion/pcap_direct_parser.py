# src/ingestion/pcap_direct_parser.py
# Single-process streaming Scapy parser (multiprocessing was 10x slower: pickling cost).
#
# conn_state semantics (mirrors Zeek closely enough for the scan/beacon rules):
#   S0  - SYN with NO SYN-ACK ever seen for that flow (unanswered or RST-rejected)
#   SF  - established flow (SYN answered by SYN-ACK), or any ACK/SYN-ACK packet
#   REJ - RST packet
# Why: labelling every bare SYN as S0 made ordinary successful connections
# (e.g. AD traffic to ports 88/135/389/445) look like an unanswered port scan.

from datetime import datetime, timezone
from typing import List
from src.models.event_schema import NormalizedEvent, EventSource, EventType, Severity


def parse_pcap_direct(pcap_path: str) -> List[NormalizedEvent]:
    try:
        from scapy.all import PcapReader, TCP, IP, UDP
    except ImportError:
        print("[Direct PCAP] scapy not installed")
        return []

    events: List[NormalizedEvent] = []
    syn_events = []          # (index into events, flow key) for bare SYNs
    established = set()      # flow keys that received a SYN-ACK
    count = 0

    try:
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
                        if flags == 2:                       # bare SYN
                            conn_state = "S0"
                            syn_events.append(
                                (len(events), (ip.src, tcp.sport, ip.dst, tcp.dport)))
                        elif (flags & 0x12) == 0x12:         # SYN+ACK: handshake answered
                            conn_state = "SF"
                            established.add((ip.dst, tcp.dport, ip.src, tcp.sport))
                        elif flags & 4:                      # RST
                            conn_state = "REJ"
                        elif flags & 16:                     # ACK
                            conn_state = "SF"
                        else:
                            conn_state = "unknown"
                        events.append(NormalizedEvent(
                            timestamp=ts, source=EventSource.ZEEK,
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
                            timestamp=ts, source=EventSource.ZEEK,
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

    # Second pass: a SYN whose flow later got a SYN-ACK was a successful connection.
    answered = 0
    for idx, key in syn_events:
        if key in established:
            events[idx] = events[idx].model_copy(update={"conn_state": "SF"})
            answered += 1

    print(f"[Direct PCAP] Extracted {len(events)} packet-level events from {count} packets "
          f"in {pcap_path} ({answered}/{len(syn_events)} SYNs were answered)")
    return events
