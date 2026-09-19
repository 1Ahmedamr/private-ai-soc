# src/ingestion/pcap_direct_parser.py

from datetime import datetime, timezone
from typing import List
from multiprocessing import Pool, cpu_count
from src.models.event_schema import NormalizedEvent, EventSource, EventType, Severity


def _parse_packet_batch(args):
    """Worker function for parallel packet processing."""
    batch, batch_start = args
    events = []
    try:
        from scapy.all import TCP, IP, UDP
        for pkt in batch:
            try:
                if not pkt.haslayer(IP):
                    continue
                if pkt.haslayer(TCP):
                    tcp = pkt[TCP]
                    ip = pkt[IP]
                    flags = int(tcp.flags)
                    conn_state = "S0" if flags == 2 else ("SF" if flags == 18 else ("REJ" if flags & 4 else "unknown"))
                    events.append(NormalizedEvent(
                        timestamp=datetime.fromtimestamp(float(pkt.time), tz=timezone.utc),
                        source=EventSource.ZEEK,
                        event_type=EventType.NETWORK_CONNECTION,
                        src_ip=ip.src, dst_ip=ip.dst,
                        src_port=tcp.sport, dst_port=tcp.dport,
                        protocol="tcp", conn_state=conn_state,
                        severity=Severity.INFO,
                        raw_data={"src": ip.src, "dst": ip.dst, "sport": tcp.sport, "dport": tcp.dport, "flags": flags, "ts": float(pkt.time)},
                    ))
                elif pkt.haslayer(UDP):
                    ip = pkt[IP]
                    udp = pkt[UDP]
                    events.append(NormalizedEvent(
                        timestamp=datetime.fromtimestamp(float(pkt.time), tz=timezone.utc),
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
    except Exception:
        pass
    return events


def parse_pcap_direct(pcap_path: str) -> List[NormalizedEvent]:
    try:
        from scapy.all import rdpcap
    except ImportError:
        print("[Direct PCAP] scapy not installed")
        return []

    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"[Direct PCAP] Failed to read {pcap_path}: {e}")
        return []

    total = len(packets)
    if total == 0:
        return []

    # Use parallel processing for large PCAPs (>1000 packets)
    # Split into batches, one per CPU core
    workers = min(cpu_count(), 8)
    batch_size = max(1, total // workers)
    batches = [
        (list(packets[i:i + batch_size]), i)
        for i in range(0, total, batch_size)
    ]

    if total > 1000:
        print(f"[Direct PCAP] Processing {total} packets across {len(batches)} parallel workers...")
        with Pool(processes=workers) as pool:
            results = pool.map(_parse_packet_batch, batches)
        all_events = [e for batch_result in results for e in batch_result]
    else:
        # Small PCAPs: no overhead of spawning processes
        all_events = []
        from scapy.all import TCP, IP, UDP
        for pkt in packets:
            try:
                if not pkt.haslayer(IP):
                    continue
                if pkt.haslayer(TCP):
                    tcp = pkt[TCP]
                    ip = pkt[IP]
                    flags = int(tcp.flags)
                    conn_state = "S0" if flags == 2 else ("SF" if flags == 18 else ("REJ" if flags & 4 else "unknown"))
                    all_events.append(NormalizedEvent(
                        timestamp=datetime.fromtimestamp(float(pkt.time), tz=timezone.utc),
                        source=EventSource.ZEEK,
                        event_type=EventType.NETWORK_CONNECTION,
                        src_ip=ip.src, dst_ip=ip.dst,
                        src_port=tcp.sport, dst_port=tcp.dport,
                        protocol="tcp", conn_state=conn_state,
                        severity=Severity.INFO,
                        raw_data={"src": ip.src, "dst": ip.dst, "sport": tcp.sport, "dport": tcp.dport, "flags": flags, "ts": float(pkt.time)},
                    ))
            except Exception:
                continue

    print(f"[Direct PCAP] Extracted {len(all_events)} packet-level events from {pcap_path}")
    return all_events
