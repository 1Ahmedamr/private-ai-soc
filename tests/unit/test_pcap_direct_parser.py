# tests/unit/test_pcap_direct_parser.py

from scapy.all import Ether, IP, TCP, wrpcap
from src.ingestion.pcap_direct_parser import parse_pcap_direct


def pkt(src, dst, sport, dport, flags, t):
    p = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    p.time = t
    return p


def test_only_unanswered_syns_are_s0(tmp_path):
    path = str(tmp_path / "t.pcap")
    wrpcap(path, [
        pkt("10.0.0.5", "10.0.0.9", 40000, 80, "S", 1.0),
        pkt("10.0.0.9", "10.0.0.5", 80, 40000, "SA", 1.1),   # answered -> not a scan probe
        pkt("10.0.0.5", "10.0.0.9", 40001, 81, "S", 2.0),    # no reply
        pkt("10.0.0.5", "10.0.0.9", 40002, 82, "S", 3.0),    # RST-rejected (closed port)
        pkt("10.0.0.9", "10.0.0.5", 82, 40002, "RA", 3.1),
    ])
    events = parse_pcap_direct(path)
    syn_states = {e.dst_port: e.conn_state for e in events if e.raw_data.get("flags") == 2}
    assert syn_states == {80: "SF", 81: "S0", 82: "S0"}
