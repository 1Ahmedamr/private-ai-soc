# Real-world outcomes that must not silently change. Run explicitly:
#   python -m pytest tests/regression -v
import os
import pytest
from src.ingestion.pcap_direct_parser import parse_pcap_direct
from src.detection.rules.port_scan import detect_port_scan
from src.detection.rules.c2_beacon import detect_c2_beacon


def load(path):
    if not os.path.exists(path):
        pytest.skip(f"{path} not available")
    return parse_pcap_direct(path)


def test_0day_fast_scan_still_detected():
    r = detect_port_scan(load("data/pcaps/0day.pcap"))
    assert r.triggered and "192.168.0.20" in r.description


def test_exercise1_beacon_to_known_c2():
    r = detect_c2_beacon(load("data/pcaps/malware_samples/exercise1.pcap"))
    assert r.triggered and "37.1.215.220" in r.description


def test_exercise3_domain_traffic_is_not_a_port_scan():
    assert not detect_port_scan(load("data/pcaps/malware_samples/exercise3.pcap")).triggered
