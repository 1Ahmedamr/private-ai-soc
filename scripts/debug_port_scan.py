# scripts/debug_port_scan.py

import json
from src.ingestion.zeek_parser import parse_zeek_conn_logs
from src.detection.rules.port_scan import detect_port_scan

with open("tests/samples/zeek_portscan_sample.json") as f:
    raw_events = json.load(f)

events = parse_zeek_conn_logs(raw_events)

print("--- Normalized events ---")
for e in events:
    print(f"src={e.src_ip} dst={e.dst_ip} dst_port={e.dst_port} conn_state={e.conn_state} event_type={e.event_type}")

print("\n--- Running detect_port_scan directly ---")
result = detect_port_scan(events, unique_ports_threshold=5, window_seconds=10)
print(result.model_dump_json(indent=2))