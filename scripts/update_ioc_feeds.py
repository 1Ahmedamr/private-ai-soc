# scripts/update_ioc_feeds.py
"""
Refreshes local IOC feeds from public sources. Run manually or on a schedule:
    python -m scripts.update_ioc_feeds

This is deliberately a separate step from detection: the runtime IOC store
never touches the network. The only data sent out is a plain GET for a
public list - no incident data, no event data.
"""

import ipaddress
import json
import sys
from pathlib import Path

import requests

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
OUT_PATH = Path("data/ioc/feodo_tracker.json")


def fetch_feodo() -> list:
    resp = requests.get(
        FEODO_URL, timeout=30,
        headers={"User-Agent": "private-ai-soc-ioc-updater"},
    )
    resp.raise_for_status()
    data = resp.json()

    # Tolerate either a bare list or a dict wrapping a list.
    if isinstance(data, dict):
        for key in ("data", "blocklist", "results"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
    if not isinstance(data, list) or not data:
        raise ValueError("Unexpected or empty Feodo response shape")

    print("First record keys (verify schema):", sorted(data[0].keys()))

    entries = []
    skipped = 0
    for rec in data:
        raw_ip = rec.get("ip_address") or rec.get("ip")
        if not raw_ip:
            skipped += 1
            continue
        try:
            ip = ipaddress.ip_address(str(raw_ip).strip())
        except ValueError:
            skipped += 1
            continue
        if not ip.is_global:      # never ship private/reserved IPs as IOCs
            skipped += 1
            continue

        malware = rec.get("malware") or "botnet C2"
        online = str(rec.get("status", "")).lower() == "online"
        entries.append({
            "value": str(ip),
            "type": "ip",
            "threat_name": f"Feodo Tracker: {malware}",
            "confidence": 0.9 if online else 0.75,
        })

    print(f"Parsed {len(entries)} IOCs ({skipped} skipped)")
    return entries


def main() -> int:
    try:
        entries = fetch_feodo()
    except Exception as e:
        print(f"[IOC update] Feodo fetch failed, keeping existing file: {e}")
        return 1
    if not entries:
        print("[IOC update] Zero usable entries, keeping existing file")
        return 1

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = OUT_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(entries, indent=2))
    tmp.replace(OUT_PATH)
    print(f"[IOC update] Wrote {len(entries)} entries to {OUT_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
