# scripts/update_ioc_feeds.py
"""
Refreshes local IOC feeds from public sources. Run manually or on a schedule:
    python -m scripts.update_ioc_feeds

This is deliberately a separate step from detection: the runtime IOC store
never touches the network. The only data sent out is a plain GET for a
public list - no incident data, no event data.

Each feed is fetched, strictly validated and written on its own. A failed or
suspicious download never overwrites the last good file.
"""

import ipaddress
import json
import re
import sys
from pathlib import Path

import requests

IOC_DIR = Path("data/ioc")
HEADERS = {"User-Agent": "private-ai-soc-ioc-updater"}

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
URLHAUS_HOSTS_URL = "https://urlhaus.abuse.ch/downloads/hostfile/"
ET_COMPROMISED_URL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"

# A list smaller than this is treated as a broken download, not a real feed.
MIN_ENTRIES = {"feodo_tracker": 1, "urlhaus_hosts": 50, "et_compromised": 50}

_DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$"
)


def _get(url: str) -> requests.Response:
    resp = requests.get(url, timeout=30, headers=HEADERS)
    resp.raise_for_status()
    return resp


def fetch_feodo() -> list:
    data = _get(FEODO_URL).json()

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

    print(f"Feodo: parsed {len(entries)} IOCs ({skipped} skipped)")
    return entries


def fetch_urlhaus_hosts() -> list:
    """URLhaus hostfile: lines like '127.0.0.1 bad.example'. Keep the host only."""
    entries, seen, skipped = [], set(), 0
    for line in _get(URLHAUS_HOSTS_URL).text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        host = line.split()[-1].lower().rstrip(".")
        if host in seen:
            continue
        seen.add(host)

        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None

        if ip is not None:
            if not ip.is_global:
                skipped += 1
                continue
            entries.append({"value": str(ip), "type": "ip",
                            "threat_name": "URLhaus: malware distribution host",
                            "confidence": 0.8})
        elif _DOMAIN_RE.match(host):
            entries.append({"value": host, "type": "domain",
                            "threat_name": "URLhaus: malware distribution host",
                            "confidence": 0.8})
        else:
            skipped += 1

    print(f"URLhaus: parsed {len(entries)} IOCs ({skipped} skipped)")
    return entries


def fetch_et_compromised() -> list:
    """Emerging Threats compromised-IP list: one IPv4 per line."""
    entries, skipped = [], 0
    for line in _get(ET_COMPROMISED_URL).text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            ip = ipaddress.ip_address(line)
        except ValueError:
            skipped += 1
            continue
        if not ip.is_global:
            skipped += 1
            continue
        entries.append({"value": str(ip), "type": "ip",
                        "threat_name": "Emerging Threats: compromised host",
                        "confidence": 0.6})

    print(f"Emerging Threats: parsed {len(entries)} IOCs ({skipped} skipped)")
    return entries


FEEDS = [
    ("feodo_tracker", fetch_feodo),
    ("urlhaus_hosts", fetch_urlhaus_hosts),
    ("et_compromised", fetch_et_compromised),
]


def write_feed(name: str, entries: list) -> None:
    minimum = MIN_ENTRIES.get(name, 1)
    if len(entries) < minimum:
        raise ValueError(f"only {len(entries)} usable entries (expected at least {minimum})")
    IOC_DIR.mkdir(parents=True, exist_ok=True)
    out = IOC_DIR / f"{name}.json"
    tmp = out.with_suffix(".tmp")
    tmp.write_text(json.dumps(entries, indent=2))
    tmp.replace(out)
    print(f"[IOC update] {name}: wrote {len(entries)} entries to {out}")


def main() -> int:
    failures = 0
    for name, fetch in FEEDS:
        try:
            write_feed(name, fetch())
        except Exception as e:
            failures += 1
            print(f"[IOC update] {name} failed, keeping existing file: {e}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
