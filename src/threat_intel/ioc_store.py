# src/threat_intel/ioc_store.py

"""
Local IOC (Indicator of Compromise) store.

Loads IOC feeds from local files and provides fast O(1) lookup
using Python sets. No network calls at runtime — privacy preserved.

Supported IOC types:
- Malicious IPs (IPv4)
- Malicious domains
- Malicious hashes (MD5, SHA256)

Why sets instead of a database? For lookup performance. A set of
100,000 IPs checks membership in O(1) time. A SQLite query would
be O(log n) at best. For per-event IOC matching, O(1) matters.
"""

import json
from pathlib import Path
from typing import Set, Optional
from dataclasses import dataclass, field


IOC_DIR = Path("data/ioc")


@dataclass
class IOCMatch:
    ioc_type: str          # "ip", "domain", "hash"
    ioc_value: str         # the actual matched value
    threat_name: str       # what threat this IOC is associated with
    confidence: float      # 0.0-1.0
    source: str            # which feed it came from


class IOCStore:
    """
    In-memory IOC store. Loaded once at startup, queried per event.
    """

    def __init__(self):
        self.malicious_ips: Set[str] = set()
        self.malicious_domains: Set[str] = set()
        self.malicious_hashes: Set[str] = set()
        self._ip_metadata: dict = {}
        self._domain_metadata: dict = {}
        self._loaded = False

    def load(self) -> None:
        """
        Loads all IOC files from data/ioc/.
        Supports two formats:
        - Plain text: one IOC per line (IP or domain)
        - JSON: list of objects with {value, threat_name, confidence}
        """
        if not IOC_DIR.exists():
            return

        for ioc_file in IOC_DIR.glob("*.txt"):
            self._load_plaintext(ioc_file)
        for ioc_file in IOC_DIR.glob("*.json"):
            self._load_json(ioc_file)

        print(f"[IOC] Loaded {len(self.malicious_ips)} IPs, "
              f"{len(self.malicious_domains)} domains, "
              f"{len(self.malicious_hashes)} hashes")
        self._loaded = True

    def _load_plaintext(self, path: Path) -> None:
        source = path.stem
        ioc_type = "ip" if "ip" in source.lower() else "domain"
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ioc_type == "ip":
                    self.malicious_ips.add(line)
                    self._ip_metadata[line] = {"threat_name": source, "confidence": 0.7, "source": source}
                else:
                    self.malicious_domains.add(line)
                    self._domain_metadata[line] = {"threat_name": source, "confidence": 0.7, "source": source}

    def _load_json(self, path: Path) -> None:
        source = path.stem
        try:
            with open(path) as f:
                data = json.load(f)
            for entry in data:
                value = entry.get("value", "").strip().lower()
                ioc_type = entry.get("type", "ip")
                meta = {
                    "threat_name": entry.get("threat_name", source),
                    "confidence": float(entry.get("confidence", 0.8)),
                    "source": source,
                }
                if ioc_type == "ip":
                    self.malicious_ips.add(value)
                    self._ip_metadata[value] = meta
                elif ioc_type == "domain":
                    self.malicious_domains.add(value)
                    self._domain_metadata[value] = meta
                elif ioc_type in ("md5", "sha256", "hash"):
                    self.malicious_hashes.add(value)
        except Exception as e:
            print(f"[IOC] Failed to load {path}: {e}")

    def check_ip(self, ip: str) -> Optional[IOCMatch]:
        if not ip:
            return None
        if ip in self.malicious_ips:
            meta = self._ip_metadata.get(ip, {})
            return IOCMatch(
                ioc_type="ip", ioc_value=ip,
                threat_name=meta.get("threat_name", "unknown"),
                confidence=meta.get("confidence", 0.7),
                source=meta.get("source", "unknown"),
            )
        return None

    def check_domain(self, domain: str) -> Optional[IOCMatch]:
        if not domain:
            return None
        domain_lower = domain.lower()
        if domain_lower in self.malicious_domains:
            meta = self._domain_metadata.get(domain_lower, {})
            return IOCMatch(
                ioc_type="domain", ioc_value=domain_lower,
                threat_name=meta.get("threat_name", "unknown"),
                confidence=meta.get("confidence", 0.7),
                source=meta.get("source", "unknown"),
            )
        return None

    def check_event(self, event) -> list:
        """
        Checks all IOC-relevant fields of a NormalizedEvent.
        Returns a list of IOCMatch objects (empty if none found).
        """
        matches = []
        if event.src_ip:
            m = self.check_ip(event.src_ip)
            if m:
                matches.append(m)
        if event.dst_ip:
            m = self.check_ip(event.dst_ip)
            if m:
                matches.append(m)
        if event.event_id:
            m = self.check_domain(event.event_id)
            if m:
                matches.append(m)
        return matches


_store: Optional[IOCStore] = None


def get_ioc_store() -> IOCStore:
    global _store
    if _store is None:
        _store = IOCStore()
        _store.load()
    return _store
