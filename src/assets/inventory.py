# src/assets/inventory.py

import csv
from pathlib import Path
from typing import Dict, Optional
from src.assets.models import Asset, AssetCriticality


class AssetInventory:
    """
    A lookup table: "is this host/IP important?"

    Why not query this from a live source (AD, CMDB) on day one?
    Because we don't have one built yet, and hardcoding real integration
    now would be premature - Phase 24's roadmap correctly defers
    "Multi-source integrations" to later. A simple, file-based inventory
    is the honest MVP: it proves the CONCEPT (risk scoring should depend
    on what asset is affected) without over-building infrastructure we
    can't populate with real data yet.
    """

    def __init__(self):
        self._by_host: Dict[str, Asset] = {}
        self._by_ip: Dict[str, Asset] = {}

    def add_asset(self, asset: Asset) -> None:
        if asset.identifier_type == "host":
            self._by_host[asset.identifier] = asset
        elif asset.identifier_type == "ip":
            self._by_ip[asset.identifier] = asset

    def load_from_csv(self, path: str) -> None:
        """
        Expected CSV columns: identifier,identifier_type,criticality,description

        Why CSV and not JSON for this specific file?
        Because a real SOC analyst (not a developer) is the person who'll
        maintain this list - "which servers are our Domain Controllers."
        CSV opens directly in Excel/Google Sheets. That's a deliberate
        usability choice, not a technical limitation.
        """
        file_path = Path(path)
        if not file_path.exists():
            return

        with open(file_path, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                self.add_asset(Asset(
                    identifier=row["identifier"],
                    identifier_type=row["identifier_type"],
                    criticality=AssetCriticality(row["criticality"]),
                    description=row.get("description") or None,
                ))

    def get_criticality(self, host: Optional[str], ip: Optional[str]) -> AssetCriticality:
        """
        Looks up criticality by host first, then IP, defaulting to STANDARD.

        Why host before ip?
        Hostnames are more stable identifiers than IPs (DHCP reassigns
        IPs; a server's hostname rarely changes). If both are available,
        trust the more durable identifier.
        """
        if host and host in self._by_host:
            return self._by_host[host].criticality
        if ip and ip in self._by_ip:
            return self._by_ip[ip].criticality
        return AssetCriticality.STANDARD

    def is_critical_or_important(self, host: Optional[str], ip: Optional[str]) -> bool:
        """
        Bridges to the existing is_critical_asset boolean used by
        map_severity_to_priority and calculate_risk_score - so we don't
        need to touch those functions' signatures today.
        """
        criticality = self.get_criticality(host, ip)
        return criticality in (AssetCriticality.CRITICAL, AssetCriticality.IMPORTANT)