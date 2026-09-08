# tests/unit/test_asset_inventory.py

from src.assets.models import Asset, AssetCriticality
from src.assets.inventory import AssetInventory


def test_unknown_asset_defaults_to_standard():
    inventory = AssetInventory()
    result = inventory.get_criticality(host="UNKNOWN-HOST", ip="1.2.3.4")
    assert result == AssetCriticality.STANDARD


def test_known_ip_returns_correct_criticality():
    inventory = AssetInventory()
    inventory.add_asset(Asset(identifier="10.0.0.50", identifier_type="ip", criticality=AssetCriticality.CRITICAL))

    result = inventory.get_criticality(host=None, ip="10.0.0.50")
    assert result == AssetCriticality.CRITICAL


def test_host_lookup_takes_priority_over_ip():
    inventory = AssetInventory()
    inventory.add_asset(Asset(identifier="DC01", identifier_type="host", criticality=AssetCriticality.CRITICAL))
    inventory.add_asset(Asset(identifier="10.0.0.99", identifier_type="ip", criticality=AssetCriticality.STANDARD))

    # Same event has both a known critical host AND an unrelated standard ip
    result = inventory.get_criticality(host="DC01", ip="10.0.0.99")
    assert result == AssetCriticality.CRITICAL


def test_is_critical_or_important_true_for_important_not_just_critical():
    inventory = AssetInventory()
    inventory.add_asset(Asset(identifier="10.0.0.20", identifier_type="ip", criticality=AssetCriticality.IMPORTANT))

    assert inventory.is_critical_or_important(host=None, ip="10.0.0.20") is True


def test_load_from_csv_populates_inventory():
    inventory = AssetInventory()
    inventory.load_from_csv("configs/assets.csv")

    assert inventory.get_criticality(host=None, ip="10.0.0.50") == AssetCriticality.CRITICAL
    assert inventory.get_criticality(host="WIN-CLIENT", ip=None) == AssetCriticality.STANDARD


def test_missing_csv_file_does_not_crash():
    inventory = AssetInventory()
    inventory.load_from_csv("configs/does_not_exist.csv")  # should silently no-op
    assert inventory.get_criticality(host="anything", ip="anything") == AssetCriticality.STANDARD