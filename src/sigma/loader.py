# src/sigma/loader.py

import yaml
from pathlib import Path
from typing import List, Dict
from src.sigma.evaluator import SigmaRule

SIGMA_RULES_DIR = Path("data/sigma_rules")
TRUSTED_STATUSES = {"stable", "test"}


def load_sigma_rules(rules_dir: str = None) -> List[SigmaRule]:
    directory = Path(rules_dir) if rules_dir else SIGMA_RULES_DIR
    rules = []
    skipped = 0

    for yaml_file in directory.rglob("*.yml"):
        try:
            with open(yaml_file, encoding="utf-8", errors="ignore") as f:
                content = yaml.safe_load(f)

            if not isinstance(content, dict):
                skipped += 1
                continue
            if "detection" not in content:
                skipped += 1
                continue

            status = content.get("status", "experimental")
            if status not in TRUSTED_STATUSES:
                skipped += 1
                continue

            rule = SigmaRule(content, source_file=str(yaml_file))
            rules.append(rule)

        except Exception:
            skipped += 1
            continue

    print(f"[Sigma] Loaded {len(rules)} rules ({skipped} skipped) from {directory}")
    return rules


class SigmaRuleIndex:
    """
    Pre-indexes Sigma rules by BOTH product AND category.

    Why category matters: Most Sysmon detection rules use:
      logsource:
        category: process_creation
    NOT:
      logsource:
        product: windows
        service: sysmon

    Without category indexing, 200+ process_creation rules never
    fire on Sysmon events, even though they're exactly the right
    events to match against. This is the fix.
    """

    def __init__(self, rules: List[SigmaRule]):
        self._by_product: Dict[str, List[SigmaRule]] = {}
        self._by_category: Dict[str, List[SigmaRule]] = {}
        self._universal: List[SigmaRule] = []

        for rule in rules:
            product = rule.logsource_product
            category = rule.logsource_category

            if product:
                self._by_product.setdefault(product, []).append(rule)
            if category:
                self._by_category.setdefault(category, []).append(rule)
            if not product and not category:
                self._universal.append(rule)

        total_product = sum(len(v) for v in self._by_product.values())
        total_category = sum(len(v) for v in self._by_category.values())
        print(f"[Sigma Index] {total_product} rules by product, "
              f"{total_category} rules by category, "
              f"{len(self._universal)} universal")
        for product, rules_list in sorted(self._by_product.items()):
            print(f"  product/{product}: {len(rules_list)} rules")
        for category, rules_list in sorted(self._by_category.items()):
            print(f"  category/{category}: {len(rules_list)} rules")

    def get_rules_for_source(self, source: str, event_type: str = "") -> List[SigmaRule]:
        """
        Returns rules relevant to this event's source and type.

        Mapping strategy:
        - Windows auth events (4625, 4624) → product/windows rules
        - Sysmon process events → category/process_creation rules
        - Sysmon network events → category/network_connection rules
        - Sysmon DNS events → category/dns_query rules
        - Linux events → product/linux rules
        - Zeek/Suricata events → product/zeek or product/suricata rules
        """
        source_to_product = {
            "windows": "windows",
            "linux": "linux",
            "zeek": "zeek",
            "suricata": "suricata",
            "firewall": "firewall",
        }

        rules = []

        # Product-based rules (always included for the source)
        product = source_to_product.get(source, source)
        rules.extend(self._by_product.get(product, []))

        # Category-based rules (based on event_type for Sysmon richness)
        if source == "windows":
            if "process" in event_type:
                rules.extend(self._by_category.get("process_creation", []))
                rules.extend(self._by_category.get("image_load", []))
            if "network" in event_type:
                rules.extend(self._by_category.get("network_connection", []))
            if "dns" in event_type:
                rules.extend(self._by_category.get("dns_query", []))

        # Zeek can also match network_connection category rules
        if source == "zeek" and "network" in event_type:
            rules.extend(self._by_category.get("network_connection", []))

        # Deduplicate by rule_id — a rule may appear in both product and category
        seen = set()
        unique = []
        for r in rules + self._universal:
            if r.rule_id not in seen:
                seen.add(r.rule_id)
                unique.append(r)
        return unique


_rule_index: SigmaRuleIndex = None


def get_sigma_index() -> SigmaRuleIndex:
    global _rule_index
    if _rule_index is None:
        rules = load_sigma_rules()
        _rule_index = SigmaRuleIndex(rules)
    return _rule_index


def get_sigma_rules() -> List[SigmaRule]:
    """Backward compatibility wrapper."""
    return load_sigma_rules()
