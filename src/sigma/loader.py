# src/sigma/loader.py

import yaml
from pathlib import Path
from typing import List, Dict
from src.sigma.evaluator import SigmaRule

SIGMA_RULES_DIR = Path("data/sigma_rules")

# Only load these statuses to minimize false positives
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

            # Skip experimental rules for production use
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
    Pre-indexes Sigma rules by log source at startup.
    Reduces evaluation from O(all_rules) to O(relevant_rules) per event.

    Why this matters: 4,000 rules × 53,000 PCAP events = 212M evaluations.
    With indexing: ~200 windows rules × 1,000 windows events = 200K evaluations.
    That's a 1,000x reduction for mixed-source PCAPs.
    """

    def __init__(self, rules: List[SigmaRule]):
        self._by_product: Dict[str, List[SigmaRule]] = {}
        self._universal: List[SigmaRule] = []

        for rule in rules:
            product = rule.logsource_product
            if product:
                self._by_product.setdefault(product, []).append(rule)
            else:
                self._universal.append(rule)

        total = sum(len(v) for v in self._by_product.values())
        print(f"[Sigma Index] {total} rules indexed by product, "
              f"{len(self._universal)} universal rules")
        for product, rules_list in self._by_product.items():
            print(f"  {product}: {len(rules_list)} rules")

    def get_rules_for_source(self, source: str) -> List[SigmaRule]:
        """
        Returns only the rules relevant to this event source.
        Maps our EventSource values to Sigma product names.
        """
        source_to_product = {
            "windows": "windows",
            "linux": "linux",
            "zeek": "zeek",
            "suricata": "suricata",
            "firewall": "firewall",
        }
        product = source_to_product.get(source, source)
        return self._by_product.get(product, []) + self._universal


# Module-level cache
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
