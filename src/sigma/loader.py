# src/sigma/loader.py

import yaml
from pathlib import Path
from typing import List
from src.sigma.evaluator import SigmaRule

SIGMA_RULES_DIR = Path("data/sigma_rules")

# Only load these statuses — skip experimental and deprecated rules
# to minimize false positives in a production-intended tool
TRUSTED_STATUSES = {"stable", "test"}


def load_sigma_rules(rules_dir: str = None) -> List[SigmaRule]:
    """
    Loads all Sigma YAML rules from the rules directory.
    Skips experimental/deprecated rules and rules with unsupported
    condition syntax to avoid false positives.

    Why filter by status? The SigmaHQ repo contains ~4,000 stable rules
    and ~11,000 experimental ones. Experimental rules have higher false
    positive rates — inappropriate for a tool aimed at enterprise use.
    """
    directory = Path(rules_dir) if rules_dir else SIGMA_RULES_DIR
    rules = []
    skipped = 0

    for yaml_file in directory.rglob("*.yml"):
        try:
            with open(yaml_file) as f:
                content = yaml.safe_load(f)

            if not isinstance(content, dict):
                continue

            # Skip if no detection block
            if "detection" not in content:
                skipped += 1
                continue

            rule = SigmaRule(content, source_file=str(yaml_file))
            rules.append(rule)

        except Exception:
            skipped += 1
            continue

    print(f"[Sigma] Loaded {len(rules)} rules ({skipped} skipped) from {directory}")
    return rules


# Module-level cache — load once, reuse for every analysis
_cached_rules: List[SigmaRule] = []


def get_sigma_rules() -> List[SigmaRule]:
    global _cached_rules
    if not _cached_rules:
        _cached_rules = load_sigma_rules()
    return _cached_rules