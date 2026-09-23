# src/sigma/evaluator.py

"""
Evaluates Sigma rules against NormalizedEvent objects.

Design decision: we parse Sigma YAML ourselves rather than using
pySigma's compilation pipeline. Why? pySigma compiles to query
languages (SPL, KQL) — we need Python function evaluation against
our own objects, not a query string. Parsing the YAML detection
logic ourselves gives us direct control and is simpler for our use case.
"""

import yaml
import re
from pathlib import Path
from typing import List, Optional, Any
from dataclasses import dataclass
from src.models.event_schema import NormalizedEvent, EventSource
from src.sigma.field_mapping import get_field_value


@dataclass
class SigmaMatch:
    rule_id: str
    rule_name: str
    severity: str
    mitre_technique: Optional[str]
    mitre_tactic: Optional[str]
    description: str
    matched_fields: dict


class SigmaRule:
    """
    A parsed, evaluable Sigma rule.
    Loaded once at startup, evaluated many times per ingestion run.
    """

    def __init__(self, rule_dict: dict, source_file: str = ""):
        self.source_file = source_file
        self.rule_id = rule_dict.get("id", "unknown")
        self.title = rule_dict.get("title", "Unknown Rule")
        self.description = rule_dict.get("description", "")
        self.raw_level = rule_dict.get("level", "medium")
        self.status = rule_dict.get("status", "experimental")

        # MITRE mapping
        tags = rule_dict.get("tags", [])
        self.mitre_techniques = [t.replace("attack.t", "T").upper() for t in tags if t.startswith("attack.t")]
        self.mitre_tactics = [t.replace("attack.", "").replace("_", " ").title() for t in tags if t.startswith("attack.") and not t.startswith("attack.t")]

        # Log source filter — only evaluate rules matching our sources
        logsource = rule_dict.get("logsource", {})
        self.logsource_product = logsource.get("product", "").lower()
        self.logsource_category = logsource.get("category", "").lower()
        self.logsource_service = logsource.get("service", "").lower()

        # Detection logic
        self.detection = rule_dict.get("detection", {})
        self.condition = self.detection.get("condition", "")

    def _matches_logsource(self, event: NormalizedEvent) -> bool:
        """
        Quick pre-filter: skip rules that can't possibly match this
        event's source. This is the key optimization that prevents
        evaluating all 15,000 rules against every event.
        """
        product = self.logsource_product
        category = self.logsource_category

        if product == "windows" and event.source != "windows":
            return False
        if product == "linux" and event.source != "linux":
            return False
        if product == "zeek" and event.source != "zeek":
            return False

        return True

    def _evaluate_selection(self, selection_dict: dict, event: NormalizedEvent) -> bool:
        """
        Evaluates a single Sigma selection block against an event.
        A selection block is an AND of all its field conditions.
        """
        for field_expr, expected in selection_dict.items():
            # Handle modifiers: field|contains, field|startswith, etc.
            parts = field_expr.split("|")
            field_name = parts[0]
            modifier = parts[1] if len(parts) > 1 else "exact"

            actual = get_field_value(event, field_name)
            if actual is None:
                return False  # field not in our schema - can't match

            actual_str = str(actual).lower() if actual is not None else ""

            # Expected can be a single value or a list (OR within a field)
            if not isinstance(expected, list):
                expected = [expected]

            matched_any = False
            for exp_val in expected:
                exp_str = str(exp_val).lower()
                if modifier == "contains" and exp_str in actual_str:
                    matched_any = True
                    break
                elif modifier == "startswith" and actual_str.startswith(exp_str):
                    matched_any = True
                    break
                elif modifier == "endswith" and actual_str.endswith(exp_str):
                    matched_any = True
                    break
                elif modifier == "re":
                    if re.search(exp_str, actual_str, re.IGNORECASE):
                        matched_any = True
                        break
                elif modifier in ("exact", "equals") and actual_str == exp_str:
                    matched_any = True
                    break
                elif modifier == "exact" and actual_str == exp_str:
                    matched_any = True
                    break

            if not matched_any:
                return False

        return True

    def evaluate(self, event: NormalizedEvent) -> Optional[SigmaMatch]:
        """
        Returns a SigmaMatch if the rule fires on this event, None otherwise.
        """
        if not self._matches_logsource(event):
            return None

        # Build a dict of all named selections in the detection block
        selections: dict[str, bool] = {}
        for key, value in self.detection.items():
            if key == "condition":
                continue
            if isinstance(value, dict):
                selections[key] = self._evaluate_selection(value, event)
            elif isinstance(value, list):
                # List of dicts = OR between them
                selections[key] = any(
                    self._evaluate_selection(v, event) if isinstance(v, dict) else False
                    for v in value
                )
            else:
                selections[key] = False

        if not selections:
            return None

        # Evaluate the condition expression
        # Supports: 'selection', 'all of selection*', '1 of filter*', NOT, AND, OR
        try:
            result = self._eval_condition(self.condition, selections)
        except Exception:
            return None

        if not result:
            return None

        matched_fields = {
            k: get_field_value(event, k)
            for k in self.detection.keys()
            if k != "condition"
        }

        return SigmaMatch(
            rule_id=self.rule_id,
            rule_name=self.title,
            severity=self.raw_level,
            mitre_technique=self.mitre_techniques[0] if self.mitre_techniques else None,
            mitre_tactic=self.mitre_tactics[0] if self.mitre_tactics else None,
            description=self.description or self.title,
            matched_fields=matched_fields,
        )

    def _eval_condition(self, condition: str, selections: dict) -> bool:
        """
        Evaluates simple Sigma condition expressions.
        Handles the most common patterns: selection, all of X, 1 of X,
        NOT, AND, OR, and their combinations.
        """
        condition = condition.strip()

        # "all of selection*" — all keys matching the pattern must be True
        m = re.match(r"all of (\w+)\*", condition)
        if m:
            prefix = m.group(1)
            matching = [v for k, v in selections.items() if k.startswith(prefix)]
            return bool(matching) and all(matching)

        # "1 of filter*" or "1 of selection*"
        m = re.match(r"1 of (\w+)\*", condition)
        if m:
            prefix = m.group(1)
            matching = [v for k, v in selections.items() if k.startswith(prefix)]
            return any(matching)

        # "not X"
        if condition.lower().startswith("not "):
            inner = condition[4:].strip()
            return not self._eval_condition(inner, selections)

        # "X and Y"
        if " and " in condition.lower():
            parts = re.split(r"\band\b", condition, flags=re.IGNORECASE)
            return all(self._eval_condition(p.strip(), selections) for p in parts)

        # "X or Y"
        if " or " in condition.lower():
            parts = re.split(r"\bor\b", condition, flags=re.IGNORECASE)
            return any(self._eval_condition(p.strip(), selections) for p in parts)

        # Simple named selection
        return selections.get(condition, False)