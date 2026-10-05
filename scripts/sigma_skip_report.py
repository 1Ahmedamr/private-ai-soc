from collections import Counter, defaultdict
import yaml

from src.sigma.evaluator import SigmaRule
from src.sigma.loader import SIGMA_RULES_DIR, TRUSTED_STATUSES

reasons = Counter()
examples = defaultdict(list)


def note(reason, path):
    reasons[reason] += 1
    if len(examples[reason]) < 3:
        examples[reason].append(str(path))


total = 0
for f in SIGMA_RULES_DIR.rglob("*.yml"):
    total += 1
    try:
        with open(f, encoding="utf-8", errors="ignore") as fh:
            c = yaml.safe_load(fh)
        if not isinstance(c, dict):
            note("YAML is not a mapping", f)
            continue
        if "detection" not in c:
            note("correlation rule (no detection)" if "correlation" in c else "no detection section", f)
            continue
        status = c.get("status", "experimental")
        if status not in TRUSTED_STATUSES:
            note(f"status={status}", f)
            continue
        SigmaRule(c, source_file=str(f))
    except Exception as e:
        note(f"error: {type(e).__name__}: {str(e)[:70]}", f)

skipped = sum(reasons.values())
print(f"files: {total} | loaded: {total - skipped} | skipped: {skipped}\n")
for reason, n in reasons.most_common():
    print(f"{n:5}  {reason}")
    for p in examples[reason]:
        print(f"         e.g. {p}")
