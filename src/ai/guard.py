# src/ai/guard.py
"""Post-processing guard for LLM text. The local 8B model ignores prompt rules
(it wrote "Attacker", "compromised endpoint", "immediate containment" despite
explicit bans), so the rules are enforced here in code."""
import re

_REPLACEMENTS = [
    (re.compile(r"\bcompromised (endpoint|host|system|device|machine)\b", re.I), r"potentially affected \1"),
    (re.compile(r"\battackers?\b", re.I), "source host"),
    (re.compile(r"\bvictims?\b", re.I), "peer host"),
    (re.compile(r"\bimmediate containment\b", re.I), "alert validation before any containment"),
]
_CONTAINMENT = re.compile(r"\b(isolate|containment|block (?:the )?(?:ip|source))\b", re.I)

NOTE = ("\n\n[Wording adjusted: this tool cannot determine attacker/victim roles or "
        "confirmed compromise from alerts alone. Containment is not recommended until the alert is validated.]")


def sanitize_ai_text(text: str, evidence_text: str = "", add_note: bool = True) -> str:
    changed = False
    for pattern, repl in _REPLACEMENTS:
        new = pattern.sub(repl, text)
        changed = changed or new != text
        text = new
    if _CONTAINMENT.search(text):
        changed = True
    # "Informational signature matched" is a prompt artefact; it is wrong on ET MALWARE/TROJAN.
    if re.search(r"ET (MALWARE|TROJAN)", evidence_text or ""):
        text = re.sub(r"\s*Informational signature matched\.?", "", text, flags=re.I)
    return text + NOTE if (changed and add_note) else text
