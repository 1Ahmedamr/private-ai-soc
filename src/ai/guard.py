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

# Claims the model likes to add without evidence. Each entry is
# (phrase that makes a sentence a claim, pattern the evidence must contain to support it).
_UNSUPPORTED_CLAIMS = [
    (re.compile(r"\blateral movement\b", re.I), re.compile(r"lateral|psexec|\bsmb\b|\brdp\b|winrm|remote service", re.I)),
    (re.compile(r"\bexfiltrat\w*|\bdata theft\b|\bstole\w*|\bstolen\b", re.I), re.compile(r"exfil|upload|data transfer|\bstole|\bstolen", re.I)),
    (re.compile(r"\bransomware\b", re.I), re.compile(r"ransom|encrypt", re.I)),
    (re.compile(r"\breconnaissance\b", re.I), re.compile(r"scan|recon|enumerat|discovery|probe", re.I)),
]
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+")

NOTE = ("\n\n[Wording adjusted: this tool cannot determine attacker/victim roles or "
        "confirmed compromise from alerts alone. Containment is not recommended until the alert is validated.]")


def drop_unsupported_claims(text: str, evidence_text: str) -> str:
    """Remove sentences that assert something the evidence never mentions.
    If every sentence would be removed, the original text is kept."""
    if not evidence_text:
        return text
    kept = []
    for sentence in _SENTENCE_SPLIT.split(text.strip()):
        unsupported = any(
            claim.search(sentence) and not support.search(evidence_text)
            for claim, support in _UNSUPPORTED_CLAIMS
        )
        if not unsupported:
            kept.append(sentence)
    return " ".join(kept) if kept else text

def _drop_sentences_starting(text: str, prefix: str) -> str:
    kept = [s for s in _SENTENCE_SPLIT.split(text.strip()) if not s.strip().lower().startswith(prefix)]
    return " ".join(kept) if kept else text


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
    # Also wrong when the evidence has no ET INFO signature at all (e.g. Windows logs).
    elif evidence_text and "ET INFO" not in evidence_text:
        text = _drop_sentences_starting(text, "informational signature matched")
    text = drop_unsupported_claims(text, evidence_text)
    return text + NOTE if (changed and add_note) else text