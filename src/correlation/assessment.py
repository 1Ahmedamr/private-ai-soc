# src/correlation/assessment.py
"""Deterministic campaign assessment for one host, built from detections only.
Confidence rule (network evidence only, so never 'High'):
  1 indicator type = Low, 2 = Medium, 3+ = Medium-High."""

_INDICATORS = [
    ("Periodic beaconing", ("periodic connections", "beacon")),
    ("DNS queries to suspicious domains", (".top domain", "high-entropy domain")),
    ("Malware-related Suricata signature", ("et malware", "et trojan")),
    ("Executable download activity", ("pe exe or dll",)),
    ("Match against a known-bad IP list", ("ioc match",)),
    ("Port scanning", ("port scan",)),
]


def build_assessment(entries: list, host: str = "") -> dict:
    blob = " ".join([e.get("title", "") + " " + " ".join(e.get("evidence", [])) for e in entries]).lower()
    found = [name for name, keys in _INDICATORS if any(k in blob for k in keys)]
    conf = {0: "None", 1: "Low", 2: "Medium"}.get(len(found), "Medium-High")
    c2ish = any(n in found for n in ("Periodic beaconing", "Malware-related Suricata signature"))
    if not found:
        text = "No corroborating indicators were identified."
    elif c2ish:
        text = (f"These indicators collectively suggest possible post-compromise command-and-control "
                f"activity involving host {host}. They are network observations, not confirmed compromise.")
    else:
        text = f"These indicators suggest activity involving host {host} that warrants investigation."
    return {
        "indicators": found,
        "confidence": conf,
        "text": text,
        "attribution": "Malware family attribution: not determined from network evidence alone.",
    }
