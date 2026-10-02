# src/ai/actions.py
"""
Deterministic, evidence-driven investigation actions.

Why not the LLM: IPs, flow direction and domains are already known in code.
The local 8B model copied prompt examples verbatim (wrong direction, invented
auth-log checks) and mangled IPs ("172.17.5.13,5"). Every IP here comes from
the evidence, so none can be invented or mistyped.
"""
import base64
import ipaddress
import re
from typing import List, Optional

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_QUOTED = re.compile(r"'([^']+)'")
_WIN_HOST_RE = re.compile(r"host '([^']+)'", re.IGNORECASE)
_WIN_USER_RE = re.compile(r"user '([^']+)'", re.IGNORECASE)
_ENC_RE = re.compile(r"-e(?:nc|ncodedcommand)?\s+([A-Za-z0-9+/=]{8,})", re.IGNORECASE)


def _split_ips(ips):
    internal, external = [], []
    for ip in ips:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if a.is_multicast or a.is_loopback or a.is_link_local:
            continue
        (internal if a.is_private else external).append(ip)
    return internal, external


def _decode_encoded_command(text: str) -> Optional[str]:
    """Decode a PowerShell -EncodedCommand payload (base64 of UTF-16LE).
    Returns a short printable preview, or None if it cannot be decoded."""
    for payload in _ENC_RE.findall(text or ""):
        try:
            padded = payload + "=" * (-len(payload) % 4)
            decoded = base64.b64decode(padded, validate=True).decode("utf-16-le")
        except Exception:
            continue
        decoded = decoded.strip()
        if decoded and decoded.isprintable():
            return decoded[:120] + ("..." if len(decoded) > 120 else "")
    return None


def _windows_actions(text: str, low: str, peer: Optional[str]) -> List[str]:
    """Actions for Windows evidence: failed logons, encoded PowerShell, persistence."""
    actions: List[str] = []
    hosts = _WIN_HOST_RE.findall(text)
    users = _WIN_USER_RE.findall(text)
    win_host = hosts[0] if hosts else None
    win_user = users[0] if users else None
    where = f" on {win_host}" if win_host else ""
    who = f" for '{win_user}'" if win_user else ""

    failed_logons = any(k in low for k in ("failed logon", "failed windows logon", "brute force"))
    if failed_logons:
        origin = f" from {peer}" if peer else ""
        actions.append(
            f"Search the Security log for a successful logon (Event ID 4624){who}{origin} "
            f"after the failed attempts{where}. Failed logons alone do not show the account was accessed."
        )

    if "encoded" in low or "-enc" in low or "powershell" in low:
        decoded = _decode_encoded_command(text)
        if decoded:
            actions.append(f"Decoded PowerShell payload: {decoded}. Review what it does and what launched it{where}.")
        else:
            actions.append(
                f"Decode the PowerShell -EncodedCommand payload (base64, UTF-16LE){where} "
                f"and review the parent process that launched it."
            )

    if "scheduled task" in low:
        actions.append(
            f"Review the scheduled task definition{where} (author, trigger, action, run-as account) and compare it "
            f"with change records. Export the task XML as evidence before any change."
        )

    if "service" in low and "installed" in low:
        actions.append(
            f"Check the service binary{where}: file hash, digital signature, creation time and path. "
            f"Services started from user-writable folders are unusual."
        )

    return actions


def build_actions(descriptions: List[str], source_ips: List[str], target_ips: List[str]) -> List[str]:
    text = " ".join(descriptions or [])
    low = text.lower()
    ips = []
    for ip in list(source_ips or []) + list(target_ips or []) + _IP_RE.findall(text):
        if ip not in ips:
            ips.append(ip)
    internal, external = _split_ips(ips)
    host = internal[0] if internal else None
    peer = external[0] if external else None
    domains = [d for d in _QUOTED.findall(text)
               if "." in d and " " not in d and not _IP_RE.fullmatch(d) and not d.startswith("ET")]

    actions: List[str] = []

    actions.extend(_windows_actions(text, low, peer))

    if host and peer and any(k in low for k in ("beacon", "periodic", "backconnect", "cnc", "c2")):
        actions.append(f"Extract all flows between {host} and {peer}; measure interval, jitter and byte counts to confirm or rule out beaconing.")
        actions.append(f"Identify which process on {host} owns the connections to {peer} (needs endpoint telemetry; not present in this capture).")

    if "high-entropy" in low and domains:
        d = domains[0]
        actions.append(f"Resolve {d} and check registration age, hosting and passive-DNS history. Entropy alone does not establish DGA; it may be a lookalike or fake domain.")

    if ".top domain" in low and host:
        actions.append(f"List every .top/.xyz/.pw domain queried by {host} and check each against reputation sources.")

    if "pe exe or dll" in low and host and peer:
        actions.append(f"From HTTP/proxy logs, identify the URL, file name and hash for the download from {peer} to {host}. An executable download is informational until the file is shown to be malicious.")
        actions.append(f"Check whether the file was written to disk and executed on {host} (endpoint telemetry).")

    if "port scan" in low and len(internal) >= 2:
        actions.append(f"Confirm whether {internal[0]} is an authorized scanner or admin host; review which ports on {internal[1]} were probed and whether they were answered.")

    if "ioc match" in low and (peer or host):
        actions.append(f"Review {peer or host} against current threat intelligence (opt-in VirusTotal lookup only for public IPs).")

    if not actions:
        actions.append("Review the raw events for this incident and correlate with endpoint telemetry before acting.")

    seen, out = set(), []
    for a in actions:
        if a not in seen:
            seen.add(a)
            out.append(a)
    return out[:5]