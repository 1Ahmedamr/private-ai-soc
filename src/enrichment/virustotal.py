# src/enrichment/virustotal.py

"""
VirusTotal enrichment — EXPLICITLY OPT-IN ONLY.

Design principles:
1. NEVER called automatically. Only on explicit analyst request.
2. Shows a clear privacy warning before submitting anything.
3. Requires VT_API_KEY environment variable — no hardcoded keys.
4. Results are cached in SQLite to avoid re-querying the same IOC.
5. Rate-limited to stay within VT free tier (4 requests/minute).

Why not automatic? Submitting an IP to VirusTotal tells VirusTotal
(and potentially other parties) that you investigated that IP, at
what time, from what API key. For a privacy-first SOC tool, that
information leakage is only acceptable when the analyst explicitly
chooses to make it.
"""

import os
import time
import sqlite3
import json
import requests
from pathlib import Path
from typing import Optional
from dataclasses import dataclass


VT_API_URL = "https://www.virustotal.com/api/v3"
CACHE_DB = "data/processed/vt_cache.db"
RATE_LIMIT_SECONDS = 15  # 4 requests/minute on free tier


@dataclass
class VTResult:
    ioc_value: str
    ioc_type: str           # "ip", "domain", "hash"
    malicious_votes: int
    suspicious_votes: int
    harmless_votes: int
    total_engines: int
    community_score: int    # -100 to 100, negative = malicious
    last_analysis_date: str
    threat_names: list
    permalink: str


def _get_cache_conn() -> sqlite3.Connection:
    Path(CACHE_DB).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(CACHE_DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS vt_cache (
            ioc_value TEXT PRIMARY KEY,
            ioc_type TEXT,
            result_json TEXT,
            cached_at TEXT
        )
    """)
    conn.commit()
    return conn


def _check_cache(ioc_value: str) -> Optional[dict]:
    try:
        conn = _get_cache_conn()
        row = conn.execute(
            "SELECT result_json FROM vt_cache WHERE ioc_value = ?",
            (ioc_value,)
        ).fetchone()
        conn.close()
        if row:
            return json.loads(row[0])
    except Exception:
        pass
    return None


def _save_cache(ioc_value: str, ioc_type: str, result: dict) -> None:
    try:
        conn = _get_cache_conn()
        conn.execute(
            "INSERT OR REPLACE INTO vt_cache (ioc_value, ioc_type, result_json, cached_at) VALUES (?,?,?,datetime('now'))",
            (ioc_value, ioc_type, json.dumps(result))
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def _parse_vt_response(data: dict, ioc_value: str, ioc_type: str) -> VTResult:
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return VTResult(
        ioc_value=ioc_value,
        ioc_type=ioc_type,
        malicious_votes=stats.get("malicious", 0),
        suspicious_votes=stats.get("suspicious", 0),
        harmless_votes=stats.get("harmless", 0),
        total_engines=sum(stats.values()),
        community_score=attrs.get("reputation", 0),
        last_analysis_date=str(attrs.get("last_analysis_date", "")),
        threat_names=list(set(
            r.get("result", "") for r in attrs.get("last_analysis_results", {}).values()
            if r.get("category") == "malicious" and r.get("result")
        ))[:5],
        permalink=f"https://www.virustotal.com/gui/{ioc_type}/{ioc_value}",
    )


def enrich_ip(ip: str) -> Optional[VTResult]:
    """
    Looks up an IP address on VirusTotal.
    Requires VT_API_KEY environment variable.
    Results are cached locally to avoid repeated API calls.
    """
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        return None

    # Check cache first — no network call needed if we've seen this before
    cached = _check_cache(ip)
    if cached:
        return _parse_vt_response(cached, ip, "ip_addresses")

    try:
        time.sleep(RATE_LIMIT_SECONDS)  # respect free tier rate limit
        response = requests.get(
            f"{VT_API_URL}/ip_addresses/{ip}",
            headers={"x-apikey": api_key},
            timeout=30,
        )
        if response.status_code == 200:
            data = response.json()
            _save_cache(ip, "ip_addresses", data)
            return _parse_vt_response(data, ip, "ip_addresses")
        elif response.status_code == 404:
            return None
        else:
            print(f"[VT] API error {response.status_code} for {ip}")
            return None
    except Exception as e:
        print(f"[VT] Request failed for {ip}: {e}")
        return None


def enrich_hash(file_hash: str) -> Optional[VTResult]:
    """Looks up a file hash on VirusTotal."""
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        return None

    cached = _check_cache(file_hash)
    if cached:
        return _parse_vt_response(cached, file_hash, "files")

    try:
        time.sleep(RATE_LIMIT_SECONDS)
        response = requests.get(
            f"{VT_API_URL}/files/{file_hash}",
            headers={"x-apikey": api_key},
            timeout=30,
        )
        if response.status_code == 200:
            data = response.json()
            _save_cache(file_hash, "files", data)
            return _parse_vt_response(data, file_hash, "files")
        return None
    except Exception as e:
        print(f"[VT] Request failed for {file_hash}: {e}")
        return None
