# src/detection/rule_analytics.py

"""
Tracks which detection rules fire and how often.
Persists to SQLite so data accumulates across analysis sessions.
Gives you real data on which rules are noisy vs useful.
"""

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import List, Dict
from dataclasses import dataclass


ANALYTICS_DB = "data/processed/rule_analytics.db"


@dataclass
class RuleStats:
    rule_name: str
    rule_id: str
    total_fires: int
    last_fired: str
    first_fired: str


def _get_conn() -> sqlite3.Connection:
    Path(ANALYTICS_DB).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(ANALYTICS_DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS rule_fires (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_name TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            fired_at TEXT NOT NULL,
            severity TEXT,
            confidence REAL
        )
    """)
    conn.commit()
    return conn


def record_rule_fires(detections: list) -> None:
    """
    Records all triggered detections to the analytics database.
    Call this after every analysis run.
    """
    triggered = [d for d in detections if d.triggered]
    if not triggered:
        return
    conn = _get_conn()
    now = datetime.utcnow().isoformat()
    conn.executemany(
        "INSERT INTO rule_fires (rule_name, rule_id, fired_at, severity, confidence) VALUES (?,?,?,?,?)",
        [(d.rule_name, d.rule_id, now, d.severity, d.confidence) for d in triggered]
    )
    conn.commit()
    conn.close()


def get_rule_stats() -> List[RuleStats]:
    """
    Returns a summary of how often each rule has fired, sorted by frequency.
    """
    try:
        conn = _get_conn()
        rows = conn.execute("""
            SELECT rule_name, rule_id,
                   COUNT(*) as total_fires,
                   MAX(fired_at) as last_fired,
                   MIN(fired_at) as first_fired
            FROM rule_fires
            GROUP BY rule_id
            ORDER BY total_fires DESC
        """).fetchall()
        conn.close()
        return [RuleStats(*row) for row in rows]
    except Exception:
        return []


def get_never_fired_rules(all_known_rule_ids: List[str]) -> List[str]:
    """
    Returns rule IDs that have never fired in the analytics database.
    These are candidates for removal or threshold adjustment.
    """
    try:
        conn = _get_conn()
        fired_ids = {row[0] for row in conn.execute("SELECT DISTINCT rule_id FROM rule_fires").fetchall()}
        conn.close()
        return [rid for rid in all_known_rule_ids if rid not in fired_ids]
    except Exception:
        return all_known_rule_ids