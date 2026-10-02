# src/webapp/analysis_store.py

"""
Server-side storage for the last analysis result.

Why: Flask's default session lives in a browser cookie capped at ~4KB.
A real PCAP analysis (incidents, detections, host summaries) is far larger,
so browsers silently dropped the cookie and features like the chat and
timeline lost their context. The cookie now carries only a random id.

Files live under data/processed/sessions (local only, gitignored with the
rest of data/processed). Only the oldest beyond MAX_FILES are pruned.
"""

import json
import re
import secrets
from pathlib import Path
from typing import List, Optional

STORE_DIR = Path("data/processed/sessions")
MAX_FILES = 50
_ID_RE = re.compile(r"^[a-f0-9]{32}$")


def _prune() -> None:
    files = sorted(STORE_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime)
    for old in files[:-MAX_FILES + 1] if len(files) >= MAX_FILES else []:
        try:
            old.unlink()
        except OSError:
            pass


def save_analysis(analysis: dict) -> str:
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    _prune()
    analysis_id = secrets.token_hex(16)
    (STORE_DIR / f"{analysis_id}.json").write_text(
        json.dumps({"analysis": analysis, "chat_history": []})
    )
    return analysis_id


def load_analysis(analysis_id: Optional[str]) -> Optional[dict]:
    # Strict id format: blocks path traversal even though the id comes
    # from a signed cookie.
    if not analysis_id or not _ID_RE.match(str(analysis_id)):
        return None
    path = STORE_DIR / f"{analysis_id}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def save_chat_history(analysis_id: str, history: List[dict]) -> None:
    stored = load_analysis(analysis_id)
    if stored is None:
        return
    stored["chat_history"] = history
    (STORE_DIR / f"{analysis_id}.json").write_text(json.dumps(stored))
