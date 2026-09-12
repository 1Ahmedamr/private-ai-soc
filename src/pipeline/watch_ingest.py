# src/pipeline/watch_ingest.py

import time
import json
import shutil
from pathlib import Path
from src.ingestion.windows_parser import parse_windows_events
from src.ingestion.linux_parser import parse_linux_ssh_events
from src.ingestion.zeek_parser import parse_zeek_conn_logs
from src.storage.event_store import EventStore
from src.incidents.store import IncidentStore
from src.assets.inventory import AssetInventory
from src.pipeline.orchestrator import PipelineOrchestrator

WATCH_DIR = Path("data/incoming")
PROCESSED_DIR = Path("data/processed/ingested_archive")

# Filename convention decides which parser to use - simple, explicit,
# no fragile auto-detection guessing at file content.
_PREFIX_PARSER_MAP = {
    "windows_": parse_windows_events,
    "linux_": parse_linux_ssh_events,
    "zeek_": parse_zeek_conn_logs,
}


def _pick_parser(filename: str):
    for prefix, parser in _PREFIX_PARSER_MAP.items():
        if filename.startswith(prefix):
            return parser
    return None


def watch_and_ingest(orchestrator: PipelineOrchestrator, poll_seconds: int = 3) -> None:
    """
    Polls WATCH_DIR for new .json files, parses them by filename prefix,
    ingests through the orchestrator, then archives the file so it's
    never processed twice. This is a crude but honest stand-in for a
    real log shipper (Filebeat, rsyslog) - the pipeline downstream
    (detection/correlation/risk/AI) doesn't know or care that this is
    simulated rather than a real agent.
    """
    WATCH_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Watching {WATCH_DIR} for new log files (prefix windows_/linux_/zeek_)...")
    try:
        while True:
            for file_path in WATCH_DIR.glob("*.json"):
                parser = _pick_parser(file_path.name)
                if not parser:
                    print(f"[SKIP] {file_path.name} - unrecognized prefix, expected windows_/linux_/zeek_")
                    shutil.move(str(file_path), PROCESSED_DIR / file_path.name)
                    continue

                with open(file_path) as f:
                    raw_events = json.load(f)

                events = parser(raw_events)
                incidents = orchestrator.ingest(events)
                print(f"[INGESTED] {file_path.name}: {len(events)} events -> {len(incidents)} incident(s)")

                shutil.move(str(file_path), PROCESSED_DIR / file_path.name)

            time.sleep(poll_seconds)
    except KeyboardInterrupt:
        print("\nStopped watching.")