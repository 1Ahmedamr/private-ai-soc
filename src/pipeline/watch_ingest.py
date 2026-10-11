# src/pipeline/watch_ingest.py

import time
import json
import shutil
from datetime import datetime, timezone
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
FAILED_DIR = Path("data/processed/failed_files")
SKIPPED_DIR = Path("data/processed/skipped_files")
# The watcher and the dashboard are separate processes, so the watcher reports its own
# health through a small file: timestamps only, never log content.
STATUS_FILE = Path("data/processed/watcher_status.json")

# Filename convention decides which parser to use - simple, explicit,
# no fragile auto-detection guessing at file content.
_PREFIX_PARSER_MAP = {
    "windows_": parse_windows_events,
    "linux_": parse_linux_ssh_events,
    "zeek_": parse_zeek_conn_logs,
}

_status_warning_shown = False


def _pick_parser(filename: str):
    for prefix, parser in _PREFIX_PARSER_MAP.items():
        if filename.startswith(prefix):
            return parser
    return None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _read_status() -> dict:
    try:
        data = json.loads(STATUS_FILE.read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_status(**fields) -> None:
    """Never raises: failing to report health must not stop ingestion, or turn a file that
    was ingested fine into a failure."""
    global _status_warning_shown
    try:
        status = _read_status()
        status.update(fields)
        STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = STATUS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(status))
        tmp.replace(STATUS_FILE)
    except OSError as exc:
        if not _status_warning_shown:
            _status_warning_shown = True
            print(f"[WARNING] could not update {STATUS_FILE}: {exc}")


def _move_without_overwrite(file_path: Path, directory: Path) -> Path:
    """Move a file into a folder, never replacing one that is already there. A plain move
    silently overwrites a same-named file, which would destroy earlier evidence."""
    directory.mkdir(parents=True, exist_ok=True)
    dest = directory / file_path.name
    if dest.exists():
        stamp = datetime.now().strftime("%Y%m%dT%H%M%S")
        n = 1
        while dest.exists():
            dest = directory / f"{file_path.stem}.{stamp}-{n}{file_path.suffix}"
            n += 1
    shutil.move(str(file_path), str(dest))
    return dest


def process_file(file_path: Path, orchestrator: PipelineOrchestrator) -> str:
    """Handles one file. Returns 'ingested', 'failed', 'skipped' or 'pending'."""
    parser = _pick_parser(file_path.name)
    if not parser:
        print(f"[SKIP] {file_path.name} - unrecognized prefix, expected windows_/linux_/zeek_; moved to {SKIPPED_DIR}")
        _move_without_overwrite(file_path, SKIPPED_DIR)
        return "skipped"

    try:
        size_1 = file_path.stat().st_size
        time.sleep(0.2)
        if file_path.stat().st_size != size_1:
            return "pending"  # still being written; look again next poll
    except FileNotFoundError:
        return "pending"  # removed between listing and reading

    try:
        with open(file_path) as f:
            raw_events = json.load(f)
        if isinstance(raw_events, dict):
            raw_events = [raw_events]

        events = parser(raw_events)
        incidents = orchestrator.ingest(events)
        print(f"[INGESTED] {file_path.name}: {len(events)} events -> {len(incidents)} incident(s)")
        _move_without_overwrite(file_path, PROCESSED_DIR)
        _write_status(last_ingest_at=_now())
        return "ingested"
    except Exception as exc:
        # One bad file must never stop the watcher (and, with a restart policy, loop on it forever).
        print(f"[FAILED] {file_path.name}: {type(exc).__name__}: {exc}")
        _move_without_overwrite(file_path, FAILED_DIR)
        return "failed"


def pipeline_health() -> dict:
    """Counts and times only, never filenames, so the dashboard can show pipeline health."""
    def count(directory: Path, pattern: str = "*") -> int:
        return sum(1 for p in directory.glob(pattern) if p.is_file()) if directory.exists() else 0

    status = _read_status()
    return {
        "incoming_backlog": count(WATCH_DIR, "*.json"),
        "quarantined": count(FAILED_DIR),
        "skipped": count(SKIPPED_DIR),
        "last_ingest_at": status.get("last_ingest_at"),
        "last_poll_at": status.get("last_poll_at"),
    }


def watch_and_ingest(orchestrator: PipelineOrchestrator, poll_seconds: int = 3) -> None:
    """
    Polls WATCH_DIR for new .json files, parses them by filename prefix,
    ingests through the orchestrator, then archives the file so it's
    never processed twice. This is a crude but honest stand-in for a
    real log shipper (Filebeat, rsyslog) - the pipeline downstream
    (detection/correlation/risk/AI) doesn't know or care that this is
    simulated rather than a real agent.

    Each poll records a heartbeat (last_poll_at) and each successful ingest records
    last_ingest_at, so silence can be told apart from a watcher that has stopped.
    """
    WATCH_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Watching {WATCH_DIR} for new log files (prefix windows_/linux_/zeek_)...")
    try:
        while True:
            _write_status(last_poll_at=_now())
            for file_path in WATCH_DIR.glob("*.json"):
                process_file(file_path, orchestrator)
            time.sleep(poll_seconds)
    except KeyboardInterrupt:
        print("\nStopped watching.")
