# tests/unit/test_watch_ingest.py

import json
from pathlib import Path
from src.pipeline.watch_ingest import _pick_parser
from src.ingestion.windows_parser import parse_windows_events
from src.ingestion.linux_parser import parse_linux_ssh_events


def test_pick_parser_matches_windows_prefix():
    assert _pick_parser("windows_batch1.json") is parse_windows_events


def test_pick_parser_matches_linux_prefix():
    assert _pick_parser("linux_ssh_today.json") is parse_linux_ssh_events


def test_pick_parser_returns_none_for_unknown_prefix():
    assert _pick_parser("random_file.json") is None