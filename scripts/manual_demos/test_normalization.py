# scripts/test_normalization.py

from src.ingestion.windows_parser import parse_windows_4625
import json

with open("tests/samples/windows_4625.json") as f:
    raw = json.load(f)

normalized = parse_windows_4625(raw)
print(normalized.model_dump_json(indent=2))