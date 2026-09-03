from src.ingestion.windows_parser import parse_windows_event


event = parse_windows_event(
    "tests/samples/windows_4625.json"
)

print(event.model_dump_json(indent=4))