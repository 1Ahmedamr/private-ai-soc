# src/ingestion/windows_parser.py

from datetime import datetime, timezone

from src.models.event_schema import NormalizedEvent, EventSource, EventType, Severity


def _parse_ts(value: str) -> datetime:
    """Parse ISO timestamps, including a trailing 'Z' (Python 3.9 can't).
    Timezone-aware values are converted to naive UTC to match existing samples."""
    ts = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    if ts.tzinfo is not None:
        ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
    return ts


def _get(raw: dict, *keys):
    """Return the first non-empty value among alias keys."""
    for key in keys:
        value = raw.get(key)
        if value not in (None, ""):
            return value
    return None


def parse_windows_4625(raw_event: dict) -> NormalizedEvent:
    """Windows Event ID 4625 (failed logon) -> common schema."""
    return NormalizedEvent(
        timestamp=_parse_ts(raw_event["timestamp"]),
        source=EventSource.WINDOWS,
        event_type=EventType.AUTHENTICATION,
        host=_get(raw_event, "host", "computer"),
        user=_get(raw_event, "username", "user"),
        src_ip=_get(raw_event, "src_ip", "source_ip"),
        event_id=str(raw_event.get("event_id", "4625")),
        status="failure",
        severity=Severity.MEDIUM,
        raw_data=raw_event,
    )


def parse_windows_process_event(raw_event: dict) -> NormalizedEvent:
    """Windows Event ID 4688 (process creation) -> common schema."""
    return NormalizedEvent(
        timestamp=_parse_ts(raw_event["timestamp"]),
        source=EventSource.WINDOWS,
        event_type=EventType.PROCESS_EXECUTION,
        host=_get(raw_event, "host", "computer"),
        user=_get(raw_event, "username", "user"),
        process=_get(raw_event, "process_name"),
        command=_get(raw_event, "command_line"),
        parent_process=_get(raw_event, "parent_process", "parent_image", "ParentImage"),
        event_id=str(raw_event.get("event_id", "4688")),
        severity=Severity.INFO,
        raw_data=raw_event,
    )


def parse_windows_persistence_event(raw_event: dict) -> NormalizedEvent:
    """4698 (scheduled task created) and 7045 (service installed).
    Stored as process-execution events: the thing that will run goes in `command`."""
    event_id = str(raw_event.get("event_id"))
    if event_id == "4698":
        process = _get(raw_event, "task_name")
        command = _get(raw_event, "action")
    else:  # 7045
        process = _get(raw_event, "service_name")
        command = _get(raw_event, "service_path")

    return NormalizedEvent(
        timestamp=_parse_ts(raw_event["timestamp"]),
        source=EventSource.WINDOWS,
        event_type=EventType.PROCESS_EXECUTION,
        host=_get(raw_event, "host", "computer"),
        user=_get(raw_event, "username", "user"),
        process=process,
        command=command,
        event_id=event_id,
        severity=Severity.MEDIUM,
        raw_data=raw_event,
    )


_PARSERS = {
    "4625": parse_windows_4625,
    "4688": parse_windows_process_event,
    "4698": parse_windows_persistence_event,
    "7045": parse_windows_persistence_event,
}


def parse_windows_events(raw_events: list[dict]) -> list[NormalizedEvent]:
    """Dispatch each raw Windows event to the parser for its event_id.
    Events with no event_id are treated as 4625 (previous behaviour);
    unsupported event IDs are skipped instead of being parsed as failed logons."""
    parsed = []
    for raw in raw_events:
        parser = _PARSERS.get(str(raw.get("event_id", "4625")))
        if parser is not None:
            parsed.append(parser(raw))
    return parsed


def parse_windows_process_events(raw_events: list[dict]) -> list[NormalizedEvent]:
    return [parse_windows_process_event(raw) for raw in raw_events]