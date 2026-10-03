# src/ingestion/excel_parser.py
"""
Excel (.xlsx / .xls) ingestion for firewall / SIEM exports.

Real exports never agree on column names, so columns are matched by alias after
normalising the header text (case, spaces, underscores and punctuation are ignored:
"Source IP", "src-ip" and "SRC_IP" are the same column). The header row does not
have to be the first row; the parser scans the top of each sheet for it.

Every row becomes a NormalizedEvent. Bad cells never abort the parse:
  * empty / NaN / "N/A" cells        -> None
  * non-UTF-8 bytes                  -> decoded with replacement characters
  * invalid IPs / ports              -> None (the original value stays in raw_data)
  * unparseable timestamps           -> carried over from the nearest valid row and
                                        flagged with raw_data["_timestamp_fallback"]
Timestamps are converted to UTC and stored as NAIVE datetimes, because that is what
the rest of the pipeline uses (windows_parser does the same). normalize_timestamp()
returns the same instant as an ISO-8601 string ending in "Z".

parse_excel() never raises on bad input. Use parse_excel_with_report() to see what
was skipped and why.
"""

import ipaddress
import logging
import math
import re
import warnings
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np
import pandas as pd

from src.models.event_schema import EventSource, EventType, NormalizedEvent, Severity

logger = logging.getLogger(__name__)

__all__ = [
    "ExcelParseReport",
    "FIELD_ALIASES",
    "build_column_map",
    "clean_cell",
    "detect_excel_engine",
    "infer_event_type",
    "infer_source",
    "infer_status",
    "normalize_column_name",
    "normalize_timestamp",
    "parse_excel",
    "parse_excel_with_report",
    "parse_ip_and_port",
    "parse_port",
    "parse_timestamp",
    "row_to_event",
]

# --------------------------------------------------------------------------- #
# Column aliases (priority order: the first alias present in the sheet wins)
# --------------------------------------------------------------------------- #

FIELD_ALIASES: Dict[str, List[str]] = {
    "timestamp": ["timestamp", "time", "date", "datetime", "EventTime", "@timestamp"],
    "src_ip": ["src_ip", "source_ip", "source", "src", "ClientIP", "src_addr"],
    "src_port": ["src_port", "source_port", "sport", "srcport"],
    "dst_ip": ["dst_ip", "dest_ip", "destination", "dst", "ServerIP", "dst_addr"],
    "dst_port": ["dst_port", "dest_port", "dport", "dstport"],
    "protocol": ["protocol", "proto", "app_proto"],
    "action": ["event_type", "action", "message", "event", "category", "signature"],
    "event_id": ["event_id", "EventID", "event_code", "EventCode"],
    "user": ["user", "username", "user_name", "account", "TargetUserName"],
    "host": ["hostname", "computer_name", "host", "device"],
}

MAX_HEADER_SCAN_ROWS = 25      # how far down a sheet we look for the header row
MIN_RECOGNIZED_COLUMNS = 2     # header row must match at least this many known fields
MAX_TEXT_LEN = 1000            # cap for any text value used in an event field
MAX_RAW_LEN = 2000             # cap for text values copied into raw_data
MAX_EVENT_ID_LEN = 200
MAX_REPORT_ERRORS = 50

_NULL_TOKENS = {"", "nan", "none", "null", "n/a", "na", "-", "--", "nat"}
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_NUMERIC_TEXT = re.compile(r"^\d{5,}(\.\d+)?$")
_IPV4_LOOSE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_IPV4_WITH_PORT = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$")
_PORT_TEXT = re.compile(r"^(\d{1,5})(?:\.0+)?(?:/[A-Za-z]+)?$")

_AUTH_RE = re.compile(
    r"\b(log[\s_-]?on|log[\s_-]?in|log[\s_-]?off|authentication|auth|password|kerberos|ntlm|4624|4625|4634)\b",
    re.I,
)
_ALERT_RE = re.compile(r"\balert\b|\bET\s+[A-Z]+|malware|trojan|exploit|\bc2\b|beacon", re.I)
_DNS_RE = re.compile(r"\bdns\b|\bnxdomain\b", re.I)
_HTTP_RE = re.compile(r"\bhttps?\b|\burl\b", re.I)
_FAILURE_RE = re.compile(
    r"\b(deny|denied|drop|dropped|block|blocked|reject|rejected|fail|failed|failure|invalid|4625)\b", re.I
)
_SUCCESS_RE = re.compile(
    r"\b(allow|allowed|permit|permitted|accept|accepted|success|succeeded|successful|4624)\b", re.I
)

_PROTOCOL_NUMBERS = {"1": "icmp", "6": "tcp", "17": "udp"}

_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"   # legacy .xls
_ZIP_MAGIC = b"PK\x03\x04"                          # .xlsx / .xlsm

_EXCEL_EPOCH = datetime(1899, 12, 30)
_UNIX_EPOCH = datetime(1970, 1, 1)


def normalize_column_name(name: Any) -> str:
    """Lower-case and strip everything except letters and digits."""
    if _is_missing(name):
        return ""
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #

@dataclass
class ExcelParseReport:
    """What happened during a parse. parse_excel() hides this; parse_excel_with_report() returns it."""

    file_path: str
    engine: Optional[str] = None
    sheets_parsed: List[str] = field(default_factory=list)
    sheets_skipped: List[Tuple[str, str]] = field(default_factory=list)
    rows_read: int = 0
    rows_skipped_empty: int = 0
    rows_skipped_invalid: int = 0
    timestamp_fallbacks: int = 0
    events_created: int = 0
    errors: List[str] = field(default_factory=list)

    def add_error(self, message: str) -> None:
        if len(self.errors) < MAX_REPORT_ERRORS:
            self.errors.append(message)

    def skip_sheet(self, name: str, reason: str) -> None:
        self.sheets_skipped.append((name, reason))


# --------------------------------------------------------------------------- #
# Cell-level helpers (all pure functions, safe to unit test)
# --------------------------------------------------------------------------- #

def _is_missing(value: Any) -> bool:
    if value is None:
        return True
    try:
        result = pd.isna(value)
    except (TypeError, ValueError):
        return False
    return bool(result) if isinstance(result, (bool, np.bool_)) else False


def _is_blank(value: Any) -> bool:
    if _is_missing(value):
        return True
    return isinstance(value, (str, bytes, bytearray)) and clean_cell(value) is None


def _decode_bytes(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp1252", errors="replace")


def clean_cell(value: Any, max_len: int = MAX_TEXT_LEN) -> Optional[str]:
    """Return a trimmed, printable string for any cell value, or None if the cell is empty."""
    if _is_missing(value):
        return None
    if isinstance(value, (bytes, bytearray)):
        text = _decode_bytes(bytes(value))
    elif isinstance(value, bool):
        text = str(value)
    elif isinstance(value, (datetime, date, pd.Timestamp, np.datetime64)):
        text = normalize_timestamp(value) or str(value)
    elif isinstance(value, (int, np.integer)):
        text = str(int(value))
    elif isinstance(value, (float, np.floating)):
        number = float(value)
        if not math.isfinite(number):
            return None
        text = str(int(number)) if number.is_integer() else repr(number)
    else:
        text = str(value)
    # Replace lone surrogates / unencodable characters, then drop control characters.
    text = text.encode("utf-8", errors="replace").decode("utf-8")
    text = _CONTROL_CHARS.sub("", text).strip()
    if text.lower() in _NULL_TOKENS:
        return None
    return text[:max_len]


def _jsonable(value: Any) -> Any:
    """Convert a cell to something JSON-serialisable for raw_data."""
    if _is_missing(value):
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, np.integer)):
        return int(value)
    if isinstance(value, (float, np.floating)):
        number = float(value)
        if not math.isfinite(number):
            return None
        return int(number) if number.is_integer() else number
    return clean_cell(value, MAX_RAW_LEN)


def _from_number(number: float) -> Optional[datetime]:
    """Interpret a bare number as an Excel serial date or a Unix epoch (s / ms)."""
    if not math.isfinite(number):
        return None
    try:
        if 20000 <= number <= 80000:                       # Excel serial day (1954 - 2119)
            return _EXCEL_EPOCH + timedelta(days=number)
        if 1e9 <= number < 1e11:                           # Unix seconds
            return _UNIX_EPOCH + timedelta(seconds=number)
        if 1e11 <= number < 1e14:                          # Unix milliseconds
            return _UNIX_EPOCH + timedelta(milliseconds=number)
    except (OverflowError, ValueError):
        return None
    return None


def _to_naive_utc(value: Any) -> Optional[datetime]:
    """Parse with pandas; offsets are converted to UTC, naive values are taken as UTC."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            stamp = pd.to_datetime(value, utc=True, errors="coerce")
            if pd.isna(stamp):
                return None
            return stamp.tz_localize(None).to_pydatetime()
    except (ValueError, TypeError, OverflowError):
        return None


def _datetime_to_naive_utc(value: datetime) -> datetime:
    if isinstance(value, pd.Timestamp):
        value = value.to_pydatetime(warn=False)
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def _parse_iso_fast(text: str) -> Optional[datetime]:
    """Cheap path for the common ISO-8601 case; None means 'let pandas try'."""
    candidate = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
    try:
        return _datetime_to_naive_utc(datetime.fromisoformat(candidate))
    except ValueError:
        return None


def parse_timestamp(value: Any) -> Optional[datetime]:
    """Any date-like cell -> naive UTC datetime, or None if it cannot be interpreted."""
    if _is_missing(value) or isinstance(value, bool):
        return None
    if isinstance(value, (int, np.integer, float, np.floating)):
        return _from_number(float(value))
    if isinstance(value, datetime):
        return _datetime_to_naive_utc(value)
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day)
    if isinstance(value, np.datetime64):
        return _to_naive_utc(value)
    text = clean_cell(value)
    if text is None:
        return None
    if _NUMERIC_TEXT.fullmatch(text):
        converted = _from_number(float(text))
        if converted is not None:
            return converted
    return _parse_iso_fast(text) or _to_naive_utc(text)


def _format_utc(value: datetime) -> str:
    return value.isoformat(timespec="microseconds" if value.microsecond else "seconds") + "Z"


def normalize_timestamp(value: Any) -> Optional[str]:
    """Any date-like cell -> UTC ISO-8601 string ending in 'Z', or None."""
    parsed = parse_timestamp(value)
    return None if parsed is None else _format_utc(parsed)


def parse_ip_and_port(value: Any) -> Tuple[Optional[str], Optional[int]]:
    """
    Cell -> (valid IP string or None, port embedded in the cell or None).
    Handles 'a.b.c.d:port', leading-zero octets, and IPv4 stored as a 32-bit integer.
    """
    if _is_missing(value) or isinstance(value, bool):
        return None, None
    if isinstance(value, (int, np.integer, float, np.floating)):
        number = float(value)
        if math.isfinite(number) and number.is_integer() and 2 ** 24 <= number < 2 ** 32:
            return str(ipaddress.IPv4Address(int(number))), None
        return None, None

    text = clean_cell(value)
    if text is None:
        return None, None
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]

    port: Optional[int] = None
    with_port = _IPV4_WITH_PORT.match(text)
    if with_port:
        text = with_port.group(1)
        candidate = int(with_port.group(2))
        port = candidate if candidate <= 65535 else None

    loose = _IPV4_LOOSE.match(text)
    if loose:
        text = ".".join(str(int(group)) for group in loose.groups())

    try:
        return str(ipaddress.ip_address(text)), port
    except ValueError:
        return None, None


def parse_port(value: Any) -> Optional[int]:
    """Cell -> port 0-65535 or None. Accepts 443, 443.0, '443', '443/tcp'."""
    if _is_missing(value) or isinstance(value, bool):
        return None
    if isinstance(value, (int, np.integer, float, np.floating)):
        number = float(value)
        if not math.isfinite(number) or not number.is_integer():
            return None
        port = int(number)
    else:
        text = clean_cell(value)
        if text is None:
            return None
        match = _PORT_TEXT.match(text)
        if not match:
            return None
        port = int(match.group(1))
    return port if 0 <= port <= 65535 else None


def _normalize_protocol(text: Optional[str]) -> Optional[str]:
    if text is None:
        return None
    lowered = text.lower()
    return _PROTOCOL_NUMBERS.get(lowered, lowered[:32])


def infer_event_type(
    action: Optional[str], user: Optional[str], src_ip: Optional[str], dst_ip: Optional[str]
) -> EventType:
    """Best-effort event type from the action text and which fields are present."""
    text = action or ""
    if _AUTH_RE.search(text):
        return EventType.AUTHENTICATION
    if _ALERT_RE.search(text):
        return EventType.ALERT
    if _DNS_RE.search(text):
        return EventType.DNS_QUERY
    if _HTTP_RE.search(text):
        return EventType.HTTP_REQUEST
    if src_ip or dst_ip:
        return EventType.NETWORK_CONNECTION
    if user:
        return EventType.AUTHENTICATION
    return EventType.ALERT


def infer_status(action: Optional[str]) -> str:
    """'failure' for deny/drop/fail-style actions, 'success' for allow/accept-style, else 'unknown'."""
    text = action or ""
    if _FAILURE_RE.search(text):
        return "failure"
    if _SUCCESS_RE.search(text):
        return "success"
    return "unknown"


_WINDOWS_HEADER_HINTS = {"eventid", "eventcode", "targetusername", "subjectusername", "computername", "logontype"}


def infer_source(header_row: Sequence[Any]) -> EventSource:
    """WINDOWS when the headers look like a Windows event export, otherwise FIREWALL."""
    normalized = {normalize_column_name(header) for header in header_row}
    return EventSource.WINDOWS if normalized & _WINDOWS_HEADER_HINTS else EventSource.FIREWALL

# --------------------------------------------------------------------------- #
# Column mapping and row conversion
# --------------------------------------------------------------------------- #

_NORMALIZED_ALIASES: Dict[str, List[str]] = {
    fld: [normalize_column_name(alias) for alias in aliases] for fld, aliases in FIELD_ALIASES.items()
}


def build_column_map(headers: Sequence[Any]) -> Dict[str, int]:
    """Map each known field to the position of its column, honouring alias priority."""
    normalized = [normalize_column_name(header) for header in headers]
    mapping: Dict[str, int] = {}
    for fld, aliases in _NORMALIZED_ALIASES.items():
        for alias in aliases:
            if alias in normalized:
                mapping[fld] = normalized.index(alias)
                break
    return mapping


def _unique_headers(header_row: Sequence[Any]) -> List[str]:
    names: List[str] = []
    seen: Dict[str, int] = {}
    for position, header in enumerate(header_row):
        base = clean_cell(header) or f"column_{position + 1}"
        count = seen.get(base, 0)
        seen[base] = count + 1
        names.append(base if count == 0 else f"{base}_{count + 1}")
    return names


def _get(cells: Sequence[Any], column_map: Dict[str, int], fld: str) -> Any:
    index = column_map.get(fld)
    if index is None or index >= len(cells):
        return None
    return cells[index]


def row_to_event(
    cells: Sequence[Any],
    column_map: Dict[str, int],
    headers: Sequence[str],
    *,
    timestamp: datetime,
    source: EventSource = EventSource.FIREWALL,
    sheet_name: str = "",
    excel_row: int = 0,
    timestamp_fallback: bool = False,
) -> Optional[NormalizedEvent]:
    """
    Convert one spreadsheet row. Returns None when the row carries nothing usable
    (no IPs, user, host or action text). May raise ValueError if the event model
    rejects the values; parse_sheet() catches that and counts the row as invalid.
    """
    src_ip, embedded_src_port = parse_ip_and_port(_get(cells, column_map, "src_ip"))
    dst_ip, embedded_dst_port = parse_ip_and_port(_get(cells, column_map, "dst_ip"))
    src_port = parse_port(_get(cells, column_map, "src_port"))
    dst_port = parse_port(_get(cells, column_map, "dst_port"))
    if src_port is None:
        src_port = embedded_src_port
    if dst_port is None:
        dst_port = embedded_dst_port

    protocol = _normalize_protocol(clean_cell(_get(cells, column_map, "protocol")))
    action = clean_cell(_get(cells, column_map, "action"))
    user = clean_cell(_get(cells, column_map, "user"))
    host = clean_cell(_get(cells, column_map, "host"))
    event_code = clean_cell(_get(cells, column_map, "event_id"), MAX_EVENT_ID_LEN)

    if not any((src_ip, dst_ip, action, user, host, event_code)):
        return None

    classify_text = " ".join(part for part in (action, event_code) if part)
    event_type = infer_event_type(classify_text, user, src_ip, dst_ip)
    status = infer_status(classify_text)
    # A denied / dropped connection attempt is the spreadsheet equivalent of Zeek's "S0"
    # (attempt, no reply). The port-scan rules only look at conn_state == "S0".
    conn_state = "S0" if event_type == EventType.NETWORK_CONNECTION and status == "failure" else None

    raw_data: Dict[str, Any] = {}
    for position, cell in enumerate(cells):
        if position >= len(headers):
            break
        converted = _jsonable(cell)
        if converted is not None:
            raw_data[headers[position]] = converted
    raw_data["_sheet"] = sheet_name
    raw_data["_row"] = excel_row
    raw_data["_timestamp_utc"] = _format_utc(timestamp)
    if timestamp_fallback:
        raw_data["_timestamp_fallback"] = True

    return NormalizedEvent(
        timestamp=timestamp,
        source=source,
        event_type=event_type,
        host=host,
        user=user,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        event_id=event_code or (action[:MAX_EVENT_ID_LEN] if action else None),
        status=status,
        conn_state=conn_state,
        severity=Severity.INFO,
        raw_data=raw_data,
    )


# --------------------------------------------------------------------------- #
# Sheet / workbook level
# --------------------------------------------------------------------------- #

def _find_header(frame: pd.DataFrame) -> Optional[Tuple[int, Dict[str, int], List[Any]]]:
    """Scan the top of a sheet for the row that best matches the known column names."""
    best: Optional[Tuple[int, Dict[str, int], List[Any]]] = None
    for index in range(min(len(frame), MAX_HEADER_SCAN_ROWS)):
        row = frame.iloc[index].tolist()
        column_map = build_column_map(row)
        if "timestamp" not in column_map or len(column_map) < MIN_RECOGNIZED_COLUMNS:
            continue
        if best is None or len(column_map) > len(best[1]):
            best = (index, column_map, row)
    return best


def _parse_sheet(
    name: str, frame: pd.DataFrame, source: Optional[EventSource], report: ExcelParseReport
) -> List[NormalizedEvent]:
    if frame is None or frame.empty:
        report.skip_sheet(name, "sheet is empty")
        return []

    found = _find_header(frame)
    if found is None:
        report.skip_sheet(name, "no header row with a timestamp column and at least one other known column")
        return []
    header_index, column_map, header_row = found
    headers = _unique_headers(header_row)
    timestamp_index = column_map["timestamp"]
    sheet_source = source or infer_source(header_row)

    staged: List[Tuple[int, Sequence[Any], Optional[datetime]]] = []
    body = frame.iloc[header_index + 1:].itertuples(index=False, name=None)
    for offset, cells in enumerate(body):
        report.rows_read += 1
        excel_row = header_index + offset + 2          # 1-based sheet row number
        if all(_is_blank(cell) for cell in cells):
            report.rows_skipped_empty += 1
            continue
        staged.append((excel_row, cells, parse_timestamp(cells[timestamp_index])))

    valid = [stamp for _, _, stamp in staged if stamp is not None]
    if not valid:
        report.skip_sheet(name, "no valid timestamps in the timestamp column")
        return []

    events: List[NormalizedEvent] = []
    last_valid = valid[0]          # leading bad rows borrow the first good timestamp
    for excel_row, cells, stamp in staged:
        used_fallback = stamp is None
        if used_fallback:
            stamp = last_valid
        else:
            last_valid = stamp
        try:
            event = row_to_event(
                cells,
                column_map,
                headers,
                timestamp=stamp,
                source=sheet_source,
                sheet_name=name,
                excel_row=excel_row,
                timestamp_fallback=used_fallback,
            )
        except (ValueError, TypeError) as exc:
            report.rows_skipped_invalid += 1
            report.add_error(f"{name} row {excel_row}: {' '.join(str(exc).split())[:200]}")
            continue
        if event is None:
            report.rows_skipped_empty += 1
            continue
        if used_fallback:
            report.timestamp_fallbacks += 1
        events.append(event)
    return events


def detect_excel_engine(path: Path) -> Optional[str]:
    """Pick 'openpyxl' or 'xlrd' from the file's magic bytes, falling back to the extension."""
    try:
        with open(path, "rb") as handle:
            head = handle.read(8)
    except OSError:
        head = b""
    if head.startswith(_ZIP_MAGIC):
        return "openpyxl"
    if head.startswith(_OLE_MAGIC):
        return "xlrd"
    suffix = Path(path).suffix.lower()
    if suffix in (".xlsx", ".xlsm"):
        return "openpyxl"
    if suffix == ".xls":
        return "xlrd"
    return None


def _read_workbook(path: Path, engine: str, report: ExcelParseReport) -> Dict[str, pd.DataFrame]:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return pd.read_excel(path, sheet_name=None, header=None, dtype=object, engine=engine)
    except ImportError as exc:
        report.add_error(
            f"Missing dependency for the '{engine}' engine: {' '.join(str(exc).split())[:150]} "
            f"(install with: pip install openpyxl xlrd)"
        )
    except Exception as exc:  # corrupt, encrypted or unsupported workbook
        report.add_error(f"Could not read workbook ({type(exc).__name__}): {' '.join(str(exc).split())[:200]}")
    return {}


def parse_excel_with_report(
    file_path: str, source: Optional[EventSource] = None
) -> Tuple[List[NormalizedEvent], ExcelParseReport]:
    """Parse every usable sheet of an .xlsx/.xls file. Never raises on bad input."""
    report = ExcelParseReport(file_path=str(file_path))
    path = Path(file_path)

    if not path.is_file():
        report.add_error(f"File not found: {file_path}")
        logger.error("Excel parse failed: %s", report.errors[-1])
        return [], report

    engine = detect_excel_engine(path)
    if engine is None:
        report.add_error("Not a recognised Excel workbook (expected .xlsx, .xlsm or .xls)")
        logger.error("Excel parse failed for %s: %s", file_path, report.errors[-1])
        return [], report
    report.engine = engine

    events: List[NormalizedEvent] = []
    for sheet_name, frame in _read_workbook(path, engine, report).items():
        name = str(sheet_name)
        try:
            sheet_events = _parse_sheet(name, frame, source, report)
        except Exception as exc:  # defensive: one broken sheet must not lose the others
            logger.exception("Unexpected error parsing sheet %r of %s", name, file_path)
            report.skip_sheet(name, f"unexpected error: {type(exc).__name__}")
            continue
        if sheet_events:
            report.sheets_parsed.append(name)
            events.extend(sheet_events)

    events.sort(key=lambda event: event.timestamp)
    report.events_created = len(events)
    logger.info(
        "Excel parse of %s: %d events from %d sheet(s); %d empty rows, %d invalid rows, %d timestamp fallbacks",
        file_path, len(events), len(report.sheets_parsed),
        report.rows_skipped_empty, report.rows_skipped_invalid, report.timestamp_fallbacks,
    )
    for sheet_name, reason in report.sheets_skipped:
        logger.warning("Skipped sheet %r: %s", sheet_name, reason)
    for message in report.errors:
        logger.warning("Excel parse issue: %s", message)
    return events, report


def parse_excel(file_path: str, source: Optional[EventSource] = None) -> List[NormalizedEvent]:
    """
    Parse an .xlsx/.xls export into NormalizedEvents, sorted by time. Returns [] on unreadable input.
    source=None picks WINDOWS per sheet when the headers look like a Windows export, else FIREWALL.
    """
    events, _ = parse_excel_with_report(file_path, source)
    return events