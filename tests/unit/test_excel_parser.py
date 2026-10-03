# tests/unit/test_excel_parser.py

from datetime import datetime

from openpyxl import Workbook

from src.ingestion.excel_parser import (
    build_column_map,
    clean_cell,
    detect_excel_engine,
    normalize_timestamp,
    parse_excel,
    parse_excel_with_report,
    parse_ip_and_port,
    parse_port,
)


def _make_workbook(path, sheets):
    workbook = Workbook()
    workbook.remove(workbook.active)
    for title, rows in sheets.items():
        sheet = workbook.create_sheet(title)
        for row in rows:
            sheet.append(row)
    workbook.save(path)


def test_column_aliases_ignore_case_spaces_and_punctuation():
    headers = ["@timestamp", "Source IP", "DST-PORT", "Action", "TargetUserName", "Computer_Name"]
    mapping = build_column_map(headers)
    assert mapping == {"timestamp": 0, "src_ip": 1, "dst_port": 2, "action": 3, "user": 4, "host": 5}


def test_alias_priority_prefers_earlier_alias():
    mapping = build_column_map(["source", "src_ip"])
    assert mapping["src_ip"] == 1   # "src_ip" is listed before "source"


def test_normalize_timestamp_handles_offsets_naive_serial_and_epoch():
    assert normalize_timestamp("2026-10-02T10:15:01Z") == "2026-10-02T10:15:01Z"
    assert normalize_timestamp("2026-10-02 12:15:01+02:00") == "2026-10-02T10:15:01Z"
    assert normalize_timestamp("2026-10-02 10:15:01") == "2026-10-02T10:15:01Z"
    assert normalize_timestamp(datetime(2026, 10, 2, 10, 15, 1)) == "2026-10-02T10:15:01Z"

    serial = (datetime(2026, 10, 2, 12) - datetime(1899, 12, 30)).total_seconds() / 86400
    assert normalize_timestamp(serial) == "2026-10-02T12:00:00Z"

    epoch = int((datetime(2026, 10, 2, 10, 15, 1) - datetime(1970, 1, 1)).total_seconds())
    assert normalize_timestamp(epoch) == "2026-10-02T10:15:01Z"
    assert normalize_timestamp(str(epoch * 1000)) == "2026-10-02T10:15:01Z"


def test_normalize_timestamp_rejects_garbage():
    for bad in ("not a date", "", None, float("nan"), True):
        assert normalize_timestamp(bad) is None


def test_parse_ip_and_port():
    assert parse_ip_and_port("10.0.0.1:443") == ("10.0.0.1", 443)
    assert parse_ip_and_port(167772161) == ("10.0.0.1", None)
    assert parse_ip_and_port("010.000.000.001") == ("10.0.0.1", None)
    assert parse_ip_and_port("[::1]") == ("::1", None)
    assert parse_ip_and_port("999.1.1.1") == (None, None)
    assert parse_ip_and_port("firewall-01") == (None, None)
    assert parse_ip_and_port(float("nan")) == (None, None)
    assert parse_ip_and_port("") == (None, None)


def test_parse_port():
    assert parse_port(443.0) == 443
    assert parse_port("443") == 443
    assert parse_port("443/tcp") == 443
    assert parse_port(0) == 0
    assert parse_port(70000) is None
    assert parse_port("abc") is None
    assert parse_port(3.5) is None


def test_clean_cell_handles_nulls_bytes_and_numbers():
    assert clean_cell(float("nan")) is None
    assert clean_cell("  N/A ") is None
    assert clean_cell("-") is None
    assert clean_cell(443.0) == "443"
    assert clean_cell(b"caf\xe9") == "caf\u00e9"          # not valid UTF-8 -> cp1252
    assert clean_cell("a\x00b\x07c") == "abc"
    assert clean_cell("x" * 5000, max_len=10) == "x" * 10


def test_parse_excel_end_to_end(tmp_path):
    path = tmp_path / "export.xlsx"
    _make_workbook(path, {
        "Traffic": [
            ["Firewall export", None, None, None, None, None],            # title row above the header
            ["Time", "Source IP", "Destination", "DPort", "Action", "Host"],
            ["2026-10-02 10:15:01", "185.220.101.45", "10.0.0.5", 22, "deny", "FW01"],
            ["not-a-date", "185.220.101.45", "10.0.0.5", 3389, "deny", None],
            [None, None, None, None, None, None],
            ["2026-10-02 10:16:00", "not-an-ip", "10.0.0.6", "443", "allow", "FW01"],
        ],
    })

    events, report = parse_excel_with_report(str(path))

    assert len(events) == 3
    first, second, third = events
    assert first.source == "firewall"
    assert first.event_type == "network_connection"
    assert first.src_ip == "185.220.101.45" and first.dst_ip == "10.0.0.5"
    assert first.dst_port == 22 and first.status == "failure" and first.host == "FW01"
    assert first.conn_state == "S0"                               # denied attempt, as the port-scan rules expect
    assert first.timestamp == datetime(2026, 10, 2, 10, 15, 1)
    assert first.raw_data["_row"] == 3 and first.raw_data["_sheet"] == "Traffic"

    assert second.timestamp == first.timestamp                    # borrowed from the previous valid row
    assert second.raw_data["_timestamp_fallback"] is True
    assert second.host is None

    assert third.src_ip is None                                   # invalid IP dropped, kept in raw_data
    assert third.raw_data["Source IP"] == "not-an-ip"
    assert third.dst_port == 443 and third.status == "success"
    assert third.conn_state is None                                # not a denied attempt

    assert report.rows_skipped_empty == 1
    assert report.timestamp_fallbacks == 1
    assert report.events_created == 3
    assert report.sheets_parsed == ["Traffic"]


def test_auth_rows_and_multiple_sheets_are_merged_in_time_order(tmp_path):
    path = tmp_path / "multi.xlsx"
    _make_workbook(path, {
        "Logons": [
            ["EventTime", "TargetUserName", "message", "ClientIP"],
            [datetime(2026, 10, 2, 11, 0, 0), "administrator", "Failed logon attempt", "185.220.101.45"],
        ],
        "Notes": [["just", "some", "notes"]],                      # no header -> skipped, not an error
        "Traffic": [
            ["timestamp", "src", "dst", "proto"],
            [datetime(2026, 10, 2, 10, 0, 0), "10.0.0.9", "8.8.8.8", 17],
        ],
    })

    events, report = parse_excel_with_report(str(path))

    assert [e.timestamp.hour for e in events] == [10, 11]
    assert events[0].source == "firewall" and events[1].source == "windows"   # inferred per sheet
    assert events[0].protocol == "udp" and events[0].event_type == "network_connection"
    assert events[1].event_type == "authentication" and events[1].status == "failure"
    assert events[1].user == "administrator" and events[1].src_ip == "185.220.101.45"
    assert [name for name, _ in report.sheets_skipped] == ["Notes"]


def test_sheet_without_timestamp_column_is_skipped(tmp_path):
    path = tmp_path / "nots.xlsx"
    _make_workbook(path, {"Data": [["src_ip", "dst_ip"], ["10.0.0.1", "10.0.0.2"]]})
    events, report = parse_excel_with_report(str(path))
    assert events == []
    assert report.sheets_skipped and report.sheets_skipped[0][0] == "Data"


def test_sheet_with_no_valid_timestamps_is_skipped(tmp_path):
    path = tmp_path / "badts.xlsx"
    _make_workbook(path, {"Data": [["time", "src_ip"], ["garbage", "10.0.0.1"], ["", "10.0.0.2"]]})
    assert parse_excel(str(path)) == []


def test_bad_input_never_raises(tmp_path):
    assert parse_excel(str(tmp_path / "missing.xlsx")) == []

    fake = tmp_path / "fake.xlsx"
    fake.write_text("this is not a workbook")
    events, report = parse_excel_with_report(str(fake))
    assert events == [] and report.errors

    unknown = tmp_path / "data.csv"
    unknown.write_text("time,src_ip\n2026-10-02,10.0.0.1\n")
    events, report = parse_excel_with_report(str(unknown))
    assert events == [] and report.errors


def test_detect_excel_engine_uses_magic_bytes_before_extension(tmp_path):
    xlsx_like = tmp_path / "renamed.xls"
    xlsx_like.write_bytes(b"PK\x03\x04rest")
    xls_like = tmp_path / "renamed.xlsx"
    xls_like.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1rest")
    assert detect_excel_engine(xlsx_like) == "openpyxl"
    assert detect_excel_engine(xls_like) == "xlrd"

def test_event_id_column_is_used_and_marks_the_sheet_as_windows(tmp_path):
    path = tmp_path / "winlogons.xlsx"
    _make_workbook(path, {"Security": [
        ["Time", "Event ID", "User", "ClientIP"],
        [datetime(2026, 10, 2, 10, 15, 1), 4625, "administrator", "185.220.101.45"],
        [datetime(2026, 10, 2, 10, 16, 1), 4624, "administrator", "185.220.101.45"],
    ]})
    events = parse_excel(str(path))
    assert [e.event_id for e in events] == ["4625", "4624"]
    assert [e.status for e in events] == ["failure", "success"]
    assert all(e.event_type == "authentication" and e.source == "windows" for e in events)


def test_explicit_source_overrides_inference(tmp_path):
    from src.models.event_schema import EventSource
    path = tmp_path / "forced.xlsx"
    _make_workbook(path, {"Security": [
        ["Time", "Event ID", "User"],
        [datetime(2026, 10, 2, 10, 15, 1), 4625, "administrator"],
    ]})
    assert parse_excel(str(path), source=EventSource.LINUX)[0].source == "linux"

def test_denied_connections_to_many_ports_are_scan_shaped(tmp_path):
    path = tmp_path / "scan.xlsx"
    rows = [["Time", "Source IP", "Destination", "DPort", "Action"]]
    for i, port in enumerate([21, 22, 23, 25, 80, 443]):
        rows.append([datetime(2026, 10, 2, 10, 0, i), "185.220.101.45", "10.0.0.5", port, "DENY"])
    _make_workbook(path, {"fw": rows})
    events = parse_excel(str(path))
    assert len(events) == 6
    assert all(e.event_type == "network_connection" and e.conn_state == "S0" for e in events)
    assert len({e.dst_port for e in events}) == 6