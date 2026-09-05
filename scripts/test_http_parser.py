from src.parsers.http_parser import parse_http_log

events = parse_http_log(
    "data/zeek_output/http.log"
)

print(events[:5])