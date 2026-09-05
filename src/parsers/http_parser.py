from pathlib import Path

def parse_http_log(file_path):
    events = []

    with open(file_path, "r") as f:
        for line in f:

            if line.startswith("#"):
                continue

            fields = line.strip().split("\t")

            if len(fields) < 11:
                continue

            event = {
                "src_ip": fields[2],
                "dst_ip": fields[4],
                "method": fields[7],
                "host": fields[8],
                "uri": fields[9]
            }

            events.append(event)

    return events