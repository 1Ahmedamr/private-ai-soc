from collections import Counter

from src.models.alert import Alert


def detect_bruteforce(events):

    failed_ips = []

    for event in events:

        if event.event_id == 4625:
            failed_ips.append(event.src_ip)

    counts = Counter(failed_ips)

    alerts = []

    for ip, count in counts.items():

        if count >= 5:

            alerts.append(
                Alert(
                    alert_name="Possible Brute Force",
                    severity="high",
                    description=f"{count} failed logins detected",
                    src_ip=ip,
                )
            )

    return alerts