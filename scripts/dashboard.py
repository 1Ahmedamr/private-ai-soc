# scripts/dashboard.py

import sys
import time
from src.incidents.store import IncidentStore
from src.dashboard.cli_view import render_incident_table, render_incident_detail, clear_screen

DB_PATH = "data/processed/soc_incidents.db"
DEFAULT_REFRESH_SECONDS = 5


def show_once(store: IncidentStore) -> None:
    incidents = store.get_all()
    print(render_incident_table(incidents))
    print(f"\nTotal incidents in store: {len(incidents)}")


def watch(store: IncidentStore, refresh_seconds: int) -> None:
    """
    Polling loop - re-reads the store on a fixed interval and redraws.
    Why re-open nothing and just re-query? SQLite/Postgres connections
    stay open; we're not reconnecting each cycle, only re-running the
    SELECT. This means new rows written by a SEPARATE ingestion process
    (Day 6's whole proof) become visible here without restarting anything.
    """
    try:
        while True:
            clear_screen()
            print(f"[LIVE - refreshing every {refresh_seconds}s - Ctrl+C to stop]\n")
            show_once(store)
            time.sleep(refresh_seconds)
    except KeyboardInterrupt:
        print("\nStopped watching.")


def main():
    store = IncidentStore(DB_PATH)
    args = sys.argv[1:]

    if not args:
        show_once(store)
        print("Tip: run `python -m scripts.dashboard <INCIDENT_ID>` for details,")
        print("     or `python -m scripts.dashboard --watch` for a live view.")
        return

    if args[0] == "--watch":
        refresh = int(args[1]) if len(args) > 1 else DEFAULT_REFRESH_SECONDS
        watch(store, refresh)
        return

    incident_id = args[0]
    incident = store.get_by_id(incident_id)
    if not incident:
        print(f"No incident found with id {incident_id}")
        return
    print(render_incident_detail(incident))


if __name__ == "__main__":
    main()