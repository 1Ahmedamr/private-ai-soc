# scripts/dashboard.py

import sys
from src.incidents.store import IncidentStore
from src.dashboard.cli_view import render_incident_table, render_incident_detail

DB_PATH = "data/processed/soc_incidents.db"


def main():
    store = IncidentStore(DB_PATH)
    incidents = store.get_all()

    if len(sys.argv) > 1:
        # Drill-down mode: python -m scripts.dashboard INC-XXXXXXXX
        incident_id = sys.argv[1]
        incident = store.get_by_id(incident_id)
        if not incident:
            print(f"No incident found with id {incident_id}")
            return
        print(render_incident_detail(incident))
    else:
        print(render_incident_table(incidents))
        print(f"\nTotal incidents in store: {len(incidents)}")
        print("Tip: run `python -m scripts.dashboard <INCIDENT_ID>` to see full details.")


if __name__ == "__main__":
    main()