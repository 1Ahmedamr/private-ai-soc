# scripts/run_watch_ingest.py
from src.storage.event_store import EventStore
from src.incidents.store import IncidentStore
from src.assets.inventory import AssetInventory
from src.pipeline.orchestrator import PipelineOrchestrator
from src.pipeline.watch_ingest import watch_and_ingest

EVENTS_DB = "data/processed/soc_events.db"
INCIDENTS_DB = "data/processed/soc_incidents.db"

asset_inventory = AssetInventory()
asset_inventory.load_from_csv("configs/assets.csv")

orchestrator = PipelineOrchestrator(EventStore(EVENTS_DB), IncidentStore(INCIDENTS_DB), asset_inventory)
watch_and_ingest(orchestrator)