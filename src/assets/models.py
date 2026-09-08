# src/assets/models.py

from pydantic import BaseModel
from enum import Enum
from typing import Optional


class AssetCriticality(str, Enum):
    """
    Why a 3-tier enum instead of just a boolean is_critical?
    Because real environments aren't binary. A Domain Controller and a
    file server holding customer PII are both "critical," but a DC
    compromise is catastrophic (full domain takeover) while a file
    server breach is serious but contained. STANDARD covers everything
    else - most workstations, print servers, etc.
    """
    CRITICAL = "critical"    # Domain Controllers, core DBs, PKI/CA servers
    IMPORTANT = "important"  # File servers, app servers, exec workstations
    STANDARD = "standard"    # Regular employee workstations, default assumption


class Asset(BaseModel):
    identifier: str            # hostname OR ip - whichever we have
    identifier_type: str       # "host" or "ip"
    criticality: AssetCriticality
    description: Optional[str] = None