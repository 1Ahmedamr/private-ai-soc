from pydantic import BaseModel
from typing import Optional


class SecurityEvent(BaseModel):
    timestamp: str
    source: str

    event_id: int
    event_type: str

    username: Optional[str] = None
    src_ip: Optional[str] = None

    status: Optional[str] = None

    raw_data: dict