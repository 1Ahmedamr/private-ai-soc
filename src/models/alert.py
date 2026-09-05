from pydantic import BaseModel
from typing import Optional

class Alert(BaseModel):
    rule_name: str
    severity: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    domain: Optional[str] = None
    description: str
    confidence: int