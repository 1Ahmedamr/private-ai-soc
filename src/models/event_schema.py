# src/models/event_schema.py

from pydantic import BaseModel, Field, field_validator
from datetime import datetime
from typing import Optional, Literal
from enum import Enum


class EventSource(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    ZEEK = "zeek"
    SURICATA = "suricata"
    FIREWALL = "firewall"


class EventType(str, Enum):
    AUTHENTICATION = "authentication"
    PROCESS_EXECUTION = "process_execution"
    NETWORK_CONNECTION = "network_connection"
    DNS_QUERY = "dns_query"
    HTTP_REQUEST = "http_request"
    FILE_ACCESS = "file_access"
    ALERT = "alert"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class NormalizedEvent(BaseModel):
    """
    Common Security Event Schema.
    كل event من أي مصدر (Windows, Linux, Zeek, Suricata) لازم يتحول للشكل ده
    قبل ما يدخل أي مرحلة تانية في الـpipeline.
    """

    # --- Core identity fields ---
    timestamp: datetime
    source: EventSource
    event_type: EventType
    host: Optional[str] = None

    # --- Identity/Actor fields ---
    user: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None

    # --- Event-specific fields ---
    event_id: Optional[str] = None       # e.g. Windows Event ID "4625"
    process: Optional[str] = None
    command: Optional[str] = None
    status: Optional[Literal["success", "failure", "unknown"]] = "unknown"

    # --- Metadata ---
    severity: Severity = Severity.INFO
    raw_data: dict = Field(default_factory=dict)  # نحتفظ بالأصل دايمًا للـaudit

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def validate_ip_format(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        parts = v.split(".")
        if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            raise ValueError(f"Invalid IPv4 address format: {v}")
        return v

    model_config = {"use_enum_values": True}