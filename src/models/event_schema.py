# src/models/event_schema.py

from pydantic import BaseModel, Field, field_validator
from datetime import datetime
from typing import Optional, Literal
from enum import Enum
from ipaddress import ip_address


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
    conn_state: Optional[str] = None   # Zeek connection state (e.g. "S0", "SF", "REJ")

    # --- Metadata ---
    severity: Severity = Severity.INFO
    raw_data: dict = Field(default_factory=dict)  # نحتفظ بالأصل دايمًا للـaudit

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def validate_ip_format(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        try:
            ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")
        return v

    model_config = {"use_enum_values": True}

        # Sysmon-specific fields
    parent_process: Optional[str] = None      # ParentImage
    parent_command: Optional[str] = None      # ParentCommandLine  
    process_guid: Optional[str] = None        # ProcessGuid (unique per process instance)
    target_process: Optional[str] = None      # TargetImage (for process injection)
    file_hash: Optional[str] = None           # Hashes (MD5/SHA256)
    network_initiated: Optional[bool] = None  # Initiated field in Sysmon Event 3