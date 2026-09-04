from pydantic import BaseModel


class Alert(BaseModel):
    alert_name: str
    severity: str
    description: str

    src_ip: str