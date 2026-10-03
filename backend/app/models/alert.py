from datetime import datetime
from pydantic import BaseModel, Field


class Alert(BaseModel):
    alert_id: str
    incident_id: str | None = None        # ground truth; el copiloto no lo conoce
    tactic: str                           # p. ej. "Credential Access"
    technique_id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    timestamp: datetime
    source_ip: str | None = None
    hostname: str | None = None
    user: str | None = None
    event_type: str
    causal_link_to: str | None = None


class Incident(BaseModel):
    incident_id: str
    alerts: list[Alert]
    summary: str | None = None
    suggested_actions: list[str] = []
