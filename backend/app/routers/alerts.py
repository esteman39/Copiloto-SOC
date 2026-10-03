# routers/alerts.py
from functools import lru_cache
from fastapi import APIRouter, Depends
from app.models.alert import Alert
from app.services.azure_client import AzureAlertClient, get_azure_client

router = APIRouter()

@lru_cache
def azure_client() -> AzureAlertClient:
    return get_azure_client()

@router.get("/health")
def health_check():
    return {"status": "ok"}


@router.post("/alerts")
def receive_alert(alert: Alert, client: AzureAlertClient = Depends(azure_client)):
    # El ground truth nunca sale hacia Sentinel
    data = alert.model_dump(mode="json", exclude={"incident_id", "causal_link_to"})
    data["TimeGenerated"] = alert.timestamp.isoformat()
    return client.send_alert(data)
