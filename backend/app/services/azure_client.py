import os
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class AzureAlertClient(ABC):
    """Interfaz común: el resto del código depende de esto, no de la implementación."""

    @abstractmethod
    def send_alert(self, alert: dict) -> dict:
        ...


class MockAzureAlertClient(AzureAlertClient):
    """Simula el envío a Azure. Útil mientras no hay credenciales o para pruebas rápidas."""

    def send_alert(self, alert: dict) -> dict:
        logger.info(f"[MOCK] Alerta que se enviaría a Azure: {alert}")
        return {
            "status": "mock_accepted",
            "sent_at": datetime.now(timezone.utc).isoformat(),
            "alert": alert,
        }


class RealAzureAlertClient(AzureAlertClient):
    """Implementación real, usa las credenciales del Service Principal."""

    def __init__(self):

        from azure.identity import ClientSecretCredential
        from azure.monitor.ingestion import LogsIngestionClient

        tenant_id = os.environ["AZURE_TENANT_ID"]
        client_id = os.environ["AZURE_CLIENT_ID"]
        client_secret = os.environ["AZURE_CLIENT_SECRET"]
        endpoint = os.environ["AZURE_DCE_ENDPOINT"]  # Data Collection Endpoint
        self.rule_id = os.environ["AZURE_DCR_IMMUTABLE_ID"]  # Data Collection Rule
        self.stream_name = os.environ["AZURE_STREAM_NAME"]

        credential = ClientSecretCredential(tenant_id, client_id, client_secret)
        self.client = LogsIngestionClient(endpoint=endpoint, credential=credential)

    def send_alert(self, alert: dict) -> dict:
        self.client.upload(
            rule_id=self.rule_id,
            stream_name=self.stream_name,
            logs=[alert],
        )
        return {"status": "sent_to_azure", "alert": alert}


def get_azure_client() -> AzureAlertClient:
    """Factory: decide cuál implementación usar según el .env."""
    mode = os.getenv("AZURE_MODE", "mock")
    if mode == "real":
        return RealAzureAlertClient()
    return MockAzureAlertClient()
