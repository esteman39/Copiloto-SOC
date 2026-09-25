from fastapi import APIRouter

router = APIRouter()

@router.get("/health")
def health_check():
    return {"status": "ok"}

@router.post("/alerts")
def receive_alert(payload: dict):
    # Aquí llega la alerta simulada o la notificación de Sentinel.
    # Por ahora solo la devolvemos para confirmar que el endpoint funciona.
    return {"received": True, "payload": payload}
