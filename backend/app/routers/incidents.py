from pathlib import Path
from fastapi import APIRouter
from app.services.correlation import cargar_alertas, correlacionar

router = APIRouter()

DATASET_PATH = Path(__file__).resolve().parent.parent / "data" / "alertas_crudas.jsonl"
ORDEN_SEVERIDAD = {"high": 3, "medium": 2, "low": 1}


@router.get("/incidents")
def listar_incidentes():
    alertas = cargar_alertas(str(DATASET_PATH))
    incidentes = correlacionar(alertas)
    resultado = []
    for n, inc in enumerate(incidentes, 1):
        alertas_out = [
            {
                "alert_id": a["alert_id"],
                "timestamp": a["timestamp"],
                "rule_name": a.get("rule_name"),
                "severity": a.get("severity", "low"),
                "source": a.get("source"),
                "mitre": a.get("mitre"),
                "message": a["message"],
            }
            for a in inc
        ]
        severidad_max = max(alertas_out, key=lambda a: ORDEN_SEVERIDAD.get(a["severity"], 0))["severity"]
        resultado.append({
            "incident_id": f"INC-{n:03d}",
            "num_alertas": len(inc),
            "severidad_max": severidad_max,
            "alertas": alertas_out,
        })
    return {"total_incidentes": len(resultado), "incidentes": resultado}
