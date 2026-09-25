from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from app.routers import alerts

app = FastAPI(title="Copiloto Inteligente SOC")

app.include_router(alerts.router, prefix="/api")

app.mount("/", StaticFiles(directory="app/static", html=True), name="frontend")
