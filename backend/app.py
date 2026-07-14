from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.v1.api import api_router, n8n_router

app = FastAPI(
    title="SecScan API (Modular V3)",
    description="Backend reestructurado con Clean Architecture",
    version="3.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def raiz():
    return {"mensaje": "SecScan Modular API está ONLINE."}

app.include_router(api_router, prefix="/api")

app.include_router(n8n_router, prefix="/internal")

@app.on_event("startup")
def startup_event():
    from core.local_db import LocalDBManager
    LocalDBManager()
    
    from services.sync_service import start_sync_daemon
    start_sync_daemon()
    
    from services.scan_service import start_passive_daemon
    start_passive_daemon()

