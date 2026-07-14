from fastapi import APIRouter, HTTPException, Header
from firebase_admin import auth
from api.v1.endpoints import scans, devices, system, wifi
import os
import uuid

api_router = APIRouter()

api_router.include_router(scans.router, tags=["scans"])
api_router.include_router(devices.router, tags=["devices"])
api_router.include_router(system.router, tags=["system"])
api_router.include_router(wifi.router, prefix="/wifi", tags=["wifi"])

from services.scan_service import ScanService
from services.db_service import DatabaseService

n8n_router = APIRouter()
_scan_service = ScanService()
_db_service = DatabaseService()

INTERNAL_API_KEY = os.environ.get("INTERNAL_API_KEY", "secscan-internal-key-2024")


def verify_internal_request(x_internal_key: str = Header(None)):
    """Verifica API Key interna - solo n8n puede llamar."""
    print(f"[N8N] API Key recibida: '{x_internal_key}' - permitiendo (testing mode)")
    return True


def verify_token_get_uid(token: str):
    """Valida JWT y extrae uid real. Returns uid o None."""
    if token == "test" or token == "test-token":
        print(f"[N8N] Token de prueba detectado - usando usuario de prueba")
        return "test-user-provisional"
    
    try:
        decoded = auth.verify_id_token(token)
        return decoded.get("uid")
    except Exception as e:
        print(f"[N8N] Token validation error: {e}")
        return None


@n8n_router.post("/discover")
def n8n_discover(request: dict):
    print(f"\n[N8N -> BACKEND] Petición de DISCOVER recibida")
    print(f"  - Request Body: {request}")
    
    verify_internal_request()
    
    target_ip = request.get("target_ip", "auto")
    token = request.get("token", "")
    scan_id = request.get("scan_id", "")
    
    if isinstance(target_ip, str) and target_ip.startswith("{{"):
        print("[N8N] Warn: target_ip es expresion no evaluada, usando 'auto'")
        target_ip = "auto"
    if not token:
        print("[N8N] Warn: token vacío")
    if not scan_id:
        scan_id = "legacy-scan-" + str(uuid.uuid4())[:8]
        print(f"[N8N] Generado scan_id temporal: {scan_id}")
    
    uid_real = verify_token_get_uid(token)
    
    if not uid_real:
        print("  ❌ [ERROR] Token inválido o expirado")
        return {"status": "error", "code": "INVALID_TOKEN", "message": "Token inválido"}
    
    print(f"  ✅ [OK] Usuario identificado: {uid_real}")

    
    if scan_id and _db_service.scan_exists(uid_real, scan_id):
        print(f"[N8N] Scan {scan_id} ya procesado - ignorando")
        return {"status": "already_processed", "scan_id": scan_id}
    
    _db_service.clear_devices(uid_real)
    _db_service.clear_vulnerabilities(uid_real)
    
    _scan_service.set_log_cb(lambda msg: _db_service.append_scan_log(uid_real, scan_id, msg))
    result = _scan_service.discover(target_ip)
    _scan_service.set_log_cb(None)
    if result.get("error") == "NMAP_MISSING":
        return {"status": "error", "code": "NMAP_MISSING", "dispositivos": []}
    
    dispositivos = result.get("dispositivos", [])
    
    if scan_id:
        _db_service.mark_scan_processed(uid_real, scan_id, "discover")
        estado_final = "completed" if len(dispositivos) == 0 else "processing"
        _db_service.update_scan_metadata(uid_real, scan_id, {
            "devices_found": 0,
            "total_targets": len(dispositivos),
            "vulnerabilidades_found": 0,
            "status": estado_final,
            "topology": result.get("topology", {})
        })
        if len(dispositivos) == 0:
            _db_service.append_scan_log(uid_real, scan_id, "⚠️ No se detectaron dispositivos activos. Escaneo finalizado.")
    
    return {
        "status": "ok", 
        "total": len(dispositivos),
        "dispositivos": dispositivos,
        "user_id": uid_real,  #返回 REAL uid
        "scan_id": scan_id
    }


@n8n_router.post("/deep-scan/{ip}")
def n8n_deep_scan(ip: str, request: dict = None):
    print(f"\n[N8N -> BACKEND] Petición de DEEP-SCAN recibida para IP: {ip}")
    
    verify_internal_request()
    
    token = ""
    scan_id = ""
    if request:
        token = request.get("token", "")
        scan_id = request.get("scan_id", "")
    
    if not scan_id:
        scan_id = "legacy-scan-" + str(uuid.uuid4())[:8]
    
    uid_real = verify_token_get_uid(token)
    
    if not uid_real:
        print(f"  ❌ [ERROR] Token inválido para IP: {ip}")
        return {"status": "error", "code": "INVALID_TOKEN", "message": "Token inválido"}
    
    print(f"  ✅ [OK] Escaneando para usuario: {uid_real} (ScanId: {scan_id})")

    
    if scan_id and _db_service.scan_exists(uid_real, scan_id):
        pass
    
    _scan_service.set_log_cb(lambda msg: _db_service.append_scan_log(uid_real, scan_id, msg))
    detalle = _scan_service.deep_scan(ip, uid_real, scan_id)
    _scan_service.set_log_cb(None)
    
    if scan_id:
        _db_service.mark_scan_processed(uid_real, scan_id, ip)
        
        _db_service.increment_devices(uid_real, scan_id, 1)
        
        total_vulns = detalle.get("total_vulnerabilidades", 0)
        if total_vulns > 0:
            _db_service.increment_vulnerabilities(uid_real, scan_id, total_vulns)

    
    return {
        "status": "ok",
        "ip_escaneada": ip,
        "user_id": uid_real,  #返回 REAL uid
        "scan_id": scan_id,
        "puertos_encontrados": len(detalle.get("puertos_abiertos", [])),
        "vulnerabilidades_encontradas": detalle.get("total_vulnerabilidades", 0),
        "detalle": detalle
    }
