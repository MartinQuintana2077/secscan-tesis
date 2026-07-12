from fastapi import APIRouter, HTTPException, Depends, Header, BackgroundTasks
from schemas.scan import ScanRequest, CVELookupRequest
from services.scan_service import ScanService
from services.db_service import DatabaseService
from api.deps import get_current_user
import requests
import uuid
import os

router = APIRouter()
scan_service = ScanService()
db_service = DatabaseService()

# API Key interna para proteger /internal/*
INTERNAL_API_KEY = os.environ.get("INTERNAL_API_KEY", "secscan-internal-key-2024")

def verify_internal_key(x_internal_key: str = Header(None)):
    """Verifica que la request viene de n8n (no de outside)."""
    if x_internal_key != INTERNAL_API_KEY:
        raise HTTPException(status_code=403, detail="Forbidden: Invalid internal key")
    return True


@router.post("/discover")
def discover_network(request: ScanRequest, user: dict = Depends(get_current_user)):
    user_id = user.get("uid", "")
    result = scan_service.discover(request.target_ip, passive=request.passive)
    if result.get("error") == "NMAP_MISSING":
        return {"status": "error", "code": "NMAP_MISSING", "dispositivos": []}
    
    return {
        "status": "ok", 
        "total": len(result["dispositivos"]),
        "dispositivos": result["dispositivos"],
        "user_id": user_id
    }



@router.post("/deep-scan/{ip}")
def deep_scan_device(ip: str, user: dict = Depends(get_current_user)):
    user_id = user.get("uid", "")
    try:
        detalle = scan_service.deep_scan(ip, user_id)
        return {
            "status": "ok",
            "ip_escaneada": ip,
            "user_id": user_id,
            "puertos_encontrados": len(detalle.get("puertos_abiertos", [])),
            "vulnerabilidades_encontradas": detalle.get("total_vulnerabilidades", 0),
            "detalle": detalle
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def _run_scan_bg(user_id: str, scan_id: str, target_ip: str, passive: bool):
    import concurrent.futures
    import datetime
    
    scan_service.set_log_cb(lambda msg: db_service.append_scan_log(user_id, scan_id, msg))
    
    print(f"[BFF-BG] Modo directo para usuario: {user_id} (Pasivo: {passive})")
    db_service.append_scan_log(user_id, scan_id, f"Iniciando auditoría de red (Pasivo: {passive}) en {target_ip}...")
    
    result = scan_service.discover(target_ip, passive=passive)
    
    if result.get("error") == "NMAP_MISSING":
        db_service.append_scan_log(user_id, scan_id, "Error crítico: Nmap no está instalado en el sistema.")
        db_service.update_scan_metadata(user_id, scan_id, {"status": "error", "error": "NMAP_MISSING"})
        return
        
    dispositivos = result.get("dispositivos", [])
    print(f"[BFF-BG] Dispositivos encontrados: {len(dispositivos)}")
    db_service.append_scan_log(user_id, scan_id, f"Fase de descubrimiento completada. {len(dispositivos)} dispositivos detectados en la red.")
    
    # Actualizar total de targets
    db_service.update_scan_metadata(user_id, scan_id, {"total_targets": len(dispositivos)})
    
    escaneados = 0
    total_vulnerabilidades = 0
    
    def scan_single_device(dispositivo):
        ip = dispositivo.get("ip", "")
        if not ip:
            return None
        try:
            db_service.mark_scan_processed(user_id, scan_id, ip)
            
            fabricante = dispositivo.get('fabricante', 'Desconocido') or 'Desconocido'
            db_service.append_scan_log(user_id, scan_id, f"[HOST] Analizando {ip} ({fabricante})...")
            
            if passive:
                detalle = {
                    "ip": ip,
                    "mac": dispositivo.get("mac", "Desconocida"),
                    "hostname": dispositivo.get("hostname", ""),
                    "fabricante": fabricante,
                    "puertos_abiertos": [],
                    "puertos_bloqueados": [],
                    "total_vulnerabilidades": 0,
                    "max_score": 0.0,
                    "fecha_auditoria": datetime.datetime.utcnow().isoformat(),
                    "estado": "Completado (Pasivo)",
                    "es_nuevo": False,
                    "primera_conexion": datetime.datetime.utcnow().isoformat(),
                    "scan_id": scan_id
                }
                db_service.save_device(ip, detalle, user_id)
                db_service.save_scan_device(user_id, scan_id, ip, detalle)
            else:
                detalle = scan_service.deep_scan(ip, user_id, scan_id)
                # Registrar resumen en consola de auditoría
                if detalle:
                    abiertos = detalle.get("puertos_abiertos", [])
                    bloqueados = detalle.get("puertos_bloqueados", [])
                    vulns = detalle.get("total_vulnerabilidades", 0)
                    
                    if abiertos:
                        db_service.append_scan_log(user_id, scan_id,
                            f"[OK] {ip} — {len(abiertos)} puerto(s) abierto(s): " +
                            ", ".join([f"TCP/{p['puerto']} ({p['servicio'].upper()})" for p in abiertos]))
                    else:
                        db_service.append_scan_log(user_id, scan_id,
                            f"[OK] {ip} — Sin servicios expuestos en los 100 puertos principales.")

                    if bloqueados:
                        db_service.append_scan_log(user_id, scan_id,
                            f"[BLOQUEADO] {ip} — {len(bloqueados)} puerto(s) restringido(s):")
                        for p in bloqueados:
                            db_service.append_scan_log(user_id, scan_id,
                                f"  TCP/{p['puerto']} ({p.get('servicio','N/A').upper()}) — {p['razon']}")

                    if vulns > 0:
                        db_service.append_scan_log(user_id, scan_id,
                            f"[ALERTA] {ip} — {vulns} vulnerabilidad(es) CVE detectada(s). Revisa el panel de detalles.")
                        db_service.increment_vulnerabilities(user_id, scan_id, vulns)

            print(f"[BFF-BG] GUARDADO: {ip} para user: {user_id} (Pasivo: {passive})")
            db_service.increment_devices(user_id, scan_id, 1)
            return detalle
        except Exception as e:
            print(f"[BFF-BG] Error escaneando {ip}: {e}")
            db_service.append_scan_log(user_id, scan_id, f"[ERROR] No se pudo analizar {ip}: {str(e)}")
            return None

    dispositivos_validos = [d for d in dispositivos if d.get("ip")]

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        resultados = list(executor.map(scan_single_device, dispositivos_validos))

    for r in resultados:
        if r is not None:
            escaneados += 1
            total_vulnerabilidades += r.get("total_vulnerabilidades", 0)
    
    db_service.update_scan_metadata(user_id, scan_id, {
        "end_time": datetime.datetime.utcnow().isoformat(),
        "status": "completed"
    })
    
    db_service.append_scan_log(user_id, scan_id, f"✅ Auditoría finalizada con éxito. {escaneados} equipos procesados.")
    print(f"[BFF-BG] Escaneo COMPLETADO. Total: {escaneados}")
    scan_service.set_log_cb(None)


@router.post("/trigger-scan")
def trigger_scan(request: ScanRequest, background_tasks: BackgroundTasks, authorization: str = Header(None), user: dict = Depends(get_current_user)):
    """
    Endpoint BFF (Backend-for-Frontend) - Versión Segura y Asíncrona.
    - Valida JWT
    - Genera scanId único (idempotencia)
    - Delega tarea a BackgroundTasks para emitir logs en vivo
    """
    import socket as _socket
    # ── Chequeo rápido de conexión a internet (1 segundo de timeout) ──
    try:
        _socket.create_connection(("8.8.8.8", 53), timeout=1.0)
    except OSError:
        raise HTTPException(
            status_code=503,
            detail="SIN_INTERNET"
        )
    
    user_id = user.get("uid", "")
    target_ip = request.target_ip if request.target_ip else "auto"
    scan_id = request.scan_id if request.scan_id else str(uuid.uuid4())
    raw_token = authorization.split(" ")[1] if authorization and "Bearer" in authorization else ""

    print(f"🚀 [BFF] Iniciando Escaneo Global Asíncrono")
    print(f"👤 Usuario: {user_id}")
    print(f"🆔 ScanId: {scan_id}")
    
    db_service.clear_devices(user_id)
    db_service.clear_vulnerabilities(user_id)
    
    if db_service.scan_exists(user_id, scan_id):
        return {"status": "already_processed", "scan_id": scan_id}
        
    payload = {
        "target_ip": target_ip,
        "token": raw_token,
        "scan_id": scan_id,
        "user_id": user_id 
    }
    
    n8n_disponible = False
    if not request.passive:
        url_prod = "http://localhost:5678/webhook/secscan"
        url_test = "http://localhost:5678/webhook-test/secscan"
        
        try:
            resp = requests.post(url_prod, json=payload, timeout=2)
            if resp.status_code == 200:
                n8n_disponible = True
        except: pass
                
        if not n8n_disponible:
            try:
                resp = requests.post(url_test, json=payload, timeout=2)
                if resp.status_code == 200:
                    n8n_disponible = True
            except: pass
    
    if n8n_disponible:
        return {
            "status": "ok", 
            "modo": "n8n", 
            "scan_id": scan_id,
            "user_id": user_id,
            "mensaje": "Workflow n8n iniciado"
        }
    
    # FALLBACK DIRECTO: Tarea asíncrona
    db_service.update_scan_metadata(user_id, scan_id, {
        "devices_found": 0,
        "vulnerabilidades_found": 0,
        "total_targets": 0,
        "status": "processing",
        "logs": []
    })
    
    background_tasks.add_task(_run_scan_bg, user_id, scan_id, target_ip, request.passive)
    
    return {
        "status": "ok", 
        "modo": "directo",
        "scan_id": scan_id,
        "user_id": user_id,
        "mensaje": "Escaneo en segundo plano iniciado"
    }


@router.get("/history")
def get_scan_history(user: dict = Depends(get_current_user)):
    user_id = user.get("uid", "")
    scans = db_service.get_user_scans(user_id)
    return {"status": "ok", "scans": scans}


@router.get("/history/{scan_id}")
def get_scan_details(scan_id: str, user: dict = Depends(get_current_user)):
    user_id = user.get("uid", "")
    details = db_service.get_scan_details(user_id, scan_id)
    if not details:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"status": "ok", "details": details}


@router.get("/history/{scan_id}/devices")
def get_scan_devices(scan_id: str, user: dict = Depends(get_current_user)):
    user_id = user.get("uid", "")
    devices = db_service.get_scan_devices(user_id, scan_id)
    return {"status": "ok", "devices": devices}


@router.post("/cve-lookup")
def cve_lookup(request: CVELookupRequest, user: dict = Depends(get_current_user)):
    resultados = scan_service.cve_client.buscar_vulnerabilidades(request.servicio, request.version)
    return {
        "status": "ok",
        "servicio": request.servicio,
        "version": request.version,
        "total_cves": len(resultados),
        "vulnerabilidades": resultados
    }