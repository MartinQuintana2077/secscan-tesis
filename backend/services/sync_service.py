import time
import threading
import json
import traceback
from core.local_db import LocalDBManager

_sync_daemon_started = False
_sync_daemon_lock = threading.Lock()

def start_sync_daemon():
    """Lanza el hilo de sincronización en segundo plano."""
    global _sync_daemon_started
    with _sync_daemon_lock:
        if _sync_daemon_started:
            return
        _sync_daemon_started = True
        
    thread = threading.Thread(target=_run_sync_worker, daemon=True, name="SyncDaemon")
    thread.start()
    print("[SyncDaemon] Hilo de sincronización offline iniciado correctamente.")

def _run_sync_worker():
    """Ciclo infinito en segundo plano para procesar la cola de sincronización."""
    # Esperar a que la app inicie
    time.sleep(5)
    
    local_db = LocalDBManager()
    
    while True:
        try:
            # Obtener el elemento más antiguo de la cola
            rows = local_db.execute_read(
                "SELECT id, action_type, user_id, payload_json FROM offline_queue ORDER BY id ASC LIMIT 1"
            )
            
            if not rows:
                # No hay tareas pendientes, dormir 15 segundos
                time.sleep(15)
                continue
                
            task = rows[0]
            task_id = task["id"]
            action_type = task["action_type"]
            user_id = task["user_id"]
            payload = json.loads(task["payload_json"])
            
            print(f"[SyncDaemon] Procesando tarea offline {task_id} de tipo '{action_type}' para usuario '{user_id}'...")
            
            # Importar db_service aquí para evitar importaciones circulares
            from services.db_service import DatabaseService
            db_service = DatabaseService()
            
            # Intentar ejecutar la acción en Firebase
            success = _execute_firebase_action(db_service, action_type, user_id, payload)
            
            if success:
                # Éxito: eliminar de la cola local
                local_db.execute_write("DELETE FROM offline_queue WHERE id = ?", (task_id,))
                print(f"[SyncDaemon] ✅ Tarea {task_id} sincronizada correctamente en Firebase.")
                # Un pequeño sleep para no saturar si hay muchas tareas
                time.sleep(0.5)
            else:
                # Error de red/conexión: detener el vaciado de cola y volver a intentar en 15 segundos
                print(f"[SyncDaemon] ⏰ Conexión a Firebase offline. Reintentando en 15s...")
                time.sleep(15)
                
        except Exception as e:
            print(f"[SyncDaemon ERROR] Excepción general en el worker: {e}")
            traceback.print_exc()
            time.sleep(15)

def _execute_firebase_action(db_service, action, user_id, payload) -> bool:
    """Intenta ejecutar una acción contra Firebase. Retorna True si se completó (o si falló por error de lógica irrecuperable que debe descartarse), y False si falló por corte de conexión."""
    try:
        if action == "save_device":
            db_service._save_device_to_firebase(payload["ip"], payload["document"], user_id)
        elif action == "save_vulnerability":
            db_service._save_vulnerability_to_firebase(payload["cve_id"], payload["data"], user_id)
        elif action == "save_scan_device":
            db_service._save_scan_device_to_firebase(user_id, payload["scan_id"], payload["ip"], payload["data"])
        elif action == "update_scan_metadata":
            db_service._update_scan_metadata_to_firebase(user_id, payload["scan_id"], payload["metadata"])
        elif action == "increment_vulnerabilities":
            db_service._increment_vulnerabilities_to_firebase(user_id, payload["scan_id"], payload["amount"])
        elif action == "increment_devices":
            db_service._increment_devices_to_firebase(user_id, payload["scan_id"], payload["amount"])
        elif action == "append_scan_log":
            db_service._append_scan_log_to_firebase(user_id, payload["scan_id"], payload["message"])
        elif action == "clear_devices":
            db_service._clear_devices_to_firebase(user_id)
        elif action == "clear_vulnerabilities":
            db_service._clear_vulnerabilities_to_firebase(user_id)
        else:
            print(f"[SyncDaemon] Acción desconocida ignorada: {action}")
            return True
            
        return True
    except Exception as e:
        err_msg = str(e).lower()
        # Lista de palabras clave que típicamente representan cortes de red o problemas de conexión
        is_connection_error = any(kw in err_msg for kw in [
            "connection", "offline", "network", "timeout", "dns", "unreachable", "timed out", 
            "host", "socket", "grpc", "transport", "failed to connect", "server_endpoint"
        ])
        
        if is_connection_error:
            print(f"[SyncDaemon] Error de conexión detectado: {e}")
            return False
        else:
            # Si es un error lógico (permisos, sintaxis, etc.), no tiene sentido
            # bloquear la cola para siempre. Lo reportamos y devolvemos True para descartar.
            print(f"[SyncDaemon ERROR CRÍTICO] Error de datos irrecuperable en Firebase: {e}. Descartando tarea de la cola.")
            return True
