import datetime
import json
import socket
import time
import threading
from core.firebase_client import FirebaseDB
from core.local_db import LocalDBManager

class NetworkChecker:
    _is_online = True
    _last_check = 0.0
    _lock = threading.Lock()

    @classmethod
    def is_online(cls) -> bool:
        now = time.time()
        if now - cls._last_check < 5.0:
            return cls._is_online
        
        with cls._lock:
            if now - cls._last_check < 5.0:
                return cls._is_online
            try:
                socket.create_connection(("8.8.8.8", 53), timeout=0.5)
                cls._is_online = True
            except OSError:
                cls._is_online = False
            cls._last_check = now
            return cls._is_online

class LocalDocumentSnapshot:
    """Clase helper para simular el comportamiento de DocumentSnapshot de Firebase en modo local."""
    def __init__(self, exists: bool, data: dict = None):
        self.exists = exists
        self._data = data
    
    def to_dict(self):
        return self._data

class DatabaseService:
    def __init__(self):
        try:
            self.db = FirebaseDB().get_db()
            self.firebase_active = True
        except Exception as e:
            print(f"[DB SERVICE] Advertencia: Firebase no inicializado, trabajando en modo local offline: {e}")
            self.db = None
            self.firebase_active = False
            
        self.local_db = LocalDBManager()

    def _get_user_ref(self, user_id: str):
        """Obtiene referencia a la colección del usuario en Firebase."""
        if not user_id:
            user_id = "anonymous"
        if not self.db:
            raise ConnectionError("Firestore no inicializado")
        return self.db.collection("users").document(user_id)

    # ==================== GESTIÓN DE COLA OFFLINE ====================
    
    def _enqueue_action(self, action_type: str, user_id: str, payload: dict):
        """Guarda una acción fallida de Firebase en la cola local de SQLite."""
        try:
            self.local_db.execute_write(
                "INSERT INTO offline_queue (action_type, user_id, payload_json, timestamp) VALUES (?, ?, ?, ?)",
                (action_type, user_id, json.dumps(payload), datetime.datetime.utcnow().isoformat())
            )
            print(f"[DB OFFLINE] Acción '{action_type}' encolada para sincronización asíncrona.")
        except Exception as e:
            print(f"[DB ERROR] Error crítico al encolar acción en SQLite: {e}")

    # ==================== MÉTODOS DE BASE DE DATOS (OFFLINE-FIRST) ====================
    
    def get_historial_doc(self, id_unico: str, user_id: str = ""):
        """Intenta leer historial de Firebase; si falla, lee de SQLite."""
        if not user_id:
            user_id = "anonymous"
            
        try:
            if not self.firebase_active:
                raise ConnectionError("Firebase inactivo")
            user_ref = self._get_user_ref(user_id)
            doc = user_ref.collection("historial").document(id_unico).get()
            
            # Sincronizar lectura exitosa con SQLite local
            if doc.exists:
                data = doc.to_dict()
                self.local_db.execute_write(
                    "INSERT OR REPLACE INTO devices (ip, user_id, mac, fabricante, primera_conexion, estado) VALUES (?, ?, ?, ?, ?, ?)",
                    (data.get("ip_inicial", id_unico), user_id, data.get("mac", id_unico), data.get("fabricante", "Desconocido"), data.get("primera_conexion"), "historial")
                )
            return doc
        except Exception as e:
            print(f"[DB READ FALLBACK] get_historial_doc para {id_unico} leyendo de SQLite por: {e}")
            # Consultar SQLite local
            rows = self.local_db.execute_read(
                "SELECT * FROM devices WHERE mac = ? AND user_id = ?", (id_unico, user_id)
            )
            if rows:
                row = rows[0]
                historial_data = {
                    "ip_inicial": row["ip"],
                    "mac": row["mac"],
                    "primera_conexion": row["primera_conexion"],
                    "fabricante": row["fabricante"]
                }
                return LocalDocumentSnapshot(exists=True, data=historial_data)
            return LocalDocumentSnapshot(exists=False)

    def save_historial_doc(self, id_unico: str, data: dict, user_id: str = ""):
        """Guarda en SQLite y encolará/escribirá en Firebase."""
        if not user_id:
            user_id = "anonymous"
            
        # 1. Guardar localmente
        self.local_db.execute_write(
            "INSERT OR REPLACE INTO devices (ip, user_id, mac, fabricante, primera_conexion, estado) VALUES (?, ?, ?, ?, ?, ?)",
            (data.get("ip_inicial", id_unico), user_id, data.get("mac", id_unico), data.get("fabricante", "Desconocido"), data.get("primera_conexion"), "historial")
        )
        
        # 2. Intentar Firebase
        try:
            if not NetworkChecker.is_online(): raise ConnectionError('Offline')
            self._save_historial_doc_to_firebase(id_unico, data, user_id)
        except Exception as e:
            print(f"[DB WRITE FALLBACK] save_historial_doc encolado por error: {e}")
            # Guardamos como un save_device genérico de contingencia o acción personalizada.
            # Dado que el historial también se almacena como dispositivo en la cola, usamos action_type
            # personalizado que el SyncDaemon procesará convirtiéndolo en save_device o lo encolamos como save_device.
            self._enqueue_action("save_device", user_id, {"ip": data.get("ip_inicial", id_unico), "document": data})

    def _save_historial_doc_to_firebase(self, id_unico: str, data: dict, user_id: str):
        user_ref = self._get_user_ref(user_id)
        user_ref.collection("historial").document(id_unico).set(data)

    def save_device(self, ip: str, document: dict, user_id: str = ""):
        if not user_id:
            user_id = "anonymous"
            
        # 1. Guardar localmente
        self.local_db.execute_write(
            '''INSERT OR REPLACE INTO devices 
               (ip, user_id, mac, hostname, fabricante, total_vulnerabilidades, max_score, fecha_auditoria, estado, es_nuevo, primera_conexion, scan_id) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (ip, user_id, document.get("mac"), document.get("hostname"), document.get("fabricante"),
             document.get("total_vulnerabilidades", 0), document.get("max_score", 0.0), document.get("fecha_auditoria"),
             document.get("estado"), 1 if document.get("es_nuevo") else 0, document.get("primera_conexion"), document.get("scan_id"))
        )
        
        # 2. Intentar Firebase
        try:
            if not NetworkChecker.is_online(): raise ConnectionError('Offline')
            self._save_device_to_firebase(ip, document, user_id)
        except Exception as e:
            print(f"[DB WRITE FALLBACK] save_device encolado por error: {e}")
            self._enqueue_action("save_device", user_id, {"ip": ip, "document": document})

    def _save_device_to_firebase(self, ip: str, document: dict, user_id: str):
        user_ref = self._get_user_ref(user_id)
        user_ref.collection("devices").document(ip).set(document)

    def save_vulnerability(self, cve_id: str, data: dict, user_id: str = ""):
        if not user_id:
            user_id = "anonymous"
        ip = data.get("ip", "")
        puerto = data.get("puerto", 0)
        
        # Generamos una ID única compuesta para SQLite local
        local_id = f"{cve_id}_{user_id}_{ip}_{puerto}"
        
        # 1. Guardar localmente
        self.local_db.execute_write(
            '''INSERT OR REPLACE INTO vulnerabilities 
               (id, cve_id, user_id, descripcion, severidad, score, ip, puerto, servicio, version, fecha_deteccion) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (local_id, cve_id, user_id, data.get("descripcion"), data.get("severidad"), data.get("score", 0.0),
             ip, puerto, data.get("servicio"), data.get("version"), data.get("fecha_deteccion"))
        )
        
        # 2. Intentar Firebase
        try:
            if not NetworkChecker.is_online(): raise ConnectionError('Offline')
            self._save_vulnerability_to_firebase(cve_id, data, user_id)
        except Exception as e:
            print(f"[DB WRITE FALLBACK] save_vulnerability encolada por error: {e}")
            self._enqueue_action("save_vulnerability", user_id, {"cve_id": cve_id, "data": data})

    def _save_vulnerability_to_firebase(self, cve_id: str, data: dict, user_id: str):
        user_ref = self._get_user_ref(user_id)
        user_ref.collection("vulnerabilities").document(cve_id).set(data)

    def clear_devices(self, user_id: str = ""):
        if not user_id:
            user_id = "anonymous"
            
        # 1. Limpiar localmente
        self.local_db.execute_write("DELETE FROM devices WHERE user_id = ?", (user_id,))
        
        # 2. Intentar Firebase
        try:
            if not NetworkChecker.is_online(): raise ConnectionError('Offline')
            self._clear_devices_to_firebase(user_id)
        except Exception as e:
            print(f"[DB WRITE FALLBACK] clear_devices encolada por error: {e}")
            self._enqueue_action("clear_devices", user_id, {})

    def _clear_devices_to_firebase(self, user_id: str):
        user_ref = self._get_user_ref(user_id)
        docs = user_ref.collection("devices").stream()
        for doc in docs:
            doc.reference.delete()
        print(f"[DB] Dispositivos de {user_id} limpiados en Firebase.")

    def clear_vulnerabilities(self, user_id: str = ""):
        if not user_id:
            user_id = "anonymous"
            
        # 1. Limpiar localmente
        self.local_db.execute_write("DELETE FROM vulnerabilities WHERE user_id = ?", (user_id,))
        
        # 2. Intentar Firebase
        try:
            if not NetworkChecker.is_online(): raise ConnectionError('Offline')
            self._clear_vulnerabilities_to_firebase(user_id)
        except Exception as e:
            print(f"[DB WRITE FALLBACK] clear_vulnerabilities encolada por error: {e}")
            self._enqueue_action("clear_vulnerabilities", user_id, {})

    def _clear_vulnerabilities_to_firebase(self, user_id: str):
        user_ref = self._get_user_ref(user_id)
        docs = user_ref.collection("vulnerabilities").stream()
        for doc in docs:
            doc.reference.delete()
        print(f"[DB] Vulnerabilidades de {user_id} limpiadas en Firebase.")

    def get_all_devices(self, user_id: str = ""):
        if not user_id:
            user_id = "anonymous"
            
        try:
            if not self.firebase_active:
                raise ConnectionError("Firebase inactivo")
            user_ref = self._get_user_ref(user_id)
            docs = user_ref.collection("devices").stream()
            devices = [doc.to_dict() for doc in docs]
            
            # Sincronizar SQLite con los datos más nuevos de Firebase
            self.local_db.execute_write("DELETE FROM devices WHERE user_id = ? AND estado != 'historial'", (user_id,))
            for dev in devices:
                self.local_db.execute_write(
                    '''INSERT OR REPLACE INTO devices 
                       (ip, user_id, mac, hostname, fabricante, total_vulnerabilidades, max_score, fecha_auditoria, estado, es_nuevo, primera_conexion, scan_id) 
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (dev.get("ip"), user_id, dev.get("mac"), dev.get("hostname"), dev.get("fabricante"),
                     dev.get("total_vulnerabilidades", 0), dev.get("max_score", 0.0), dev.get("fecha_auditoria"),
                     dev.get("estado"), 1 if dev.get("es_nuevo") else 0, dev.get("primera_conexion"), dev.get("scan_id"))
                )
            return devices
        except Exception as e:
            print(f"[DB READ FALLBACK] get_all_devices leyendo de SQLite por: {e}")
            rows = self.local_db.execute_read("SELECT * FROM devices WHERE user_id = ? AND estado != 'historial'", (user_id,))
            devices = []
            for r in rows:
                devices.append({
                    "ip": r["ip"],
                    "mac": r["mac"],
                    "hostname": r["hostname"],
                    "fabricante": r["fabricante"],
                    "total_vulnerabilidades": r["total_vulnerabilidades"],
                    "max_score": r["max_score"],
                    "fecha_auditoria": r["fecha_auditoria"],
                    "estado": r["estado"],
                    "es_nuevo": True if r["es_nuevo"] == 1 else False,
                    "primera_conexion": r["primera_conexion"],
                    "scan_id": r["scan_id"]
                })
            return devices

    def get_all_vulnerabilities(self, user_id: str = ""):
        if not user_id:
            user_id = "anonymous"
            
        try:
            if not self.firebase_active:
                raise ConnectionError("Firebase inactivo")
            user_ref = self._get_user_ref(user_id)
            docs = user_ref.collection("vulnerabilities").stream()
            vulns = [doc.to_dict() for doc in docs]
            vulns.sort(key=lambda x: x.get("score", 0), reverse=True)
            
            # Sincronizar SQLite con Firebase
            self.local_db.execute_write("DELETE FROM vulnerabilities WHERE user_id = ?", (user_id,))
            for v in vulns:
                local_id = f"{v.get('cve_id')}_{user_id}_{v.get('ip')}_{v.get('puerto', 0)}"
                self.local_db.execute_write(
                    '''INSERT OR REPLACE INTO vulnerabilities 
                       (id, cve_id, user_id, descripcion, severidad, score, ip, puerto, servicio, version, fecha_deteccion) 
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (local_id, v.get("cve_id"), user_id, v.get("descripcion"), v.get("severidad"), v.get("score", 0.0),
                     v.get("ip"), v.get("puerto", 0), v.get("servicio"), v.get("version"), v.get("fecha_deteccion"))
                )
            return vulns
        except Exception as e:
            print(f"[DB READ FALLBACK] get_all_vulnerabilities leyendo de SQLite por: {e}")
            rows = self.local_db.execute_read("SELECT * FROM vulnerabilities WHERE user_id = ? ORDER BY score DESC", (user_id,))
            vulns = []
            for r in rows:
                vulns.append({
                    "cve_id": r["cve_id"],
                    "descripcion": r["descripcion"],
                    "severidad": r["severidad"],
                    "score": r["score"],
                    "ip": r["ip"],
                    "puerto": r["puerto"],
                    "servicio": r["servicio"],
                    "version": r["version"],
                    "fecha_deteccion": r["fecha_deteccion"]
                })
            return vulns

    # ==================== MÉTODOS DE IDEMPOTENCIA Y SESIONES DE ESCANEO ====================
    
    def scan_exists(self, user_id: str, scan_id: str) -> bool:
        if not user_id:
            user_id = "anonymous"
            
        try:
            if not self.firebase_active:
                raise ConnectionError("Firebase inactivo")
            user_ref = self._get_user_ref(user_id)
            doc = user_ref.collection("scans").document(scan_id).get()
            return doc.exists
        except Exception as e:
            print(f"[DB READ FALLBACK] scan_exists leyendo de SQLite por: {e}")
            rows = self.local_db.execute_read("SELECT 1 FROM scans WHERE scan_id = ? AND user_id = ?", (scan_id, user_id))
            return len(rows) > 0
    
    def mark_scan_processed(self, user_id: str, scan_id: str, ip: str = ""):
        if not user_id:
            user_id = "anonymous"
            
        # 1. Guardar localmente
        self.local_db.execute_write(
            "INSERT OR REPLACE INTO scans (scan_id, user_id, timestamp) VALUES (?, ?, ?)",
            (scan_id, user_id, datetime.datetime.utcnow().isoformat())
        )
        
        # 2. Intentar Firebase
        try:
            if not NetworkChecker.is_online(): raise ConnectionError('Offline')
            self._mark_scan_processed_to_firebase(user_id, scan_id, ip)
        except Exception as e:
            print(f"[DB WRITE FALLBACK] mark_scan_processed encolada por error: {e}")
            self._enqueue_action("mark_scan_processed", user_id, {"scan_id": scan_id, "ip": ip})

    def _mark_scan_processed_to_firebase(self, user_id: str, scan_id: str, ip: str):
        user_ref = self._get_user_ref(user_id)
        user_ref.collection("scans").document(scan_id).set({
            "ip": ip,
            "timestamp": datetime.datetime.utcnow().isoformat()
        }, merge=True)

    def update_scan_metadata(self, user_id: str, scan_id: str, metadata: dict):
        if not user_id:
            user_id = "anonymous"
            
        # 1. Guardar localmente
        # Obtenemos los campos clave si existen en el diccionario de metadatos
        status = metadata.get("status")
        devices_found = metadata.get("devices_found")
        total_targets = metadata.get("total_targets")
        vulns_found = metadata.get("vulnerabilidades_found")
        end_time = metadata.get("end_time")
        
        # Actualizamos dinámicamente según lo que venga en el metadata dict
        query_parts = []
        params = []
        if status is not None:
            query_parts.append("status = ?")
            params.append(status)
        if devices_found is not None:
            query_parts.append("devices_found = ?")
            params.append(devices_found)
        if total_targets is not None:
            query_parts.append("total_targets = ?")
            params.append(total_targets)
        if vulns_found is not None:
            query_parts.append("vulnerabilidades_found = ?")
            params.append(vulns_found)
        if end_time is not None:
            query_parts.append("end_time = ?")
            params.append(end_time)
            
        if query_parts:
            params.extend([scan_id, user_id])
            self.local_db.execute_write(
                f"UPDATE scans SET {', '.join(query_parts)} WHERE scan_id = ? AND user_id = ?",
                tuple(params)
            )
            
        # 2. Intentar Firebase
        try:
            if not NetworkChecker.is_online(): raise ConnectionError('Offline')
            self._update_scan_metadata_to_firebase(user_id, scan_id, metadata)
        except Exception as e:
            print(f"[DB WRITE FALLBACK] update_scan_metadata encolada por error: {e}")
            self._enqueue_action("update_scan_metadata", user_id, {"scan_id": scan_id, "metadata": metadata})

    def _update_scan_metadata_to_firebase(self, user_id: str, scan_id: str, metadata: dict):
        user_ref = self._get_user_ref(user_id)
        user_ref.collection("scans").document(scan_id).set(metadata, merge=True)

    def increment_vulnerabilities(self, user_id: str, scan_id: str, amount: int):
        if not user_id:
            user_id = "anonymous"
        if amount <= 0:
            return
            
        # 1. Guardar localmente
        self.local_db.execute_write(
            "UPDATE scans SET vulnerabilidades_found = COALESCE(vulnerabilidades_found, 0) + ? WHERE scan_id = ? AND user_id = ?",
            (amount, scan_id, user_id)
        )
        
        # 2. Intentar Firebase
        try:
            if not NetworkChecker.is_online(): raise ConnectionError('Offline')
            self._increment_vulnerabilities_to_firebase(user_id, scan_id, amount)
        except Exception as e:
            print(f"[DB WRITE FALLBACK] increment_vulnerabilities encolado por error: {e}")
            self._enqueue_action("increment_vulnerabilities", user_id, {"scan_id": scan_id, "amount": amount})

    def _increment_vulnerabilities_to_firebase(self, user_id: str, scan_id: str, amount: int):
        from firebase_admin import firestore
        user_ref = self._get_user_ref(user_id)
        user_ref.collection("scans").document(scan_id).set({
            "vulnerabilidades_found": firestore.Increment(amount)
        }, merge=True)

    def increment_devices(self, user_id: str, scan_id: str, amount: int = 1):
        if not user_id:
            user_id = "anonymous"
            
        # 1. Guardar localmente
        self.local_db.execute_write(
            "UPDATE scans SET devices_found = COALESCE(devices_found, 0) + ? WHERE scan_id = ? AND user_id = ?",
            (amount, scan_id, user_id)
        )
        
        # 2. Intentar Firebase
        try:
            if not NetworkChecker.is_online(): raise ConnectionError('Offline')
            self._increment_devices_to_firebase(user_id, scan_id, amount)
        except Exception as e:
            print(f"[DB WRITE FALLBACK] increment_devices encolado por error: {e}")
            self._enqueue_action("increment_devices", user_id, {"scan_id": scan_id, "amount": amount})

    def _increment_devices_to_firebase(self, user_id: str, scan_id: str, amount: int):
        from firebase_admin import firestore
        user_ref = self._get_user_ref(user_id)
        user_ref.collection("scans").document(scan_id).set({
            "devices_found": firestore.Increment(amount)
        }, merge=True)

    def append_scan_log(self, user_id: str, scan_id: str, message: str):
        if not user_id:
            user_id = "anonymous"
        entry = f"[{datetime.datetime.utcnow().strftime('%H:%M:%S')}] {message}"
        
        # 1. Guardar localmente (leemos logs actuales del scan, anexamos y re-guardamos en SQLite)
        try:
            rows = self.local_db.execute_read("SELECT logs_json FROM scans WHERE scan_id = ? AND user_id = ?", (scan_id, user_id))
            logs = []
            if rows and rows[0]["logs_json"]:
                logs = json.loads(rows[0]["logs_json"])
            logs.append(entry)
            
            # Si no existe la cabecera del escaneo local, la creamos al vuelo
            self.local_db.execute_write(
                '''INSERT INTO scans (scan_id, user_id, logs_json, status) VALUES (?, ?, ?, ?)
                   ON CONFLICT(scan_id, user_id) DO UPDATE SET logs_json = excluded.logs_json''',
                (scan_id, user_id, json.dumps(logs), "processing")
            )
        except Exception as ex:
            print(f"[DB LOCAL LOG ERROR] Falló guardar log en SQLite: {ex}")
            
        # 2. Intentar Firebase
        try:
            if not NetworkChecker.is_online(): raise ConnectionError('Offline')
            self._append_scan_log_to_firebase(user_id, scan_id, message)
        except Exception as e:
            print(f"[DB WRITE FALLBACK] append_scan_log encolada por error: {e}")
            self._enqueue_action("append_scan_log", user_id, {"scan_id": scan_id, "message": message})

    def _append_scan_log_to_firebase(self, user_id: str, scan_id: str, message: str):
        from firebase_admin import firestore
        user_ref = self._get_user_ref(user_id)
        entry = f"[{datetime.datetime.utcnow().strftime('%H:%M:%S')}] {message}"
        user_ref.collection("scans").document(scan_id).set({
            "logs": firestore.ArrayUnion([entry])
        }, merge=True)

    def create_user_profile(self, user_id: str, email: str = ""):
        if not user_id:
            user_id = "anonymous"
        # Para simplificar, los perfiles de usuario se guardan directo a Firebase (requieren login online).
        try:
            user_ref = self._get_user_ref(user_id)
            user_ref.collection("profile").document("data").set({
                "createdAt": datetime.datetime.utcnow().isoformat(),
                "email": email,
                "status": "active"
            })
        except Exception as e:
            print(f"[DB WRITE ERROR] No se pudo crear perfil en Firebase (offline): {e}")

    def save_scan_device(self, user_id: str, scan_id: str, ip: str, data: dict):
        if not user_id:
            user_id = "anonymous"
            
        # 1. Guardar localmente
        self.local_db.execute_write(
            "INSERT OR REPLACE INTO scan_devices (scan_id, ip, user_id, device_data_json) VALUES (?, ?, ?, ?)",
            (scan_id, ip, user_id, json.dumps(data))
        )
        
        # 2. Intentar Firebase
        try:
            if not NetworkChecker.is_online(): raise ConnectionError('Offline')
            self._save_scan_device_to_firebase(user_id, scan_id, ip, data)
        except Exception as e:
            print(f"[DB WRITE FALLBACK] save_scan_device encolada por error: {e}")
            self._enqueue_action("save_scan_device", user_id, {"scan_id": scan_id, "ip": ip, "data": data})

    def _save_scan_device_to_firebase(self, user_id: str, scan_id: str, ip: str, data: dict):
        user_ref = self._get_user_ref(user_id)
        user_ref.collection("scans").document(scan_id).collection("devices").document(ip).set(data)

    def get_user_scans(self, user_id: str):
        if not user_id:
            user_id = "anonymous"
            
        try:
            if not self.firebase_active:
                raise ConnectionError("Firebase inactivo")
            user_ref = self._get_user_ref(user_id)
            docs = user_ref.collection("scans").order_by("timestamp", direction="DESCENDING").stream()
            scans = []
            for doc in docs:
                data = doc.to_dict()
                data["id"] = doc.id
                scans.append(data)
                
            # Sincronizar SQLite con Firebase
            for s in scans:
                self.local_db.execute_write(
                    '''INSERT INTO scans 
                       (scan_id, user_id, status, devices_found, total_targets, vulnerabilidades_found, timestamp, end_time) 
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(scan_id, user_id) DO UPDATE SET 
                       status = excluded.status, devices_found = excluded.devices_found, 
                       total_targets = excluded.total_targets, vulnerabilidades_found = excluded.vulnerabilidades_found,
                       end_time = excluded.end_time''',
                    (s.get("id"), user_id, s.get("status"), s.get("devices_found", 0), s.get("total_targets", 0),
                     s.get("vulnerabilidades_found", 0), s.get("timestamp"), s.get("end_time"))
                )
            return scans
        except Exception as e:
            print(f"[DB READ FALLBACK] get_user_scans leyendo de SQLite por: {e}")
            rows = self.local_db.execute_read("SELECT * FROM scans WHERE user_id = ? ORDER BY timestamp DESC", (user_id,))
            scans = []
            for r in rows:
                scans.append({
                    "id": r["scan_id"],
                    "status": r["status"],
                    "devices_found": r["devices_found"],
                    "total_targets": r["total_targets"],
                    "vulnerabilidades_found": r["vulnerabilidades_found"],
                    "timestamp": r["timestamp"],
                    "end_time": r["end_time"]
                })
            return scans

    def get_scan_details(self, user_id: str, scan_id: str):
        if not user_id:
            user_id = "anonymous"
            
        try:
            if not self.firebase_active:
                raise ConnectionError("Firebase inactivo")
            user_ref = self._get_user_ref(user_id)
            doc = user_ref.collection("scans").document(scan_id).get()
            if doc.exists:
                data = doc.to_dict()
                data["id"] = doc.id
                
                # Sincronizar local
                self.local_db.execute_write(
                    '''INSERT INTO scans 
                       (scan_id, user_id, status, devices_found, total_targets, vulnerabilidades_found, timestamp, end_time, logs_json, topology_json) 
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(scan_id, user_id) DO UPDATE SET 
                       status = excluded.status, devices_found = excluded.devices_found, 
                       total_targets = excluded.total_targets, vulnerabilidades_found = excluded.vulnerabilidades_found,
                       end_time = excluded.end_time, logs_json = excluded.logs_json, topology_json = excluded.topology_json''',
                    (scan_id, user_id, data.get("status"), data.get("devices_found", 0), data.get("total_targets", 0),
                     data.get("vulnerabilidades_found", 0), data.get("timestamp"), data.get("end_time"),
                     json.dumps(data.get("logs", [])), json.dumps(data.get("topology", {})))
                )
                return data
            return None
        except Exception as e:
            print(f"[DB READ FALLBACK] get_scan_details leyendo de SQLite por: {e}")
            rows = self.local_db.execute_read("SELECT * FROM scans WHERE scan_id = ? AND user_id = ?", (scan_id, user_id))
            if rows:
                r = rows[0]
                logs = []
                topology = {}
                if r["logs_json"]:
                    logs = json.loads(r["logs_json"])
                if r["topology_json"]:
                    topology = json.loads(r["topology_json"])
                    
                return {
                    "id": r["scan_id"],
                    "status": r["status"],
                    "devices_found": r["devices_found"],
                    "total_targets": r["total_targets"],
                    "vulnerabilidades_found": r["vulnerabilidades_found"],
                    "timestamp": r["timestamp"],
                    "end_time": r["end_time"],
                    "logs": logs,
                    "topology": topology
                }
            return None

    def get_scan_devices(self, user_id: str, scan_id: str):
        if not user_id:
            user_id = "anonymous"
            
        try:
            if not self.firebase_active:
                raise ConnectionError("Firebase inactivo")
            user_ref = self._get_user_ref(user_id)
            docs = user_ref.collection("scans").document(scan_id).collection("devices").stream()
            devices = [doc.to_dict() for doc in docs]
            
            # Sincronizar SQLite local
            self.local_db.execute_write("DELETE FROM scan_devices WHERE scan_id = ? AND user_id = ?", (scan_id, user_id))
            for dev in devices:
                self.local_db.execute_write(
                    "INSERT OR REPLACE INTO scan_devices (scan_id, ip, user_id, device_data_json) VALUES (?, ?, ?, ?)",
                    (scan_id, dev.get("ip"), user_id, json.dumps(dev))
                )
            return devices
        except Exception as e:
            print(f"[DB READ FALLBACK] get_scan_devices leyendo de SQLite por: {e}")
            rows = self.local_db.execute_read("SELECT device_data_json FROM scan_devices WHERE scan_id = ? AND user_id = ?", (scan_id, user_id))
            devices = []
            for r in rows:
                if r["device_data_json"]:
                    devices.append(json.loads(r["device_data_json"]))
            return devices
