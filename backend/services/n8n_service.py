import requests
from typing import Optional
from services.scan_service import ScanService
from services.db_service import DatabaseService


class N8nService:
    """
    Servicio para integrar con n8n (orquestador).
    Maneja la comunicación con los webhooks de n8n.
    """
    
    def __init__(self):
        self.scan_service = ScanService()
        self.db_service = DatabaseService()
        self._n8n_available = None
    
    @property
    def is_available(self) -> bool:
        """Verifica si n8n está corriendo."""
        if self._n8n_available is not None:
            return self._n8n_available
        
        urls = [
            "http://localhost:5678/webhook/secscan",
            "http://localhost:5678/webhook-test/secscan"
        ]
        
        for url in urls:
            try:
                resp = requests.post(url, json={"test": True}, timeout=0.5)
                self._n8n_available = resp.status_code == 200
                return self._n8n_available
            except:
                continue
        
        self._n8n_available = False
        return False
    
    def trigger_workflow(self, target_ip: str, user_id: str) -> dict:
        """
        Dispara el workflow de n8n.
        Retorna información sobre el modo de ejecución.
        """
        if not self.is_available:
            return {"mode": "unavailable", "available": False}
        
        payload = {"target_ip": target_ip, "user_id": user_id}
        urls = [
            "http://localhost:5678/webhook/secscan",
            "http://localhost:5678/webhook-test/secscan"
        ]
        
        for url in urls:
            try:
                resp = requests.post(url, json=payload, timeout=0.5)
                if resp.status_code == 200:
                    return {"mode": "n8n", "available": True, "url": url}
            except:
                continue
        
        return {"mode": "unavailable", "available": False}
    
    def run_discover(self, target_ip: str, user_id: str) -> dict:
        """
        Ejecuta el descubrimiento de red.
       Si n8n está disponible, lo usa.
        Si no, ejecuta directamente SIN hacer polling a rutas internas.
        """
        if not user_id or user_id == "legacy_user":
            return {"status": "error", "code": "INVALID_USER_ID", "message": "Usuario no identificado"}
        
        self.db_service.clear_devices(user_id)
        self.db_service.clear_vulnerabilities(user_id)
        
        if self.is_available:
            result = self._trigger_discover_via_n8n(target_ip, user_id)
            if result.get("status") == "ok":
                return result
        
        # MODO DIRECTO: ejecutar directamente sin polling a rutas HTTP internas
        return self._run_discover_direct(target_ip, user_id)
    
    def _trigger_discover_via_n8n(self, target_ip: str, user_id: str) -> dict:
        """Dispara solo el descubrimiento via n8n."""
        payload = {"target_ip": target_ip, "user_id": user_id}
        
        try:
            resp = requests.post(
                "http://localhost:5678/webhook/secscan",
                json=payload,
                timeout=1
            )
            if resp.status_code == 200:
                return {"mode": "n8n", "status": "ok"}
        except:
            pass
        
        return {"mode": "unavailable", "status": "error"}
    
    def _run_discover_direct(self, target_ip: str, user_id: str) -> dict:
        """
        Ejecución directa del descubrimiento.
        NO llama a rutas HTTP internas - ejecuta directamente.
        
        IMPORTANTE: Recibe user_id del caller, NO de ningún request.
        """
        # Ejecutar el escaneo directamente (no llama a rutas HTTP)
        result = self.scan_service.discover(target_ip)
        
        if result.get("error") == "NMAP_MISSING":
            return {"status": "error", "code": "NMAP_MISSING", "dispositivos": []}
        
        dispositivos = result.get("dispositivos", [])
        return {
            "mode": "direct",
            "status": "ok",
            "total": len(dispositivos),
            "dispositivos": dispositivos
        }
    
    def run_deep_scan(self, ip: str, user_id: str) -> dict:
        """Ejecuta el escaneo profundo de un dispositivo."""
        detalle = self.scan_service.deep_scan(ip, user_id)
        return {
            "status": "ok",
            "ip_escaneada": ip,
            "puertos_encontrados": len(detalle.get("puertos_abiertos", [])),
            "vulnerabilidades_encontradas": detalle.get("total_vulnerabilidades", 0),
            "detalle": detalle
        }