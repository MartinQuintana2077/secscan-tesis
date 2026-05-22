import datetime
from core.scanner import ScannerEngine, get_local_cidr
from core.cve_client import CVEClient
from services.db_service import DatabaseService

class ScanService:
    def __init__(self):
        self.scanner = ScannerEngine()
        self.cve_client = CVEClient()
        self.db_service = DatabaseService()

    def set_log_cb(self, cb):
        from core.scanner import _thread_local
        _thread_local.log_cb = cb

    def _log(self, msg: str):
        print(msg)
        from core.scanner import _thread_local
        cb = getattr(_thread_local, 'log_cb', None)
        if cb:
            cb(msg)

    def discover(self, target_ip: str, passive: bool = False):
        # Limpieza de input
        ip_limpia = target_ip.replace('=', '').strip() if target_ip else ''
        
        # Auto-configuración
        if ip_limpia.lower() == "auto" or ip_limpia == "":
            ip_real = get_local_cidr()
        else:
            ip_real = ip_limpia

        if not getattr(self.scanner, 'nmap_installed', True):
            return {"error": "NMAP_MISSING", "target": ip_real}

        if passive:
            self._log(f"🤫 [SCAN PASIVO] Iniciando descubrimiento pasivo e indetectable en {ip_real}...")
            # Obtener topología pasiva a partir de ipconfig local
            topology = self.scanner.fallback_to_gateway("Escaneo Pasivo habilitado. Descubrimiento silencioso extraído únicamente del sistema operativo.")
            
            # Descubrimiento estrictamente pasivo vía ARP caché del sistema operativo sin enviar ningún ping
            prefix = ip_real.split('/')[0].rsplit('.', 1)[0] + '.'
            dispositivos = []
            found_ips = set()
            try:
                import subprocess, socket
                arp_output = subprocess.check_output('arp -a', shell=True).decode('cp1252', errors='ignore')
                for line in arp_output.split('\n'):
                    parts = line.split()
                    if len(parts) >= 2:
                        ip_arp = parts[0].strip()
                        mac_arp = parts[1].strip().replace('-', ':').upper()
                        if (ip_arp.startswith(prefix)
                                and ip_arp not in found_ips
                                and not ip_arp.endswith('.255')
                                and mac_arp not in ('FF:FF:FF:FF:FF:FF', 'FF-FF-FF-FF-FF-FF')
                                and len(mac_arp) == 17):
                            hostname = ""
                            try:
                                hostname = socket.gethostbyaddr(ip_arp)[0]
                            except Exception:
                                pass
                            dispositivos.append({
                                "ip": ip_arp,
                                "mac": mac_arp,
                                "hostname": hostname or "Caché ARP Pasiva",
                                "vendor": "",
                                "discovery_method": "arp_cache_passive",
                                "parent_ip": ip_real.split('/')[0]
                            })
                            found_ips.add(ip_arp)
            except Exception as e:
                self._log(f"  [Scan Pasivo Error] {e}")
                
            # Agregar la propia PC si no está
            from core.scanner import get_local_ip, get_local_mac
            local_ip = get_local_ip()
            if local_ip not in found_ips and local_ip.startswith(prefix):
                dispositivos.append({
                    "ip": local_ip,
                    "mac": get_local_mac(),
                    "hostname": socket.gethostname(),
                    "vendor": "",
                    "discovery_method": "local_passive",
                    "parent_ip": ip_real.split('/')[0]
                })

            topology["advertencias"].append("Auditoría Pasiva: Este mapa se generó de forma pasiva leyendo la memoria ARP local sin inyectar ningún paquete a la red.")
            topology["devices"] = dispositivos
            return {"status": "ok", "dispositivos": dispositivos, "target": ip_real, "topology": topology, "passive": True}

        # Fase 1: Descubrir esqueleto de red con Traceroute
        topology = self.scanner.fase1_traceroute()
        advertencias = topology.get("advertencias", [])

        # Extraer la IP real del Router Principal (puede ser "unknown" en redes blindadas)
        router_principal_ip = None
        for hop in topology.get("hops_privados", []):
            if hop.get("tipo") == "router_principal" and hop.get("ip") != "unknown":
                router_principal_ip = hop["ip"]
                break

        # Fase 2: Cascada SNMP → DHCP → Nmap fallback
        # Se pasa la IP del router y la lista de advertencias compartida
        dispositivos = self.scanner.discover_network(
            ip_real,
            router_principal_ip=router_principal_ip,
            advertencias=advertencias
        )

        # Sincronizar advertencias actualizadas de vuelta en topology
        topology["advertencias"] = advertencias
        topology["devices"] = dispositivos

        return {"status": "ok", "dispositivos": dispositivos, "target": ip_real, "topology": topology}



    def deep_scan(self, ip: str, user_id: str = "", scan_id: str = ""):
        self._log(f"====== INICIANDO ESCANEO PARA: {ip} (user: {user_id}, scan: {scan_id}) ======")

        puertos_info = self.scanner.scan_ports(ip)
        puertos = puertos_info.get("puertos_abiertos", [])
        
        total_vulnerabilidades = 0
        for puerto in puertos:
            servicio = puerto.get("servicio", "")
            version = puerto.get("version", "")
            
            if version and version.strip() != "":
                cves = self.cve_client.buscar_vulnerabilidades(servicio, version)
                puerto["vulnerabilidades"] = cves
                total_vulnerabilidades += len(cves)
            else:
                puerto["vulnerabilidades"] = []
        
        mac_real = puertos_info.get("mac", "Desconocida")
        id_unico = mac_real if mac_real != "Desconocida" else ip
        
        # Lógica de Historial e Intrusos
        doc_snap = self.db_service.get_historial_doc(id_unico, user_id)
        hora_actual = datetime.datetime.utcnow().isoformat()
        es_nuevo = False
        primera_conexion = hora_actual
        
        if not doc_snap.exists:
            es_nuevo = True
            self.db_service.save_historial_doc(id_unico, {
                "ip_inicial": ip,
                "mac": mac_real,
                "primera_conexion": hora_actual,
                "fabricante": puertos_info.get("fabricante", "Desconocido")
            }, user_id)
        else:
            datos_historial = doc_snap.to_dict()
            primera_conexion = datos_historial.get("primera_conexion", hora_actual)
            
        # Cálculo de Riesgo Máximo
        max_score = 0
        for puerto in puertos:
            for v in puerto.get("vulnerabilidades", []):
                v_score = v.get("score", 0)
                if v_score > max_score:
                    max_score = v_score

        documento = {
            "ip": ip,
            "mac": mac_real,
            "hostname": puertos_info.get("hostname", ""),
            "fabricante": puertos_info.get("fabricante", "Desconocido"),
            "puertos_abiertos": puertos,
            "total_vulnerabilidades": total_vulnerabilidades,
            "max_score": max_score,
            "fecha_auditoria": hora_actual,
            "estado": "Completado",
            "es_nuevo": es_nuevo,
            "primera_conexion": primera_conexion,
            "scan_id": scan_id
        }
        
        # 1. Guardar en vista general del usuario
        self.db_service.save_device(ip, documento, user_id)
        
        # 2. Guardar en el histórico de este escaneo específico
        if scan_id:
            self.db_service.save_scan_device(user_id, scan_id, ip, documento)
        
        if total_vulnerabilidades > 0:

            for puerto in puertos:
                for cve in puerto.get("vulnerabilidades", []):
                    self.db_service.save_vulnerability(cve["cve_id"], {
                        **cve,
                        "ip": ip,
                        "puerto": puerto.get("puerto"),
                        "servicio": puerto.get("servicio"),
                        "version": puerto.get("version"),
                        "fecha_deteccion": datetime.datetime.utcnow().isoformat()
                    }, user_id)
        
        return documento
