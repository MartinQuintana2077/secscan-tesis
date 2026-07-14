import datetime
import threading
import time
import subprocess
import socket
import ipaddress
import nmap
from core.scanner import ScannerEngine, get_local_cidr, get_local_ip, get_local_mac
from core.cve_client import CVEClient
from services.db_service import DatabaseService

_passive_device_cache = {}
_last_subnet = None
_last_discovery_time = 0.0
_daemon_started = False
_daemon_lock = threading.Lock()

_active_scan_count = 0
_active_scan_count_lock = threading.Lock()
_last_active_time = 0.0

_deep_scan_active_count = 0
_deep_scan_start_time = 0.0
_deep_scan_lock = threading.Lock()

def start_passive_daemon():
    """Inicializa de forma segura el hilo del demonio en segundo plano."""
    global _daemon_started
    with _daemon_lock:
        if _daemon_started:
            return
        _daemon_started = True
        
    thread = threading.Thread(target=run_passive_background_worker, daemon=True, name="PassiveScanDaemon")
    thread.start()
    print("[PassiveScanDaemon] Hilo de escaneo pasivo en segundo plano iniciado correctamente.")
def run_passive_background_worker():
    """Ciclo en segundo plano del demonio pasivo."""
    global _last_subnet, _passive_device_cache, _last_discovery_time
    global _active_scan_count, _active_scan_count_lock, _last_active_time
    
    time.sleep(2)
    
    _paused_logged = False
    while True:
        with _active_scan_count_lock:
            if _active_scan_count > 0:
                _last_active_time = time.time()
            hay_escaneo_activo = (_active_scan_count > 0) or (time.time() - _last_active_time < 8.0)
            
        if hay_escaneo_activo:
            if not _paused_logged:
                print("[PassiveScanDaemon] Escaneo activo en curso. Ciclo pasivo en pausa.")
                _paused_logged = True
            time.sleep(2)
            continue
            
        if _paused_logged:
            print("[PassiveScanDaemon] Escaneo activo finalizado. Reanudando ciclos pasivos en segundo plano.")
            _paused_logged = False
 
        try:
            current_cidr = get_local_cidr()
            if not current_cidr:
                time.sleep(10)
                continue
                
            if current_cidr != _last_subnet:
                print(f"[PassiveScanDaemon] Cambio de red o nueva subred detectada: {current_cidr}. Limpiando caché anterior.")
                _last_subnet = current_cidr
                _passive_device_cache.clear()
                _last_discovery_time = 0.0
            
            ahora = time.time()
            necesita_descubrimiento = False
            
            if not _passive_device_cache:
                necesita_descubrimiento = True
            elif ahora - _last_discovery_time > 300: # 5 minutos
                necesita_descubrimiento = True
            else:
                unscanned_exists = any(not data.get("deep_scan_status") for data in _passive_device_cache.values())
                if not unscanned_exists:
                    necesita_descubrimiento = True
            
            if necesita_descubrimiento:
                print(f"[PassiveScanDaemon] Iniciando ciclo de escaneo pasivo en segundo plano en {current_cidr}...")
                _last_discovery_time = ahora
                prefix = current_cidr.split('/')[0].rsplit('.', 1)[0] + '.'
                
                try:
                    nm = nmap.PortScanner()
                    nm.scan(hosts=current_cidr, arguments='-sn -PE -T3')
                except Exception:
                    pass
 
                found_ips = set()
                new_devices = {}
                try:
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
                                
                                cached_dev = _passive_device_cache.get(ip_arp)
                                hostname = cached_dev.get("hostname") if cached_dev else ""
                                vendor = cached_dev.get("vendor", "") if cached_dev else ""
                                
                                if not hostname or hostname == "Caché ARP Pasiva":
                                    try:
                                        hostname = socket.gethostbyaddr(ip_arp)[0]
                                    except Exception:
                                        hostname = "Caché ARP Pasiva"
                                        
                                new_devices[ip_arp] = {
                                    "ip": ip_arp,
                                    "mac": mac_arp,
                                    "hostname": hostname,
                                    "vendor": vendor,
                                    "discovery_method": "arp_cache_passive",
                                    "parent_ip": current_cidr.split('/')[0]
                                }
                                found_ips.add(ip_arp)
                except Exception as e:
                    print(f"[PassiveScanDaemon] Error leyendo tabla ARP: {e}")
 
                try:
                    local_ip = get_local_ip()
                    if local_ip not in found_ips and local_ip.startswith(prefix):
                        new_devices[local_ip] = {
                            "ip": local_ip,
                            "mac": get_local_mac(),
                            "hostname": socket.gethostname(),
                            "vendor": "",
                            "discovery_method": "local_passive",
                            "parent_ip": current_cidr.split('/')[0]
                        }
                except Exception:
                    pass
                    
                if new_devices:
                    for ip, data in new_devices.items():
                        if ip in _passive_device_cache:
                            old_data = _passive_device_cache[ip]
                            if old_data.get("deep_scan_status"):
                                data["deep_scan_status"] = old_data.get("deep_scan_status")
                                data["puertos_abiertos"] = old_data.get("puertos_abiertos", [])
                                data["total_vulnerabilidades"] = old_data.get("total_vulnerabilidades", 0)
                                data["fabricante"] = old_data.get("fabricante", data.get("vendor", ""))
                                if "mac" in old_data and old_data["mac"] != "Desconocida":
                                    data["mac"] = old_data["mac"]
                                if "hostname" in old_data and old_data["hostname"] != "Caché ARP Pasiva":
                                    data["hostname"] = old_data["hostname"]
                    _passive_device_cache = new_devices
                
                print(f"[PassiveScanDaemon] Ciclo de fondo finalizado. Dispositivos en caché: {len(_passive_device_cache)} | IPs: {list(_passive_device_cache.keys())}")

            unscanned_ip = None
            for ip, data in _passive_device_cache.items():
                if not data.get("deep_scan_status"):
                    unscanned_ip = ip
                    break
            
            if unscanned_ip:
                print(f"[PassiveScanDaemon] Iniciando Deep-Scan silencioso en {unscanned_ip}...")
                _passive_device_cache[unscanned_ip]["deep_scan_status"] = "scanning"
                
                from core.scanner import ScannerEngine
                from core.cve_client import CVEClient
                bg_scanner = ScannerEngine()
                bg_cve = CVEClient()
                
                try:
                    puertos_info = bg_scanner.scan_ports(unscanned_ip)
                    puertos = puertos_info.get("puertos_abiertos", [])
                    total_vulns = 0
                    
                    for puerto in puertos:
                        servicio = puerto.get("servicio", "")
                        version = puerto.get("version", "")
                        if version and version.strip() != "":
                            cves = bg_cve.buscar_vulnerabilidades(servicio, version)
                            puerto["vulnerabilidades"] = cves
                            total_vulns += len(cves)
                        else:
                            puerto["vulnerabilidades"] = []
                            
                    _passive_device_cache[unscanned_ip].update({
                        "deep_scan_status": "completed",
                        "puertos_abiertos": puertos,
                        "total_vulnerabilidades": total_vulns,
                        "fabricante": puertos_info.get("fabricante", "Desconocido"),
                        "mac": puertos_info.get("mac", _passive_device_cache[unscanned_ip].get("mac", "Desconocida")),
                        "hostname": puertos_info.get("hostname", _passive_device_cache[unscanned_ip].get("hostname", ""))
                    })
                    print(f"[PassiveScanDaemon] ✅ Deep-Scan completado silenciosamente para {unscanned_ip}.")
                except Exception as e:
                    print(f"[PassiveScanDaemon] Error en Deep-Scan silencioso para {unscanned_ip}: {e}")
                    _passive_device_cache[unscanned_ip]["deep_scan_status"] = None # Reset para reintentar

                
        except Exception as e:
            print(f"[PassiveScanDaemon] Excepción en ciclo del worker: {e}")
            
        time.sleep(30)


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
        ip_limpia = target_ip.replace('=', '').strip() if target_ip else ''
        
        if ip_limpia.lower() == "auto" or ip_limpia == "":
            ip_real = get_local_cidr()
        else:
            ip_real = ip_limpia

        if not getattr(self.scanner, 'nmap_installed', True):
            return {"error": "NMAP_MISSING", "target": ip_real}

        if passive:
            self._log(f"🤫 [SCAN PASIVO] Retornando estado en segundo plano instantáneo para {ip_real}...")
            topology = self.scanner.fallback_to_gateway("Escaneo Pasivo en segundo plano. Descubrimiento extraído de la memoria del daemon.")
            
            if ip_real == _last_subnet or ip_limpia.lower() == "auto" or ip_limpia == "":
                dispositivos = list(_passive_device_cache.values())
            else:
                prefix = ip_real.split('/')[0].rsplit('.', 1)[0] + '.'
                dispositivos = []
                found_ips = set()
                try:
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
                                    hostname = "Caché ARP Pasiva"
                                dispositivos.append({
                                    "ip": ip_arp,
                                    "mac": mac_arp,
                                    "hostname": hostname,
                                    "vendor": "",
                                    "discovery_method": "arp_cache_passive",
                                    "parent_ip": ip_real.split('/')[0]
                                })
                                found_ips.add(ip_arp)
                except Exception as e:
                    self._log(f"  [Scan Pasivo Fallback Error] {e}")
            
            topology["advertencias"].append("Auditoría Pasiva en Segundo Plano: Este mapa se generó a partir de la caché en memoria recopilada silenciosamente por el daemon de fondo.")
            topology["devices"] = dispositivos
            return {"status": "ok", "dispositivos": dispositivos, "target": ip_real, "topology": topology, "passive": True}

        global _active_scan_count, _active_scan_count_lock, _last_active_time

        active_ips = None
        if (ip_real == _last_subnet or ip_limpia.lower() == "auto" or ip_limpia == "") and _passive_device_cache:
            active_ips = list(_passive_device_cache.keys())
            self._log(f"⚡ [DAEMON] Caché pasiva lista con {len(active_ips)} IPs — pausando daemon durante el escaneo activo.")

        with _active_scan_count_lock:
            _active_scan_count += 1
            _last_active_time = time.time()
        try:
            topology = self.scanner.fase1_traceroute()
            advertencias = topology.get("advertencias", [])

            router_principal_ip = None
            for hop in topology.get("hops_privados", []):
                if hop.get("tipo") == "router_principal" and hop.get("ip") != "unknown":
                    router_principal_ip = hop["ip"]
                    break

            dispositivos = self.scanner.discover_network(
                ip_real,
                router_principal_ip=router_principal_ip,
                advertencias=advertencias,
                active_ips=active_ips
            )

            topology["advertencias"] = advertencias
            topology["devices"] = dispositivos

            return {"status": "ok", "dispositivos": dispositivos, "target": ip_real, "topology": topology}
        finally:
            with _active_scan_count_lock:
                _active_scan_count -= 1
                _last_active_time = time.time()
                restantes = _active_scan_count
            if restantes == 0:
                print("[PassiveScanDaemon] Fase discover finalizada. Reanudando ciclos de fondo si no hay deep-scans pendientes.")




    def deep_scan(self, ip: str, user_id: str = "", scan_id: str = ""):
        global _active_scan_count, _active_scan_count_lock, _last_active_time
        global _deep_scan_active_count, _deep_scan_start_time, _deep_scan_lock
        
        with _active_scan_count_lock:
            _active_scan_count += 1
            _last_active_time = time.time()
            
        with _deep_scan_lock:
            _deep_scan_active_count += 1
            if _deep_scan_active_count == 1:
                _deep_scan_start_time = time.perf_counter()
        try:
            self._log(f"====== INICIANDO ESCANEO PARA: {ip} (user: {user_id}, scan: {scan_id}) ======")
            
            cached_data = _passive_device_cache.get(ip)
            es_recuperado_cache = False
            
            if cached_data:
                esperas = 0
                while cached_data.get("deep_scan_status") == "scanning" and esperas < 60:
                    self._log(f"⏳ [DEEP-SCAN] {ip} está siendo analizado por el demonio pasivo. Sincronizando relevo...")
                    time.sleep(1)
                    esperas += 1
                
                if cached_data.get("deep_scan_status") == "completed":
                    self._log(f"[DEEP-SCAN] ✅ {ip} recuperado de caché pasiva instantáneamente.")
                    puertos = cached_data.get("puertos_abiertos", [])
                    total_vulnerabilidades = cached_data.get("total_vulnerabilidades", 0)
                    mac_real = cached_data.get("mac", "Desconocida")
                    fabricante_info = cached_data.get("fabricante", "Desconocido")
                    hostname_info = cached_data.get("hostname", "")
                    es_recuperado_cache = True
            
            if not es_recuperado_cache:
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
                fabricante_info = puertos_info.get("fabricante", "Desconocido")
                hostname_info = puertos_info.get("hostname", "")

            id_unico = mac_real if mac_real != "Desconocida" else ip
            
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
                    "fabricante": fabricante_info
                }, user_id)
            else:
                datos_historial = doc_snap.to_dict()
                primera_conexion = datos_historial.get("primera_conexion", hora_actual)
                
            max_score = 0
            for puerto in puertos:
                for v in puerto.get("vulnerabilidades", []):
                    v_score = v.get("score", 0)
                    if v_score > max_score:
                        max_score = v_score
 
            documento = {
                "ip": ip,
                "mac": mac_real,
                "hostname": hostname_info,
                "fabricante": fabricante_info,
                "puertos_abiertos": puertos,
                "total_vulnerabilidades": total_vulnerabilidades,
                "max_score": max_score,
                "fecha_auditoria": hora_actual,
                "estado": "Completado",
                "es_nuevo": es_nuevo,
                "primera_conexion": primera_conexion,
                "scan_id": scan_id
            }
            
            self.db_service.save_device(ip, documento, user_id)
            
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

        finally:
            with _active_scan_count_lock:
                _active_scan_count -= 1
                _last_active_time = time.time()
                restantes = _active_scan_count
                
            with _deep_scan_lock:
                _deep_scan_active_count -= 1
                es_ultimo_deep = (_deep_scan_active_count == 0)
                deep_start = _deep_scan_start_time
                
            if es_ultimo_deep:
                elapsed_deep = time.perf_counter() - deep_start
                self._log(f"[DEEP-SCAN TOTAL] ✅ Todos los dispositivos escaneados en {elapsed_deep:.2f}s")
                if scan_id and user_id:
                    self.db_service.update_scan_metadata(user_id, scan_id, {
                        "end_time": datetime.datetime.utcnow().isoformat(),
                        "status": "completed"
                    })
                
            if restantes == 0:
                print("[PassiveScanDaemon] Todos los deep-scans finalizados. Reanudando ciclos de fondo.")
