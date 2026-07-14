import nmap
import subprocess
import socket
import re
import ipaddress
import time

import threading
_thread_local = threading.local()

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def get_local_cidr():
    ip = get_local_ip()
    if ip != '127.0.0.1':
        parts = ip.split('.')
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return "192.168.1.0/24"

def get_local_mac():
    import uuid
    return ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0,2*6,2)][::-1]).upper()

class ScannerEngine:
    def __init__(self):
        # python-nmap intentará buscar el ejecutable "nmap" en el PATH de Windows o en su ruta base
        self.reload_engine()

    def _log(self, msg: str):
        print(msg)
        cb = getattr(_thread_local, 'log_cb', None)
        if cb:
            cb(msg)

    def reload_engine(self):
        try:
            self.nm = nmap.PortScanner(nmap_search_path=('nmap', r'C:\Program Files (x86)\Nmap\nmap.exe', r'C:\Program Files\Nmap\nmap.exe'))
            self.nmap_installed = True
            return True
        except nmap.PortScannerError:
            self.nmap_installed = False
            self.nm = None
            self._log("Soft Error: Nmap no detectado. El sistema requerirá instalación autónoma.")
            return False

    def _is_private_ip(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private
        except ValueError:
            return False

    def _get_mac_from_arp(self, ip_target: str) -> str:
        """Intenta obtener la MAC de una IP mediante el comando arp -a local."""
        try:
            arp_output = subprocess.check_output(['arp', '-a', ip_target], shell=True).decode('cp1252', errors='ignore')
            for line in arp_output.split('\n'):
                parts = line.split()
                if len(parts) >= 2 and parts[0] == ip_target:
                    mac = parts[1].replace('-', ':').upper()
                    if mac != 'FF:FF:FF:FF:FF:FF':
                        return mac
        except Exception:
            pass
        return "Desconocida"

    def fallback_to_gateway(self, extra_warning=None) -> dict:
        """Obtiene la Puerta de Enlace Predeterminada de Windows como fallback si el traceroute falla."""
        self._log("  [Fallback] Usando ipconfig para extraer el Default Gateway...")
        advertencias = ["Se ejecutó Fallback de Puerta de Enlace debido a falta de permisos o bloqueo de red."]
        if extra_warning:
            advertencias.append(extra_warning)
            
        try:
            output = subprocess.check_output('ipconfig', shell=True).decode('cp1252', errors='ignore')
            for line in output.split('\n'):
                if 'Puerta de enlace predeterminada' in line or 'Default Gateway' in line:
                    match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                    if match:
                        ip = match.group(0)
                        return {
                            "hops_privados": [{
                                "ip": ip,
                                "mac": self._get_mac_from_arp(ip),
                                "tipo": "router_principal",
                                "hostname": "Router Principal (C)"
                            }],
                            "router_isp": None,
                            "advertencias": advertencias
                        }
        except Exception as e:
            self._log(f"  [Fallback Error] No se pudo obtener gateway: {e}")
            
        return {"hops_privados": [], "router_isp": None, "advertencias": advertencias}

    def fase1_traceroute(self) -> dict:
        """
        FASE 1: Ejecuta traceroute hacia 8.8.8.8 para descubrir el 'esqueleto' de la red.
        Retorna:
            - hops_privados: Nodos internos (ej. Extensores, Router Principal).
            - router_isp: Primer salto con IP pública (Internet).
        """
        self._log("[FASE 1] Iniciando Nmap Traceroute hacia 8.8.8.8 para descubrir la columna vertebral...")
        _t_fase1 = time.perf_counter()
        hops_privados = []
        router_isp = None
        advertencias = []
        
        try:
            # Reemplazamos tracert por nmap con un timeout estricto de 30s.
            # -T2 (Polite): seguro en redes institucionales; evita que switches bloqueen la IP del escáner.
            result = subprocess.run(
                ['nmap', '--traceroute', '-sn', '-T2', '8.8.8.8'], 
                capture_output=True, text=True, timeout=30
            )
            
            # Revisar si falló por permisos (stderr tiene contenido de error)
            if result.returncode != 0 and result.stderr:
                self._log(f"  [Nmap Error] Falta de permisos o error: {result.stderr.strip()}")
                return self.fallback_to_gateway()
                
            output = result.stdout
            
            # Buscar el inicio del bloque TRACEROUTE
            if "TRACEROUTE" not in output:
                self._log("  [Nmap Error] El bloque TRACEROUTE no se encontró en la salida.")
                return self.fallback_to_gateway("El comando Nmap falló o no retornó un bloque TRACEROUTE válido.")
                
            traceroute_block = output.split("TRACEROUTE")[1]
            ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
            
            for line in traceroute_block.splitlines():
                line = line.strip()
                if not line or "HOP" in line:
                    continue
                    
                # Detectar nodos invisibles de Nmap ("4   ... 6")
                if "..." in line:
                    parts = line.split("...")
                    try:
                        start_hop = int(parts[0].strip())
                        end_hop = int(parts[1].strip())
                        for h in range(start_hop, end_hop + 1):
                            hops_privados.append({
                                "ip": "unknown",
                                "tipo": "invisible",
                                "rtt_ms": None,
                                "hostname": "Hop Invisible (Bloqueado)"
                            })
                            if "Se detectaron saltos invisibles o bloqueos de ICMP en la ruta." not in advertencias:
                                advertencias.append("Se detectaron saltos invisibles o bloqueos de ICMP en la ruta.")
                            self._log("  -> [HOP INVISIBLE] (ICMP Bloqueado / Tiempo Agotado)")
                    except Exception:
                        pass
                    continue
                
                # Detectar nodos invisibles de tracert ("* * *")
                if "*    *    *" in line or "* * *" in line:
                    hops_privados.append({
                        "ip": "unknown",
                        "tipo": "invisible",
                        "rtt_ms": None,
                        "hostname": "Hop Invisible (Bloqueado)"
                    })
                    if "Se detectaron saltos invisibles o bloqueos de ICMP en la ruta." not in advertencias:
                        advertencias.append("Se detectaron saltos invisibles o bloqueos de ICMP en la ruta.")
                    self._log("  -> [HOP INVISIBLE] (ICMP Bloqueado / Tiempo Agotado)")
                    continue
                    
                # Extraemos IPs en la línea
                match = ip_pattern.search(line)
                if match:
                    ip = match.group(0)
                    
                    if ip == '8.8.8.8':
                        continue
                        
                    if self._is_private_ip(ip):
                        mac = self._get_mac_from_arp(ip)
                        
                        # Sprint 4: Detectar si el hop está en una subred diferente (Doble NAT)
                        nat_habilitado = False
                        try:
                            local_cidr = get_local_cidr()
                            nat_habilitado = not (ipaddress.ip_address(ip) in ipaddress.ip_network(local_cidr, strict=False))
                            if nat_habilitado and "Se detectó Doble NAT en uno o más extensores, posibles subredes ocultas." not in advertencias:
                                advertencias.append("Se detectó Doble NAT en uno o más extensores, posibles subredes ocultas.")
                        except Exception:
                            pass
                            
                        hops_privados.append({
                            "ip": ip,
                            "mac": mac,
                            "tipo": "extensor", # Todos inician como extensor hasta llegar al final
                            "hostname": "Extensor / Router Intermedio",
                            "nat_habilitado": nat_habilitado
                        })
                        self._log(f"  -> [HOP PRIVADO] {ip} (MAC: {mac}) {'[NAT DETECTADO]' if nat_habilitado else ''}")
                    else:
                        router_isp = {"ip": ip, "tipo": "router_isp", "hostname": "ISP Público"}
                        self._log(f"  -> [HOP PÚBLICO - ISP] {ip} (Fin de la red local)")
                        break
                        
        except subprocess.TimeoutExpired:
            self._log("  [Traceroute] Timeout de 30s expirado.")
            return self.fallback_to_gateway()
        except Exception as e:
            self._log(f"  [Traceroute] Excepción crítica: {e}")
            return self.fallback_to_gateway()
            
        # Sprint 3: Fallback si por alguna razón la lista quedó vacía pero Nmap corrió
        # Esto pasa si hay un switch no administrado y Nmap saltó directo a Internet sin ver el router local.
        if not hops_privados:
            return self.fallback_to_gateway("La topología está ciega (posible switch pasivo). Se activó el Fallback.")
            
        # El Router Principal (C) es el último salto (sea invisible o con IP) antes de salir a Internet
        if hops_privados:
            hops_privados[-1]["hostname"] = "Router Principal (C)"
            hops_privados[-1]["tipo"] = "router_principal"
            
        _elapsed_fase1 = time.perf_counter() - _t_fase1
        self._log(f"[FASE 1] ✅ Completada en {_elapsed_fase1:.2f}s")
        return {
            "hops_privados": hops_privados,
            "router_isp": router_isp,
            "advertencias": advertencias
        }
    
    # ─────────────────────────────────────────────────────────────────────────
    # FASE 2: DESCUBRIMIENTO EN CASCADA (SNMP → DHCP → NMAP)
    # ─────────────────────────────────────────────────────────────────────────

    def _parse_snmp_output(self, output: str, parent_ip: str, method: str) -> list:
        """Extrae pares IP+MAC de la salida de los scripts snmp-interfaces / snmp-arp de Nmap."""
        devices = []
        found_ips = set()
        ip_pattern  = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        mac_pattern = re.compile(r'(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}')

        # El script snmp-interfaces lista IPs por adaptador; snmp-arp lista
        # la tabla ARP. Ambos tienen formato clave: valor.
        current_ip  = None
        current_mac = None

        for line in output.splitlines():
            line = line.strip()
            ip_match  = ip_pattern.search(line)
            mac_match = mac_pattern.search(line)

            if ip_match:
                candidate = ip_match.group(0)
                if self._is_private_ip(candidate) and candidate != parent_ip:
                    current_ip = candidate
            if mac_match:
                current_mac = mac_match.group(0).upper().replace('-', ':')

            # Cuando tenemos ambos datos en líneas próximas, los guardamos
            if current_ip and current_mac and current_ip not in found_ips:
                devices.append({
                    "ip": current_ip,
                    "mac": current_mac,
                    "hostname": "",
                    "vendor": "",
                    "discovery_method": method,
                    "parent_ip": parent_ip
                })
                found_ips.add(current_ip)
                current_ip  = None
                current_mac = None

        return devices

    def _intento_snmp(self, target_ip: str, network_range: str, advertencias: list) -> list:
        """
        Intento 1: SNMP nativo vía pysnmp.
        Consulta la tabla ARP (ipNetToMediaPhysAddress) con OID '1.3.6.1.2.1.4.22.1.2'.
        Timeout estricto de 3 s; si no responde, añade advertencia y retorna [].
        """
        self._log(f"  [Fase 2 - Intento 1] SNMP Nativo (pysnmp) sobre {target_ip}...")
        _t_snmp = time.perf_counter()
        
        try:
            from pysnmp.hlapi import (
                SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
                ObjectType, ObjectIdentity, nextCmd
            )
        except ImportError as e:
            msg = f"Librería pysnmp no instalada. Fallando al fallback. Error: {e}"
            advertencias.append(msg)
            self._log(f"  [SNMP Error] {msg}")
            return []

        devices = []
        found_ips = set()
        communities = ["public", "private"]
        
        for community in communities:
            self._log(f"    -> Probando comunidad '{community}'...")
            try:
                # OID: ipNetToMediaPhysAddress (1.3.6.1.2.1.4.22.1.2)
                # Formato devuelto: 1.3.6.1.2.1.4.22.1.2.[ifIndex].[IP] = [MAC en bytes]
                for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                    SnmpEngine(),
                    CommunityData(community),
                    UdpTransportTarget((target_ip, 161), timeout=3.0, retries=1),
                    ContextData(),
                    ObjectType(ObjectIdentity('1.3.6.1.2.1.4.22.1.2')),
                    lexicographicMode=False
                ):
                    if errorIndication:
                        # Error de transporte / timeout / puerto cerrado
                        break
                    if errorStatus:
                        # Error SNMP (noSuchName, etc.)
                        break
                    
                    for varBind in varBinds:
                        oid = varBind[0].prettyPrint()
                        val = varBind[1]
                        
                        # Extraer la IP del final del OID (los últimos 4 componentes octetos)
                        parts = oid.split('.')
                        if len(parts) >= 4:
                            candidate_ip = ".".join(parts[-4:])
                            # Validar que es una IP privada y no es el router mismo
                            if self._is_private_ip(candidate_ip) and candidate_ip != target_ip:
                                # Convertir MAC en bytes a formato estándar XX:XX:XX:XX:XX:XX
                                try:
                                    raw_bytes = val.asOctets()
                                    if len(raw_bytes) == 6:
                                        mac_str = ":".join(f"{b:02X}" for b in raw_bytes)
                                    else:
                                        mac_str = val.prettyPrint().upper().replace('-', ':')
                                        if mac_str.startswith("0X"):
                                            hex_val = mac_str[2:]
                                            mac_str = ":".join(hex_val[i:i+2] for i in range(0, len(hex_val), 2))
                                except Exception:
                                    mac_str = "Desconocida"
                                    
                                if candidate_ip not in found_ips:
                                    devices.append({
                                        "ip": candidate_ip,
                                        "mac": mac_str,
                                        "hostname": "",
                                        "vendor": "",
                                        "discovery_method": "snmp_arp",
                                        "parent_ip": target_ip
                                    })
                                    found_ips.add(candidate_ip)
                
                if devices:
                    self._log(f"  [SNMP] Éxito: {len(devices)} dispositivos extraídos con comunidad '{community}'.")
                    return devices
                    
            except Exception as e:
                self._log(f"    [SNMP] Error con comunidad '{community}': {e}")
                
        msg = f"SNMP sin respuesta o bloqueado en {target_ip} con comunidades comunes."
        advertencias.append(msg)
        self._log(f"  [SNMP] {msg} ({time.perf_counter() - _t_snmp:.2f}s)")
        return []

    def _intento_dhcp_server(self, network_range: str, advertencias: list) -> list:
        """
        Intento 2: Buscar servidor DHCP (UDP 67) en la subred y consultar SNMP sobre él.
        Timeout: 10 s para el barrido DHCP + 10 s para el SNMP.
        """
        self._log(f"  [Fase 2 - Intento 2] Buscando servidor DHCP en {network_range}...")
        _t_dhcp = time.perf_counter()
        try:
            dhcp_result = subprocess.run(
                ['nmap', '-sU', '-p', '67', '-T2', network_range],
                capture_output=True, text=True, timeout=10
            )
            dhcp_output = dhcp_result.stdout

            # Extraer IPs con el puerto 67 abierto
            ip_pattern = re.compile(r'Nmap scan report for ([\d\.]+)')
            state_pattern = re.compile(r'67/udp\s+open')

            dhcp_server_ip = None
            current_ip = None
            for line in dhcp_output.splitlines():
                ip_match = ip_pattern.search(line)
                if ip_match:
                    current_ip = ip_match.group(1)
                if state_pattern.search(line) and current_ip:
                    dhcp_server_ip = current_ip
                    break

            if not dhcp_server_ip:
                msg = f"No se encontró servidor DHCP activo en {network_range}."
                advertencias.append(msg)
                self._log(f"  [DHCP] {msg}")
                return []

            self._log(f"  [DHCP] Servidor DHCP encontrado en {dhcp_server_ip}. Consultando SNMP...")
            devices = self._intento_snmp(dhcp_server_ip, network_range, advertencias)
            # Reemplazar method tag
            for d in devices:
                d["discovery_method"] = "dhcp_server"
            return devices

        except subprocess.TimeoutExpired:
            msg = f"Timeout buscando servidor DHCP en {network_range}."
            advertencias.append(msg)
            self._log(f"  [DHCP] {msg} ({time.perf_counter() - _t_dhcp:.2f}s)")
            return []
        except Exception as e:
            msg = f"Error buscando servidor DHCP: {e}"
            advertencias.append(msg)
            self._log(f"  [DHCP] {msg}")
            return []

    def _intento_nmap_fallback(self, network_range: str, parent_ip: str, active_ips: list = None) -> list:
        """
        Intento 3: ARP cache local (siempre funciona sin admin) + Nmap como complemento.
        En Windows, -PR (ARP raw socket) requiere admin y falla silenciosamente.
        Por eso el ARP cache es la fuente primaria y Nmap el complemento.
        """
        self._log(f"  [Fase 2 - Intento 3] Fallback ARP Cache + Nmap en {network_range}...")
        _t_nmap = time.perf_counter()

        discovered = []
        found_ips  = set()
        prefix = network_range.split('/')[0].rsplit('.', 1)[0] + '.'
        self._log(f"  [ARP] Prefijo de subred buscado: '{prefix}'")

        # ── Fuente 1: ARP Cache local (no requiere admin, siempre disponible) ──
        try:
            arp_output = subprocess.check_output('arp -a', shell=True).decode('cp1252', errors='ignore')
            arp_lines = arp_output.split('\n')
            self._log(f"  [ARP] Total líneas en caché ARP: {len(arp_lines)}")

            for line in arp_lines:
                parts = line.split()
                if len(parts) >= 2:
                    ip_arp  = parts[0].strip()
                    mac_arp = parts[1].strip().replace('-', ':').upper()
                    if (ip_arp.startswith(prefix)
                            and ip_arp not in found_ips
                            and not ip_arp.endswith('.255')
                            and mac_arp not in ('FF:FF:FF:FF:FF:FF', 'FF-FF-FF-FF-FF-FF')
                            and len(mac_arp) == 17):
                        self._log(f"  [ARP] Encontrado: {ip_arp} ({mac_arp})")
                        # Intentar resolver hostname via DNS inverso
                        hostname = ""
                        try:
                            hostname = socket.gethostbyaddr(ip_arp)[0]
                        except Exception:
                            pass
                        discovered.append({
                            "ip": ip_arp,
                            "mac": mac_arp,
                            "hostname": hostname or "Caché Local ARP",
                            "vendor": "",
                            "discovery_method": "arp_cache",
                            "parent_ip": parent_ip
                        })
                        found_ips.add(ip_arp)
        except Exception as e:
            self._log(f"  [ARP] Error leyendo caché ARP: {e}")

        self._log(f"  [ARP] Dispositivos encontrados en caché ARP: {len(discovered)}")

        # ── Fuente 2: Nmap sin raw sockets (descubrimiento clásico ICMP ping sweep) ──
        # -sn -PE: usa ICMP echo. Funciona de manera limpia, rápida y no intrusiva sin saturar la red institucional.
        # -T3: Velocidad normal estandarizada.
        try:
            if active_ips:
                targets = [ip for ip in active_ips if ip.startswith(prefix)]
                if parent_ip and parent_ip != "unknown" and parent_ip not in targets and parent_ip.startswith(prefix):
                    targets.append(parent_ip)
                if targets:
                    hosts_arg = " ".join(targets)
                    self._log(f"  [Nmap] Acelerando escaneo activo usando caché del demonio pasivo ({len(targets)} IPs)...")
                else:
                    hosts_arg = network_range
                    self._log(f"  [Nmap] No se encontraron IPs en caché para esta subred. Barriendo rango completo...")
            else:
                hosts_arg = network_range
                self._log(f"  [Nmap] Complementando con ping sweep clásico ICMP (-sn -PE -T3)...")

            self.nm.scan(
                hosts=hosts_arg, 
                arguments='-sn -PE -T3'
            )

            for host in self.nm.all_hosts():
                if self.nm[host]['status']['state'] == 'up' and host not in found_ips:
                    mac = "Desconocida"
                    if 'mac' in self.nm[host]['addresses']:
                        mac = self.nm[host]['addresses']['mac']
                    if host == get_local_ip() and mac == "Desconocida":
                        mac = get_local_mac()
                    self._log(f"  [Nmap] Encontrado por descubrimiento híbrido: {host}")
                    discovered.append({
                        "ip": host,
                        "mac": mac,
                        "hostname": self.nm[host].hostname(),
                        "vendor": self.nm[host]['vendor'].get(mac, "") if mac != "Desconocida" else "",
                        "discovery_method": "nmap_scan",
                        "parent_ip": parent_ip
                    })
                    found_ips.add(host)
        except Exception as e:
            self._log(f"  [Nmap] Error en descubrimiento híbrido: {e}")

        # Agregar la propia PC si no fue detectada
        local_ip = get_local_ip()
        if local_ip not in found_ips and local_ip.startswith(prefix):
            self._log(f"  [LOCAL] Agregando PC local: {local_ip}")
            discovered.append({
                "ip": local_ip,
                "mac": get_local_mac(),
                "hostname": socket.gethostname(),
                "vendor": "",
                "discovery_method": "local",
                "parent_ip": parent_ip
            })

        self._log(f"  [Fase 2 - Intento 3] ✅ Completado en {time.perf_counter() - _t_nmap:.2f}s | Total dispositivos descubiertos: {len(discovered)}")
        return discovered


    def discover_network(self, network_range: str,
                         router_principal_ip: str = None,
                         advertencias: list = None,
                         active_ips: list = None) -> list:
        """
        FASE 2: Cascada de descubrimiento de dispositivos.
        Orden: SNMP (router principal) → SNMP (servidor DHCP) → Nmap fallback.
        Cada dispositivo retornado incluye los campos:
            ip, mac, hostname, vendor, discovery_method, parent_ip
        """
        if advertencias is None:
            advertencias = []
        parent_ip = router_principal_ip or network_range.split('/')[0]

        self._log(f"[FASE 2] Iniciando descubrimiento en cascada. Red: {network_range} | Router: {parent_ip}")
        _t_fase2 = time.perf_counter()

        # ── Intento 1: SNMP sobre el router principal ──────────────────────────
        snmp_exitosa = False
        if router_principal_ip and router_principal_ip != "unknown":
            devices = self._intento_snmp(router_principal_ip, network_range, advertencias)
            if devices:
                return devices
            snmp_exitosa = False
        else:
            snmp_exitosa = False

        # Comprobar si estamos escaneando una subred remota (detrás de un salto / NAT)
        es_subred_externa = False
        try:
            local_cidr = get_local_cidr()
            if ipaddress.ip_network(network_range, strict=False) != ipaddress.ip_network(local_cidr, strict=False):
                es_subred_externa = True
        except Exception:
            pass

        # Si es una subred externa y el SNMP falló, advertimos pero NO abortamos para permitir fallback de Nmap.
        if es_subred_externa and not snmp_exitosa:
            msg = f"Aviso de Red en {parent_ip}: La subred externa {network_range} no responde a SNMP. Continuando con escaneo de descubrimiento Nmap fallback."
            advertencias.append(msg)
            self._log(f"  [AVISO] {msg}")

        # ── Intento 2: Buscar servidor DHCP y consultar SNMP sobre él ─────────
        devices = self._intento_dhcp_server(network_range, advertencias)
        if devices:
            return devices

        # ── Intento 3: Nmap ping sweep híbrido (fallback local garantizado) ────
        advertencias.append("SNMP y DHCP fallaron — usando descubrimiento híbrido Nmap como último recurso.")
        result = self._intento_nmap_fallback(network_range, parent_ip, active_ips=active_ips)
        self._log(f"[FASE 2] ✅ Completada en {time.perf_counter() - _t_fase2:.2f}s")
        return result


    def scan_ports(self, ip_target: str) -> dict:
        """
        Escaneo profundo (Opción A): Busca puertos abiertos y descubre qué programas corren adentro.
        """
        self._log(f"Iniciando escaneo profundo en: {ip_target}...")
        _t_deep = time.perf_counter()
        # -sV: descubrir la versión exacta del servicio.
        # --version-intensity 2: Detección rápida y ligera.
        # -T4: velocidad agresiva.
        # --top-ports 100: los 100 puertos más comunes.
        # --max-retries 1: no reintentar puertos cerrados.
        # --host-timeout 45s: Evita bloqueos en dispositivos lentos o filtrados.
        self.nm.scan(hosts=ip_target, arguments='-sV --version-intensity 2 -T4 --top-ports 100 --max-retries 1 --host-timeout 45s')
        
        if ip_target not in self.nm.all_hosts():
            return {"ip": ip_target, "puertos": []}
            
        puertos_descubiertos = []
        puertos_bloqueados = []
        
        # Razones técnicas de por qué un puerto aparece como filtrado
        RAZONES_FILTRADO = {
            "filtered": "Bloqueado por firewall — los paquetes de sondeo son descartados sin respuesta (DROP rule activa)",
            "closed":   "Puerto cerrado — el sistema responde con TCP RST, confirmando que no hay servicio activo",
            "open|filtered": "Ambiguo — el host no respondió al sondeo UDP/TCP; posible firewall stateless o pérdida de paquetes",
        }
        
        # Si encuentra puertos TCP
        if 'tcp' in self.nm[ip_target]:
            for port in self.nm[ip_target]['tcp'].keys():
                port_data = self.nm[ip_target]['tcp'][port]
                state = port_data['state']
                if state == 'open':
                    puertos_descubiertos.append({
                        "puerto": port,
                        "protocolo": "TCP",
                        "servicio": port_data['name'],
                        "version": port_data['version']
                    })
                elif state in ('filtered', 'closed', 'open|filtered'):
                    puertos_bloqueados.append({
                        "puerto": port,
                        "protocolo": "TCP",
                        "servicio": port_data['name'] or "desconocido",
                        "estado": state,
                        "razon": RAZONES_FILTRADO.get(state, f"Estado desconocido: {state}")
                    })
                    
        mac = self.nm[ip_target]['addresses'].get('mac', 'Desconocida')
        
        # --- SUPLEMENTO MAC LOCAL ---
        if ip_target == get_local_ip() and mac == 'Desconocida':
            mac = get_local_mac()
        # --- FIN SUPLEMENTO MAC LOCAL ---
        
        # Intentamos obtener el fabricante a partir de la MAC usando la base de Nmap
        fabricante = "Desconocido"
        if 'vendor' in self.nm[ip_target] and mac in self.nm[ip_target]['vendor']:
            fabricante = self.nm[ip_target]['vendor'][mac]
            
        hostname = self.nm[ip_target].hostname() if hasattr(self.nm[ip_target], 'hostname') else ""
        
        # Fallback 1: DNS inverso con socket (funciona para routers y PCs bien configuradas)
        if not hostname:
            try:
                hostname = socket.gethostbyaddr(ip_target)[0]
                self._log(f"[DNS] Hostname resuelto para {ip_target}: {hostname}")
            except Exception:
                pass
        
        # Fallback 2: NetBIOS via nbtstat -A (para PCs Windows en la misma LAN)
        if not hostname:
            try:
                result = subprocess.run(
                    ['nbtstat', '-A', ip_target],
                    capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.splitlines():
                    # Buscamos la línea con <00> que es el nombre del equipo
                    if '<00>' in line and 'UNIQUE' in line:
                        hostname = line.strip().split()[0].strip()
                        self._log(f"[NetBIOS] Hostname resuelto para {ip_target}: {hostname}")
                        break
            except Exception:
                pass
            
        # Loguear resumen de puertos en la consola de auditoría
        if puertos_descubiertos:
            self._log(f"[PUERTOS ABIERTOS] {ip_target}: {len(puertos_descubiertos)} servicio(s) expuesto(s):")
            for p in puertos_descubiertos:
                ver = f" ({p['version']}" + ")" if p['version'] else ""
                self._log(f"  [ABIERTO]   TCP/{p['puerto']}  {p['servicio'].upper()}{ver}")
        else:
            self._log(f"[PUERTOS ABIERTOS] {ip_target}: Sin servicios expuestos detectados en top-100 puertos.")

        if puertos_bloqueados:
            self._log(f"[PUERTOS BLOQUEADOS] {ip_target}: {len(puertos_bloqueados)} puerto(s) con acceso restringido:")
            for p in puertos_bloqueados:
                self._log(f"  [BLOQUEADO] TCP/{p['puerto']}  {p['servicio'].upper() if p['servicio'] else 'N/A'}  — {p['razon']}")
        
        _elapsed_deep = time.perf_counter() - _t_deep
        self._log(f"[DEEP-SCAN] Completado {ip_target} en {_elapsed_deep:.2f}s | Abiertos: {len(puertos_descubiertos)} | Bloqueados: {len(puertos_bloqueados)}")
        return {
            "ip": ip_target,
            "mac": mac,
            "hostname": hostname,
            "fabricante": fabricante,
            "puertos_abiertos": puertos_descubiertos,
            "puertos_bloqueados": puertos_bloqueados
        }
