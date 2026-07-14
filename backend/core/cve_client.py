import requests
import time
import json
import datetime
from core.local_db import LocalDBManager

class CVEClient:
    """
    Cliente HTTP que consulta la API pública del NVD (National Vulnerability Database)
    del gobierno de Estados Unidos para buscar vulnerabilidades conocidas (CVEs)
    asociadas a un software y versión específicos.
    
    API Oficial: https://services.nvd.nist.gov/rest/json/cves/2.0
    """
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def buscar_vulnerabilidades(self, nombre_servicio: str, version: str) -> list:
        """
        Recibe el nombre de un servicio (ej: 'apache') y su versión (ej: '2.4.49')
        y consulta la base de datos mundial NVD para encontrar CVEs asociados.
        
        Retorna una lista de diccionarios con las vulnerabilidades encontradas.
        """
        if not version or version.strip() == "":
            return []
        
        keyword = f"{nombre_servicio} {version}".strip()
        
        try:
            local_db = LocalDBManager()
            cache_rows = local_db.execute_read(
                "SELECT cves_json FROM cve_cache WHERE keyword = ?", (keyword,)
            )
            if cache_rows:
                print(f"📦 [CVE CACHE] hit local para '{keyword}'")
                return json.loads(cache_rows[0]["cves_json"])
        except Exception as e:
            print(f"[CVE CACHE ERROR] Falló lectura de caché local: {e}")

        parametros = {
            "keywordSearch": keyword,
            "resultsPerPage": 5  # Limitamos a 5 resultados para no saturar la respuesta
        }
        
        try:
            print(f"🔍 Consultando NVD para: {keyword}...")
            
            time.sleep(1.5)
            
            respuesta = requests.get(self.BASE_URL, params=parametros, timeout=30)
            
            if respuesta.status_code != 200:
                print(f"⚠️ NVD respondió con código {respuesta.status_code}")
                return []
            
            datos = respuesta.json()
            vulnerabilidades = []
            
            for item in datos.get("vulnerabilities", []):
                cve_data = item.get("cve", {})
                
                cve_id = cve_data.get("id", "Desconocido")
                
                descripciones = cve_data.get("descriptions", [])
                descripcion = "Sin descripción"
                for desc in descripciones:
                    if desc.get("lang") == "en":
                        descripcion = desc.get("value", "Sin descripción")
                        break
                
                severidad = "No disponible"
                score = 0.0
                metricas = cve_data.get("metrics", {})
                
                metricas_v3 = metricas.get("cvssMetricV31", metricas.get("cvssMetricV30", []))
                metricas_v2 = metricas.get("cvssMetricV2", [])
                
                if metricas_v3:
                    cvss_data = metricas_v3[0].get("cvssData", {})
                    score = cvss_data.get("baseScore", 0.0)
                    severidad = cvss_data.get("baseSeverity", "No disponible")
                elif metricas_v2:
                    cvss_data = metricas_v2[0].get("cvssData", {})
                    score = cvss_data.get("baseScore", 0.0)
                    severidad = metricas_v2[0].get("baseSeverity", "")
                    if not severidad:
                        if score >= 7.0: severidad = "HIGH"
                        elif score >= 4.0: severidad = "MEDIUM"
                        else: severidad = "LOW"
                
                vulnerabilidades.append({
                    "cve_id": cve_id,
                    "descripcion": descripcion,
                    "severidad": severidad,
                    "score": score
                })
            
            print(f"✅ Se encontraron {len(vulnerabilidades)} CVEs para '{keyword}'")
            
            try:
                local_db.execute_write(
                    "INSERT OR REPLACE INTO cve_cache (keyword, cves_json, cached_at) VALUES (?, ?, ?)",
                    (keyword, json.dumps(vulnerabilidades), datetime.datetime.utcnow().isoformat())
                )
            except Exception as ex:
                print(f"[CVE CACHE ERROR] Falló escritura de caché local: {ex}")
                
            return vulnerabilidades
            
        except requests.exceptions.Timeout:
            print(f"⏰ Timeout al consultar NVD para '{keyword}'")
            return []
        except Exception as e:
            print(f"❌ Error consultando NVD: {str(e)}")
            return []
