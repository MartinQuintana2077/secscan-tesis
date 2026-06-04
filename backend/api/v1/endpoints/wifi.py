from fastapi import APIRouter, Depends, HTTPException, Body
from api.deps import get_current_user
import subprocess
import re
import os
import tempfile
import uuid

router = APIRouter()

def scan_wifi_networks():
    result = ""
    try:
        # Intentamos obtener la información detallada con Bssid para sacar el porcentaje de señal
        result = subprocess.check_output(
            "netsh wlan show networks mode=Bssid",
            shell=True,
            stderr=subprocess.DEVNULL
        ).decode("cp1252", errors="ignore")
    except Exception as e:
        print(f"Error scanning WiFi with Bssid: {e}")
        try:
            # Fallback simple
            result = subprocess.check_output(
                "netsh wlan show networks",
                shell=True,
                stderr=subprocess.DEVNULL
            ).decode("cp1252", errors="ignore")
        except Exception:
            # Fallback si no hay adaptador o servicio wlansvc está desactivado
            return []

    # Impresión de diagnóstico para ver el output real en la consola de la notebook
    print("\n--- [DEBUG NETSH WIFI RAW OUTPUT] ---")
    print(result)
    print("-------------------------------------\n")

    networks = []
    current_net = {}
    
    for line in result.split("\n"):
        line = line.strip()
        if not line:
            continue
        
        # Match SSID [Número] : [Nombre SSID] con límites de palabra (\b) para evitar matching con BSSID
        ssid_match = re.search(r"\bSSID\s+\d+\s*:\s*(.*)$", line, re.IGNORECASE)
        if ssid_match:
            if current_net and current_net.get("ssid"):
                networks.append(current_net)
            current_net = {
                "ssid": ssid_match.group(1).strip(),
                "auth": "Desconocida",
                "signal": 100
            }
            continue
            
        if not current_net:
            continue
            
        # Match Autenticación (Español o Inglés)
        auth_match = re.search(r"(?:Autenticación|Authentication)\s*:\s*(.*)$", line, re.IGNORECASE)
        if auth_match:
            current_net["auth"] = auth_match.group(1).strip()
            continue
            
        # Match Porcentaje de Señal (Español o Inglés)
        signal_match = re.search(r"(?:Señal|Signal)\s*:\s*(\d+)%", line, re.IGNORECASE)
        if signal_match:
            current_net["signal"] = int(signal_match.group(1))
            continue

    if current_net and current_net.get("ssid"):
        networks.append(current_net)
        
    # Filtrar SSIDs vacíos
    filtered = [n for n in networks if n.get("ssid")]
    print(f"[DEBUG PARSED NETWORKS] {filtered}")
    return filtered

def connect_to_wifi(ssid: str, password: str = None):
    temp_filepath = None
    try:
        if not password:
            # Plantilla XML para redes abiertas sin contraseña
            profile_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid}</name>
    <SSIDConfig>
        <SSID>
            <name>{ssid}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>open</authentication>
                <encryption>none</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
        </security>
    </MSM>
</WLANProfile>
"""
        else:
            # Plantilla XML estándar WPA2-Personal (AES)
            profile_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid}</name>
    <SSIDConfig>
        <SSID>
            <name>{ssid}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{password}</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>
"""
        
        # Guardar en un archivo temporal
        temp_dir = tempfile.gettempdir()
        temp_filename = f"secscan_wifi_{uuid.uuid4().hex}.xml"
        temp_filepath = os.path.join(temp_dir, temp_filename)
        
        with open(temp_filepath, "w", encoding="utf-8") as f:
            f.write(profile_xml)
            
        # Añadir perfil de red en Windows
        add_profile_cmd = f'netsh wlan add profile filename="{temp_filepath}" user=all'
        subprocess.check_output(add_profile_cmd, shell=True, stderr=subprocess.STDOUT)
        
        # Conectar a la red
        connect_cmd = f'netsh wlan connect name="{ssid}" ssid="{ssid}"'
        connect_output = subprocess.check_output(connect_cmd, shell=True, stderr=subprocess.STDOUT).decode("cp1252", errors="ignore")
        
        print(f"[WIFI] Conectando a {ssid}: {connect_output}")
        return True, "Conexión iniciada con éxito."
        
    except subprocess.CalledProcessError as e:
        error_msg = e.output.decode("cp1252", errors="ignore")
        print(f"[WIFI ERROR] Error en comando: {error_msg}")
        return False, error_msg
    except Exception as e:
        print(f"[WIFI ERROR] Error general: {str(e)}")
        return False, str(e)
    finally:
        # Asegurarse de eliminar el archivo XML temporal con la contraseña en texto plano
        if temp_filepath and os.path.exists(temp_filepath):
            try:
                os.remove(temp_filepath)
            except:
                pass

@router.get("/scan")
def get_wifi_networks(user: dict = Depends(get_current_user)):
    networks = scan_wifi_networks()
    # Si no detectamos redes (desarrollo en máquina virtual/PC escritorio), inyectamos mock data
    if not networks:
        return {
            "status": "ok",
            "networks": [
                {"ssid": "SecScan_Corporate_Secure", "auth": "WPA2-Personal", "signal": 95},
                {"ssid": "Lab_Vulnerabilities_IoT", "auth": "WPA2-Personal", "signal": 80},
                {"ssid": "Invitados_Libre", "auth": "Abierta", "signal": 65},
                {"ssid": "Linksys_Pruebas", "auth": "WPA2-Personal", "signal": 45}
            ],
            "mocked": True
        }
    return {"status": "ok", "networks": networks, "mocked": False}

@router.post("/connect")
def connect_wifi(
    ssid: str = Body(..., embed=True),
    password: str = Body(None, embed=True),
    user: dict = Depends(get_current_user)
):
    success, msg = connect_to_wifi(ssid, password)
    if success:
        return {"status": "ok", "mensaje": f"Petición de conexión a '{ssid}' enviada."}
    else:
        raise HTTPException(status_code=400, detail=f"No se pudo conectar a {ssid}: {msg}")
