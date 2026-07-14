import os
import urllib.request
import subprocess

def install_nmap_silently():
    """
    Descarga el instalador oficial de Nmap para Windows y lo ejecuta de forma desatendida.
    """
    nmap_url = "https://nmap.org/dist/nmap-7.95-setup.exe"
    installer_path = os.path.join(os.environ.get("TEMP", "C:\\temp"), "nmap_setup_secscan_temp.exe")
    
    try:
        print(f"Iniciando descarga de motor Nmap (30MB aprox)...")
        
        import requests
        response = requests.get(nmap_url, stream=True, timeout=30)
        response.raise_for_status()
        
        total_size = int(response.headers.get('content-length', 0))
        block_size = 1024 * 1024 # 1MB
        downloaded = 0
        
        with open(installer_path, 'wb') as f:
            for data in response.iter_content(block_size):
                f.write(data)
                downloaded += len(data)
                porcentaje = (downloaded / total_size) * 100 if total_size > 0 else 0
                print(f" >>> Descargando: {porcentaje:.1f}% ({downloaded / (1024*1024):.1f} MB)")

        print(f"Descarga finalizada en: {installer_path}")
        print("Solicitando elevación de privilegios para instalación asistida...")
        ps_command = f"Start-Process -FilePath '{installer_path}' -Verb RunAs -Wait"
        result = subprocess.run(["powershell", "-Command", ps_command], check=True)
        
        print("¡Proceso de instalación finalizado!")
        return True
    except Exception as e:
        print(f"Error grave auto-instalando Nmap: {e}")
        return False
    finally:
        if os.path.exists(installer_path):
            try:
                os.remove(installer_path)
            except:
                pass
