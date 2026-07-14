# SecScan — Network Vulnerability Scanner

Una herramienta full-stack de monitoreo de seguridad de red que escanea continuamente tu red local en busca de dispositivos conectados, puertos abiertos y vulnerabilidades conocidas (CVEs), desarrollada como proyecto de tesis universitaria.

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green?logo=fastapi)
![React](https://img.shields.io/badge/React-18-61DAFB?logo=react)
![Firebase](https://img.shields.io/badge/Firebase-Firestore-orange?logo=firebase)
![Nmap](https://img.shields.io/badge/Nmap-Required-red)

---

## Capturas de Pantalla

![Home](docs/screenshots/00_home.png)

| Dashboard — Historial de Escaneos | Resultados — Lista de Dispositivos |
|:---:|:---:|
| ![Dashboard](docs/screenshots/01_dashboard.png) | ![Devices](docs/screenshots/02_devices.png) |

| Consola de Auditoría | Reporte de Vulnerabilidades |
|:---:|:---:|
| ![Console](docs/screenshots/03_console.png) | ![Vulns](docs/screenshots/04_vulnerabilities.png) |

---

## Características

- **Network Discovery** — Detecta todos los dispositivos en la red local (IP, MAC, hostname, fabricante).
- **Deep Port Scanning** — Escanea los 100 puertos principales por dispositivo usando Nmap con detección de versión de servicios.
- **CVE Vulnerability Matching** — Cruza los servicios descubiertos con la base de datos NVD a través de su API.
- **SNMP Integration** — Recupera información extendida de dispositivos compatibles mediante el protocolo SNMP.
- **WiFi Scanner** — Lista redes WiFi cercanas y permite conectarse a ellas desde la interfaz.
- **Passive Background Daemon** — Monitorea silenciosamente la red en segundo plano buscando dispositivos nuevos.
- **Scan History** — Registro completo de auditoría para cada escaneo, almacenado persistentemente en Firebase Firestore.
- **Audit Console** — Terminal integrada en tiempo real con código de colores para puertos abiertos/bloqueados/filtrados.
- **PDF Export** — Genera reportes estructurados de 3 páginas en PDF (resumen, dispositivos, vulnerabilidades) listos para imprimir.
- **Dark Mode UI** — Dashboard profesional estilo SOC construido en React con gráficos y visualizaciones interactivas.

---

## Tech Stack

| Capa | Tecnología |
|---|---|
| Backend API | Python 3.10+, FastAPI, Uvicorn |
| Escaneo de Red | Nmap (python-nmap), SNMP |
| Base de Datos CVE | NVD REST API v2 |
| Frontend | React 18, Vite, Lucide Icons |
| Base de Datos | Firebase Firestore (cloud) + SQLite (local fallback) |
| Autenticación | Firebase Authentication |

---

## Prerrequisitos

- **Python 3.10+** (asegúrate de agregarlo al PATH durante la instalación)
- **Node.js v18+**
- **Nmap** — La aplicación puede instalarlo automáticamente en el primer inicio
- Un proyecto de **Firebase** con Firestore y Authentication habilitados

---

## Instalación

### 1. Clonar el repositorio
```bash
git clone https://github.com/MartinQuintanaC/secscan-tesis.git
cd secscan-tesis
```

### 2. Configurar el Backend
```bash
cd backend
python -m venv venv

# Windows
.\venv\Scripts\activate

# macOS / Linux
source venv/bin/activate

pip install -r requirements.txt
```

> **Importante:** Necesitas un archivo de credenciales `firebase_admin.json` de la consola de tu proyecto Firebase.  
> Colócalo dentro de la carpeta `backend/`. Este archivo está excluido del repositorio intencionalmente por seguridad.

### 3. Configurar el Frontend
```bash
cd frontend
npm install
```

---

## Ejecutar la aplicación

Usa el archivo batch incluido en Windows para iniciar con un solo clic:
```
iniciar_secscan.bat
```

O inicia manualmente en terminales separadas:

**Terminal 1 — Backend:**
```bash
cd backend
.\venv\Scripts\activate
uvicorn app:app --reload
```

**Terminal 2 — Frontend:**
```bash
cd frontend
npm run dev
```

Luego abre [http://localhost:5173](http://localhost:5173) en tu navegador.

---

## Estructura del Proyecto

```
secscan/
├── backend/
│   ├── app.py                  # Punto de entrada de FastAPI
│   ├── requirements.txt
│   ├── core/
│   │   ├── scanner.py          # Motor de escaneo con Nmap
│   │   ├── cve_client.py       # Cliente API para CVEs de NVD
│   │   ├── firebase_client.py  # Inicialización de Firebase
│   │   └── local_db.py         # Fallback offline con SQLite
│   ├── services/
│   │   ├── scan_service.py     # Orquestador + demonio pasivo
│   │   ├── db_service.py       # Capa de abstracción de base de datos
│   │   └── sync_service.py     # Sincronización Local ↔ Cloud
│   └── api/v1/endpoints/
│       ├── scans.py            # Endpoints de inicio e historial de escaneos
│       ├── devices.py          # Endpoints de listado de dispositivos
│       ├── wifi.py             # Endpoints de escaneo y conexión WiFi
│       └── system.py           # Health check e instalador de Nmap
└── frontend/
    └── src/
        ├── App.jsx             # Aplicación principal + componentes de página
        ├── components/
        │   └── NetworkTree.jsx # Visualización interactiva de topología de red
        ├── pages/
        │   ├── ScanHistoryPage.jsx
        │   └── LoginPage.jsx
        └── services/
            └── api.js          # Funciones cliente de la API
```

---

## Notas

- El escáner utiliza `--top-ports 100` por defecto para lograr un equilibrio entre velocidad y cobertura.
- Se escanean hasta 4 dispositivos en paralelo utilizando `ThreadPoolExecutor`.
- El demonio pasivo se pausa automáticamente cuando hay un escaneo activo en progreso.
- Los puertos bloqueados o filtrados se registran en la consola de auditoría con la razón exacta reportada por Nmap.

---

## Autor

**Martín Quintana** — Seguridad de Redes & Desarrollo Full-Stack  
Proyecto de Tesis — Ingeniería de Sistemas / Informática
