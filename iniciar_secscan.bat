@echo off
title SecScan Launcher

:: Obtener la ruta absoluta donde se encuentra este .bat
set "RAIZ=%~dp0"
:: Eliminar la barra final si existe
if "%RAIZ:~-1%"=="\" set "RAIZ=%RAIZ:~0,-1%"

echo ==========================================
echo   INICIANDO SERVICIOS DE SECSCAN
echo   Ruta: %RAIZ%
echo ==========================================
echo.

:: 1. Iniciar n8n en segundo plano (abre ventana propia)
echo [+] Iniciando Orquestador (n8n)...
start "SecScan - n8n" cmd /k "npx n8n"

:: 2. Iniciar Backend con su entorno virtual (ruta absoluta)
echo [+] Iniciando Backend (Uvicorn)...
start "SecScan - Backend" cmd /k "cd /d "%RAIZ%\backend" && "%RAIZ%\backend\venv\Scripts\python.exe" -m uvicorn app:app --reload --host 0.0.0.0 --port 8000"

:: 3. Iniciar Frontend (Vite) (ruta absoluta)
echo [+] Iniciando Frontend (Vite)...
start "SecScan - Frontend" cmd /k "cd /d "%RAIZ%\frontend" && npm run dev"

:: 4. Abrir la interfaz web automáticamente
echo [+] Abriendo el navegador...
timeout /t 3 >nul
start http://localhost:5173

echo.
echo [!] Todos los servicios lanzados con exito.
echo [!] Puedes cerrar esta ventana. Las demas seguiran corriendo.
timeout /t 5
