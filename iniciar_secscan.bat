@echo off
title SecScan Launcher
echo ==========================================
echo   INICIANDO SERVICIOS DE SECSCAN
echo ==========================================
echo.

:: 1. Iniciar n8n en segundo plano (abre ventana propia)
echo [+] Iniciando Orquestador (n8n)...
start "SecScan - n8n" cmd /k "npx n8n"

:: 2. Iniciar Backend con su entorno virtual
echo [+] Iniciando Backend (Uvicorn)...
start "SecScan - Backend" cmd /k "cd backend && .\venv\Scripts\python.exe -m uvicorn app:app --reload"

:: 3. Iniciar Frontend (Vite)
echo [+] Iniciando Frontend (Vite)...
start "SecScan - Frontend" cmd /k "cd frontend && npm run dev"

echo.
echo [!] Todos los servicios lanzados con exito.
echo [!] Puedes cerrar esta ventana. Las demas seguiran corriendo.
timeout /t 5
