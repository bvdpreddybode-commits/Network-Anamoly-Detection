@echo off
setlocal enabledelayedexpansion
title Network Anomaly Detection System

echo ========================================================
echo   Network Anomaly Detection System (NIDS) - Launcher
echo ========================================================
echo.

:: Find python executable
set "PY_CMD="
python --version >nul 2>&1 && set "PY_CMD=python"
if not defined PY_CMD (
    py -3 --version >nul 2>&1 && set "PY_CMD=py -3"
)

if not defined PY_CMD (
    echo [ERROR] Python is not found on this system!
    echo.
    echo To fix this:
    echo 1. Download Python from: https://www.python.org/downloads/
    echo 2. Run the installer and MUST CHECK the box: "Add Python to PATH"
    echo.
    pause
    exit /b 1
)

echo [*] Detected Python:
%PY_CMD% --version

cd /d "%~dp0cbp_network_anomaly"

:: Create venv if needed
if not exist "venv\Scripts\python.exe" (
    echo [*] Setting up local environment in .\venv...
    %PY_CMD% -m venv venv
)

if exist "venv\Scripts\activate.bat" (
    call "venv\Scripts\activate.bat"
    echo [*] Installing/checking dependencies...
    python -m pip install --upgrade pip --quiet
    pip install -r requirements.txt
    echo.
    echo [*] Launching Dashboard at http://localhost:8501 ...
    python -m streamlit run dashboard/app.py --server.port 8501
) else (
    echo [*] Installing requirements...
    %PY_CMD% -m pip install -r requirements.txt
    echo [*] Launching Dashboard at http://localhost:8501 ...
    %PY_CMD% -m streamlit run dashboard/app.py --server.port 8501
)

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Application closed with code %errorlevel%.
)
pause
