@echo off
setlocal
title Network Anomaly Detection System

echo ========================================================
echo   Network Anomaly Detection System (NIDS) - Launcher
echo ========================================================
echo.

:: Check for Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in your PATH.
    echo Please install Python 3.9+ from https://www.python.org/downloads/
    pause
    exit /b 1
)

:: Navigate to project directory
cd /d "%~dp0cbp_network_anomaly"

:: Setup virtual environment if not present
if not exist "venv" (
    echo [*] Setting up virtual environment in .\venv...
    python -m venv venv
    call venv\Scripts\activate.bat
    echo [*] Installing dependencies from requirements.txt...
    python -m pip install --upgrade pip
    pip install -r requirements.txt
) else (
    call venv\Scripts\activate.bat
)

echo.
echo [*] Starting Streamlit Dashboard...
echo [*] Opening at http://localhost:8501
echo.
streamlit run dashboard/app.py
pause
