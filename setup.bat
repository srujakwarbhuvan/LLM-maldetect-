@echo off
REM APK Feature Extractor - One-Click Setup for Windows
REM Run this file to set up everything automatically

echo ============================================================
echo    APK Feature Extraction System - Quick Setup
echo ============================================================
echo.

REM Check if virtual environment exists
if exist "venv" (
    echo [*] Virtual environment already exists
) else (
    echo [1/4] Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment
        pause
        exit /b 1
    )
    echo [OK] Virtual environment created
)

echo.
echo [2/4] Activating virtual environment...
call venv\Scripts\activate.bat

echo.
echo [3/4] Installing dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Failed to install dependencies
    pause
    exit /b 1
)

echo.
echo [4/4] Installing package in development mode...
pip install -e .
if errorlevel 1 (
    echo [ERROR] Failed to install package
    pause
    exit /b 1
)

echo.
echo ============================================================
echo    Setup Complete!
echo ============================================================
echo.
echo Next steps:
echo   1. Activate environment: venv\Scripts\activate
echo   2. Place APKs in: data\input\
echo   3. Run: apk-extract batch data\input\ -o features.csv
echo.
echo Try the example:
echo   python scripts\example_single_apk.py
echo.
pause
