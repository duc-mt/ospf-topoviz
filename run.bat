@echo off
rem ==============================================================================
rem Script Name:   run.bat
rem Description:   Universal launcher for OSPF TopoViz on Windows (CMD/PowerShell).
rem Author:        Mai Tan Duc <ducmai.network@gmail.com>
rem Created:       2026-10-10
rem Version:       1.0.0
rem License:       MIT
rem ==============================================================================
rem Usage:         run.bat [options]
rem ==============================================================================

setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "VENV_DIR=%SCRIPT_DIR%.venv"
set "VENV_PYTHON=%VENV_DIR%\Scripts\python.exe"

REM 1. Initialize config\settings.yaml from example if missing
if not exist "%SCRIPT_DIR%config\settings.yaml" (
    if exist "%SCRIPT_DIR%config\settings.yaml.example" (
        copy "%SCRIPT_DIR%config\settings.yaml.example" "%SCRIPT_DIR%config\settings.yaml" >nul
        echo Initialized config\settings.yaml from template.
    )
)

REM 2. Check and bootstrap virtual environment if missing
if not exist "%VENV_PYTHON%" (
    echo Virtual environment not found in .venv. Initializing...
    
    where python >nul 2>nul
    if !ERRORLEVEL! neq 0 (
        echo Error: Python 3 is not installed or not found in PATH.
        exit /b 1
    )

    python -m venv "%VENV_DIR%"
    if !ERRORLEVEL! neq 0 (
        echo Error: Failed to create virtual environment.
        exit /b 1
    )

    if exist "%SCRIPT_DIR%requirements.lock" (
        echo Installing locked dependencies...
        "%VENV_DIR%\Scripts\pip.exe" install --quiet -r "%SCRIPT_DIR%requirements.lock"
    ) else if exist "%SCRIPT_DIR%requirements.txt" (
        echo Installing dependencies from requirements.txt...
        "%VENV_DIR%\Scripts\pip.exe" install --quiet -r "%SCRIPT_DIR%requirements.txt"
    )
)

REM 3. Execute main.py with virtual environment python forwarding all arguments
"%VENV_PYTHON%" "%SCRIPT_DIR%main.py" %*
