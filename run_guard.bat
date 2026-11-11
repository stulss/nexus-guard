@echo off
chcp 65001 > nul
title NEXUS-GUARD 엔터프라이즈 보안 관제센터

cd /d "%~dp0"

set "PYTHON_CMD="
if exist "%~dp0..\nexus-work-portfolio\.venv\Scripts\pythonw.exe" (
    set "PYTHON_CMD=%~dp0..\nexus-work-portfolio\.venv\Scripts\pythonw.exe"
) else if exist "%~dp0.venv\Scripts\pythonw.exe" (
    set "PYTHON_CMD=%~dp0.venv\Scripts\pythonw.exe"
) else (
    set "PYTHON_CMD=pythonw"
)

start "" "%PYTHON_CMD%" run_guard.py
exit /b 0
