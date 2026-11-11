@echo off
chcp 65001 > nul
title NEXUS-GUARD 엔터프라이즈 보안 관제센터 [Console Debug]

cd /d "%~dp0"

echo ======================================================================
echo  🛡️  NEXUS-GUARD 엔터프라이즈 보안 관제 콘솔 기동 중...
echo ======================================================================

set "PYTHON_CMD="
if exist "%~dp0..\nexus-work-portfolio\.venv\Scripts\python.exe" (
    set "PYTHON_CMD=%~dp0..\nexus-work-portfolio\.venv\Scripts\python.exe"
) else if exist "%~dp0.venv\Scripts\python.exe" (
    set "PYTHON_CMD=%~dp0.venv\Scripts\python.exe"
) else (
    set "PYTHON_CMD=python"
)

"%PYTHON_CMD%" run_guard.py
if %ERRORLEVEL% neq 0 (
    echo.
    echo [경고] 프로그램 종료 코드: %ERRORLEVEL%
    pause
)
