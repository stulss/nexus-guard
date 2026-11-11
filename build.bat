@echo off
chcp 65001 > nul
title NEXUS-GUARD Windows Executable Builder

echo =====================================================================
echo  NEXUS-GUARD Enterprise Active Defense Security Suite
echo  Windows Standalone Executable (.exe) Builder
echo =====================================================================
echo.

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH.
    pause
    exit /b 1
)

echo [*] Installing / Verifying PyInstaller...
python -m pip install --quiet pyinstaller

echo.
echo [*] Running Test Verification Suite before building...
python -m pytest tests/ -q
if %errorlevel% neq 0 (
    echo [!] Tests failed! Aborting build.
    pause
    exit /b 1
)

echo.
echo [*] Building Standalone Executable...
python scripts/build_exe.py

if %errorlevel% equ 0 (
    echo.
    echo =====================================================================
    echo  Build Successful!
    echo  Standalone package created at: dist\NexusGuard\NexusGuard.exe
    echo =====================================================================
) else (
    echo.
    echo [ERROR] Build failed! Check the output above.
)

echo.
pause
