# -*- coding: utf-8 -*-
"""NEXUS-GUARD Standalone Executable Build Script.

PyInstaller를 사용하여 파이썬 환경이 없는 윈도우 PC에서도 즉시 단독 실행 가능한
'NexusGuard.exe' 및 배포 패키지(dist/NexusGuard)를 생성합니다.
"""
import os
import sys
import shutil
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DIST_DIR = PROJECT_ROOT / "dist"
BUILD_DIR = PROJECT_ROOT / "build"


def build_executable():
    print(f"[*] Building NEXUS-GUARD Standalone Executable...")
    print(f"[*] Project Root: {PROJECT_ROOT}")

    # Check if PyInstaller is available
    pyinstaller_cmd = shutil.which("pyinstaller")
    if not pyinstaller_cmd:
        # Check standard user scripts path on Windows
        user_scripts = Path(sys.executable).parent / "Scripts" / "pyinstaller.exe"
        roaming_scripts = Path(os.environ.get("APPDATA", "")) / "Python" / f"Python{sys.version_info.major}{sys.version_info.minor}" / "Scripts" / "pyinstaller.exe"
        if user_scripts.exists():
            pyinstaller_cmd = str(user_scripts)
        elif roaming_scripts.exists():
            pyinstaller_cmd = str(roaming_scripts)
        else:
            pyinstaller_cmd = sys.executable + " -m PyInstaller"

    print(f"[*] Using PyInstaller: {pyinstaller_cmd}")

    # Clean previous build artifacts
    if DIST_DIR.exists():
        shutil.rmtree(DIST_DIR, ignore_errors=True)
    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR, ignore_errors=True)

    # Prepare PyInstaller arguments
    # We collect customtkinter assets, nexus_guard rules, config, docs
    add_data_args = [
        f"--add-data={PROJECT_ROOT / 'nexus_guard' / 'rules'}{os.pathsep}{Path('nexus_guard') / 'rules'}",
        f"--add-data={PROJECT_ROOT / 'nexus_guard' / 'config.json'}{os.pathsep}{Path('nexus_guard')}",
        f"--add-data={PROJECT_ROOT / 'nexus_guard' / 'config.example.json'}{os.pathsep}{Path('nexus_guard')}",
        f"--add-data={PROJECT_ROOT / 'docs'}{os.pathsep}{Path('docs')}",
        f"--add-data={PROJECT_ROOT / 'README.md'}{os.pathsep}.",
    ]

    cmd = [
        pyinstaller_cmd if " " not in pyinstaller_cmd else pyinstaller_cmd.split()[0],
    ]
    if " -m PyInstaller" in pyinstaller_cmd:
        cmd = [sys.executable, "-m", "PyInstaller"]

    cmd.extend([
        "--noconfirm",
        "--onedir",
        "--windowed",
        "--name=NexusGuard",
        "--collect-all=customtkinter",
        "--hidden-import=psutil",
        "--hidden-import=urllib3",
        "--hidden-import=tkinter",
        "--hidden-import=tkinter.ttk",
        "--hidden-import=tkinter.filedialog",
        "--hidden-import=tkinter.messagebox",
    ])
    cmd.extend(add_data_args)
    cmd.append(str(PROJECT_ROOT / "run_guard.py"))

    print(f"[*] Running command: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=str(PROJECT_ROOT))
    if result.returncode != 0:
        print(f"[!] PyInstaller build failed with exit code {result.returncode}")
        return False

    # Copy external companion files to output directory for user convenience
    output_bundle = DIST_DIR / "NexusGuard"
    if output_bundle.exists():
        # Copy batch runner
        if (PROJECT_ROOT / "run_guard.bat").exists():
            shutil.copy2(PROJECT_ROOT / "run_guard.bat", output_bundle / "run_guard.bat")
        # Ensure logs and exports directories exist
        (output_bundle / "logs").mkdir(exist_ok=True)
        (output_bundle / "exports" / "reports").mkdir(parents=True, exist_ok=True)
        # Copy clean config.json for quick user editing
        if (PROJECT_ROOT / "nexus_guard" / "config.json").exists():
            shutil.copy2(PROJECT_ROOT / "nexus_guard" / "config.json", output_bundle / "config.json")
        if (PROJECT_ROOT / "docs" / "EXTERNAL_INTEGRATIONS_GUIDE.md").exists():
            (output_bundle / "docs").mkdir(exist_ok=True)
            shutil.copy2(PROJECT_ROOT / "docs" / "EXTERNAL_INTEGRATIONS_GUIDE.md", output_bundle / "docs" / "EXTERNAL_INTEGRATIONS_GUIDE.md")

    print(f"[+] Build finished successfully! Output available at: {output_bundle}")
    return True


if __name__ == "__main__":
    success = build_executable()
    sys.exit(0 if success else 1)
