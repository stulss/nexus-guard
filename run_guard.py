# -*- coding: utf-8 -*-
"""NEXUS-GUARD Enterprise Endpoint Security Console Launcher.

더블클릭 또는 'python run_guard.py' 실행으로 관제 콘솔을 가동합니다.
"""
import os
import sys
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))


def main():
    # Headless / Docker / CLI mode check
    is_headless = "--headless" in sys.argv or "--cli" in sys.argv
    if not is_headless and sys.platform != "win32" and not os.environ.get("DISPLAY"):
        is_headless = True

    if is_headless:
        # Pass remaining arguments to CLI
        filtered_args = [a for a in sys.argv[1:] if a not in ("--headless", "--cli")]
        sys.argv = [sys.argv[0]] + (filtered_args if filtered_args else ["status"])
        from nexus_guard.cli.guard_cli import main as cli_main
        cli_main()
    else:
        from nexus_guard.gui.native_app import main as gui_main
        gui_main()


if __name__ == "__main__":
    main()

