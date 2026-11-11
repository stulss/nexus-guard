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

from nexus_guard.gui.native_app import main

if __name__ == "__main__":
    main()
