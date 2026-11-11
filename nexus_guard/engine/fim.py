# -*- coding: utf-8 -*-
"""NEXUS-GUARD Engine: 파일 무결성 실시간 감시자 (File Integrity Monitor - FIM)."""
import hashlib
import time
from pathlib import Path
from typing import Dict, List, Tuple

BASE_DIR = Path(__file__).resolve().parents[2]


class FileIntegrityMonitor:
    """핵심 소스코드 및 환경설정 파일의 위변조를 SHA-256 해시로 실시간 감시하는 엔진."""

    def __init__(self, watch_dirs: List[Path] = None):
        if watch_dirs is None:
            self.watch_dirs = [
                BASE_DIR / "app",
                BASE_DIR / "db",
                BASE_DIR / "nexus_guard",
            ]
        else:
            self.watch_dirs = watch_dirs

        self._baseline_hashes: Dict[str, str] = {}
        self.initialize_baseline()

    def _calculate_sha256(self, filepath: Path) -> str:
        sha = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                while chunk := f.read(8192):
                    sha.update(chunk)
            return sha.hexdigest()
        except Exception:
            return ""

    def initialize_baseline(self) -> int:
        """현재 파일들의 SHA-256 해시 베이스라인을 등록합니다."""
        self._baseline_hashes.clear()
        for directory in self.watch_dirs:
            if not directory.exists():
                continue
            for file_path in directory.rglob("*.py"):
                if "__pycache__" in str(file_path):
                    continue
                rel_path = str(file_path.relative_to(BASE_DIR))
                self._baseline_hashes[rel_path] = self._calculate_sha256(file_path)

        # .env 파일도 감시
        env_file = BASE_DIR / ".env"
        if env_file.exists():
            self._baseline_hashes[".env"] = self._calculate_sha256(env_file)

        return len(self._baseline_hashes)

    def scan_for_tampering(self) -> List[Dict[str, str]]:
        """베이스라인과 비교하여 파일 변조(Modified), 신규 생성(Added), 삭제(Deleted)를 적발합니다."""
        alerts = []
        current_files = set()

        for directory in self.watch_dirs:
            if not directory.exists():
                continue
            for file_path in directory.rglob("*.py"):
                if "__pycache__" in str(file_path):
                    continue
                rel_path = str(file_path.relative_to(BASE_DIR))
                current_files.add(rel_path)
                current_hash = self._calculate_sha256(file_path)

                baseline_hash = self._baseline_hashes.get(rel_path)
                if baseline_hash is None:
                    alerts.append({
                        "type": "NEW_FILE_CREATED",
                        "severity": "MEDIUM",
                        "file": rel_path,
                        "desc": "베이스라인에 없는 새로운 실행 파일이 생성되었습니다 (백도어 의심).",
                        "time": time.strftime("%H:%M:%S"),
                    })
                elif current_hash != baseline_hash:
                    alerts.append({
                        "type": "FILE_MODIFIED",
                        "severity": "HIGH",
                        "file": rel_path,
                        "desc": "파일의 SHA-256 해시가 변경되었습니다 (소스코드 변조 감지).",
                        "time": time.strftime("%H:%M:%S"),
                    })

        # 삭제된 파일 검사
        for baseline_file in self._baseline_hashes:
            if baseline_file not in current_files and baseline_file != ".env":
                alerts.append({
                    "type": "FILE_DELETED",
                    "severity": "HIGH",
                    "file": baseline_file,
                    "desc": "핵심 보안 파일이 임의로 삭제되었습니다.",
                    "time": time.strftime("%H:%M:%S"),
                })

        return alerts
