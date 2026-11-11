# -*- coding: utf-8 -*-
"""NEXUS-GUARD Core: 능동형 디코이(허니팟) 탐침 감지 & 입구 차단 실드."""
import ipaddress
import threading
import time
from typing import Dict, List, Optional, Set

# 공격자가 자동화 도구로 자주 찌르는 대표적 미끼 경로 목록
DEFAULT_DECOY_PATHS = {
    "/.env",
    "/.git",
    "/.git/config",
    "/.aws/credentials",
    "/wp-login.php",
    "/wp-admin",
    "/phpmyadmin",
    "/admin.php",
    "/config.json",
    "/server-status",
    "/.ds_store",
}


class DecoyShield:
    """공격자의 정찰 트래픽을 유인하여 조기에 포착하고 차단하는 허니팟 엔진."""

    def __init__(self, custom_paths: Optional[Set[str]] = None):
        paths = set(custom_paths) if custom_paths else set(DEFAULT_DECOY_PATHS)
        self.decoy_paths = {self._normalize_path(p) for p in paths}
        # 메모리 기반 차단 IP 캐시: {ip: expire_timestamp}
        self._blocked_ips: Dict[str, float] = {}
        self._lock = threading.Lock()

    MAX_BLOCKED = 10000  # 스캐너가 IP를 무한히 바꿔도 메모리가 무한정 늘지 않게 하는 상한

    @staticmethod
    def _normalize_path(path: str) -> str:
        """대소문자·중복 슬래시·'.'/'..' 세그먼트를 정규화한다 (/a/../.env, //.ENV 우회 방지)."""
        parts: List[str] = []
        for seg in str(path or "").replace("\\", "/").split("/"):
            if seg in ("", "."):
                continue
            if seg == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(seg.split(";")[0].casefold())
        return "/" + "/".join(parts)

    @staticmethod
    def _canon_ip(client_ip) -> Optional[str]:
        """유효한 IP만 정규형 문자열로 반환한다. 잘못된 값은 None (차단 테이블 오염 방지)."""
        try:
            addr = ipaddress.ip_address(str(client_ip or "").strip())
        except ValueError:
            return None
        mapped = getattr(addr, "ipv4_mapped", None)
        return (mapped or addr).compressed

    @staticmethod
    def is_protected(client_ip) -> bool:
        """루프백은 관리자/헬스체크 보호를 위해 절대 차단하지 않는다."""
        try:
            addr = ipaddress.ip_address(str(client_ip or "").strip())
        except ValueError:
            return False
        mapped = getattr(addr, "ipv4_mapped", None)
        return bool((mapped or addr).is_loopback)

    def is_blocked(self, client_ip: str) -> bool:
        """해당 IP가 현재 입구 차단 상태인지 확인합니다."""
        ip = self._canon_ip(client_ip)
        if ip is None:
            return False
        now = time.time()
        with self._lock:
            expire = self._blocked_ips.get(ip)
            if expire is None:
                return False
            if now >= expire:
                del self._blocked_ips[ip]
                return False
            return True

    def block_ip(self, client_ip: str, duration_seconds: int = 900) -> bool:
        """위협 IP를 지정된 시간(초) 동안 입구 차단합니다 (기본 15분). 유효하지 않거나 보호 대상 IP는 거부(False)."""
        ip = self._canon_ip(client_ip)
        if ip is None or self.is_protected(ip):
            return False
        now = time.time()
        with self._lock:
            if len(self._blocked_ips) >= self.MAX_BLOCKED:
                for k in [k for k, v in self._blocked_ips.items() if v <= now]:
                    del self._blocked_ips[k]
                if len(self._blocked_ips) >= self.MAX_BLOCKED:
                    # 가장 먼저 만료될 항목을 밀어낸다
                    del self._blocked_ips[min(self._blocked_ips, key=self._blocked_ips.get)]
            self._blocked_ips[ip] = now + max(1, int(duration_seconds))
        return True

    def unblock_ip(self, client_ip: str) -> bool:
        """차단된 IP를 해제합니다."""
        ip = self._canon_ip(client_ip)
        with self._lock:
            if ip in self._blocked_ips:
                del self._blocked_ips[ip]
                return True
        return False

    def clear_all_blocks(self) -> int:
        """모든 차단 IP를 1초 만에 초기화합니다."""
        with self._lock:
            count = len(self._blocked_ips)
            self._blocked_ips.clear()
        return count

    def check_probe(self, path: str, client_ip: str) -> bool:
        """경로 접근이 디코이 탐침인지 판별하고, 해당될 경우 입구 차단을 즉시 발동합니다.

        매칭: 정규화한 경로가 미끼와 같거나, 미끼 하위 경로('/.git/x'), 미끼 변형 파일('/.env.bak')일 때만.
        '/.github' 처럼 접두사만 같은 정상 경로는 오탐하지 않는다.
        반환값:
            bool: 디코이 탐침 여부 (True이면 호출 측에서 404를 반환하여 기만해야 함)
        """
        norm = self._normalize_path(path)
        for dp in self.decoy_paths:
            if norm == dp or norm.startswith(dp + "/") or norm.startswith(dp + "."):
                self.block_ip(client_ip, duration_seconds=900)
                return True
        return False
