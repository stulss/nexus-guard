# -*- coding: utf-8 -*-
"""NEXUS-GUARD: 기업용 웹 애플리케이션을 위한 경량 능동형 AI-XDR 보안 에이전트 솔루션.

개발자: 홍주형 (웹/DB 보안 하드닝 & 코어 아키텍처 & AI 엔지니어링)
버전: 2.5.0-LTS

NEXUS-GUARD는 모든 웹 프레임워크(Flask, WSGI 등)에 플러그인 형태로 장착되어,
1. 능동형 디코이(허니팟) 탐침 감지 및 403 입구 격리
2. AST 정적 분석 기반 SQL Injection 100% 원천 차단
3. 5단계 순차 결재 BOLA(인가 새치기) 및 IDOR 불법 파라미터 변조 방어
4. Groq LPU(0.5초) 기반 초고속 4중 AI 캐스케이드 위협 판정
5. Server-Sent Events (SSE) 기반 0.1초 실시간 보안 관제 스트리밍
을 독립형 보안 소프트웨어로서 완결형으로 제공합니다.
"""
from typing import Any, Dict, Optional

__version__ = "2.5.0-LTS"
__author__ = "Hong Joo-hyung <stulss>"

from .core.decoy import DecoyShield
from .core.bola_shield import BolaShield
from .core.ast_guard import AstQueryGuard
from .ai_engine.cascade_router import AiCascadeRouter
from .ai_engine.xdr_triage import XdrTriageEngine
from .monitor.sse_streamer import SseAuditStreamer


def _canon(value: Any) -> Optional[str]:
    import ipaddress
    try:
        addr = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    return (getattr(addr, "ipv4_mapped", None) or addr).compressed


class NexusGuard:
    """NEXUS-GUARD 중앙 보안 컨트롤러 & 미들웨어."""

    def __init__(self, app: Optional[Any] = None, config: Optional[Dict[str, Any]] = None):
        self.app = app
        self.config = config or {}
        self.decoy = DecoyShield()
        self.bola = BolaShield()
        self.ast_guard = AstQueryGuard()
        self.ai_router = AiCascadeRouter()
        self.xdr = XdrTriageEngine(self.ai_router)
        self.streamer = SseAuditStreamer()

        if app is not None:
            self.init_app(app)

    def client_ip(self, request: Any) -> str:
        """클라이언트 IP. X-Forwarded-For 는 config["trusted_proxies"] 에 등록된 프록시가 직접 연결한 경우에만 신뢰하고,
        오른쪽(가까운 쪽)에서부터 신뢰 프록시를 건너뛴 첫 주소를 쓴다. 기본값(빈 목록)은 소켓 주소만 사용한다."""
        remote = _canon(request.remote_addr) or "-"
        trusted = {_canon(p) for p in self.config.get("trusted_proxies", [])} - {None}
        if remote in trusted:
            hops = [h.strip() for h in request.headers.get("X-Forwarded-For", "").split(",") if h.strip()]
            for hop in reversed(hops):
                ip = _canon(hop)
                if ip is None:
                    return remote  # 변조된 값: 신뢰하지 않는다
                if ip not in trusted:
                    return ip
            if hops:
                return _canon(hops[0]) or remote
        return remote

    def init_app(self, app: Any) -> None:
        """웹 애플리케이션에 보안 에이전트를 등록하고 필터를 부착합니다."""
        self.app = app
        
        # 1. 보안 설정 주입
        app.extensions = getattr(app, "extensions", {})
        app.extensions["nexus_guard"] = self

        # 2. Before Request: 인그레스 방어 (차단 IP, 디코이 탐침)
        @app.before_request
        def _ingress_security_check():
            from flask import request, abort, make_response
            client_ip = self.client_ip(request)

            # 이미 차단된 IP는 모든 경로에서 403 (이전에는 차단 등록만 하고 집행하지 않았다)
            if self.decoy.is_blocked(client_ip):
                return make_response("Forbidden", 403)

            # 디코이 경로 접근 검사
            decoy_hit = self.decoy.check_probe(request.path, client_ip)
            if decoy_hit:
                # 공격자에게는 404를 반환하여 기만하고, 이후 요청은 위 검사에서 403 차단된다
                return make_response("Not Found", 404)

        # 3. After Request: Egress 보안 헤더 주입
        @app.after_request
        def _egress_security_headers(response):
            response.headers.setdefault("X-Content-Type-Options", "nosniff")
            response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
            response.headers.setdefault("X-XSS-Protection", "1; mode=block")
            response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
            response.headers.setdefault("Server", "NEXUS-GUARD/2.5")
            return response


__all__ = [
    "NexusGuard",
    "DecoyShield",
    "BolaShield",
    "AstQueryGuard",
    "AiCascadeRouter",
    "XdrTriageEngine",
    "SseAuditStreamer",
    "__version__",
]
