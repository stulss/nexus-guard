# -*- coding: utf-8 -*-
"""NEXUS-GUARD 보안 패키지 단위 테스트 (tests/test_nexus_guard.py)."""
import time
from pathlib import Path
import pytest
from flask import Flask

from nexus_guard import (
    NexusGuard,
    DecoyShield,
    BolaShield,
    AstQueryGuard,
    AiCascadeRouter,
    XdrTriageEngine,
    SseAuditStreamer,
)


def test_decoy_shield_probe_and_block():
    """디코이(허니팟) 탐침 감지 및 15분 IP 차단 동작 검증."""
    shield = DecoyShield()
    test_ip = "192.168.99.10"

    assert not shield.is_blocked(test_ip)

    # 1. 일반 경로는 디코이 아님
    assert not shield.check_probe("/index.html", test_ip)
    assert not shield.is_blocked(test_ip)

    # 2. 미끼 경로 (/.env) 찌르면 디코이 탐침으로 감지되고 즉시 차단 등록
    assert shield.check_probe("/.env", test_ip)
    assert shield.is_blocked(test_ip)

    # 3. 해제 검증
    assert shield.unblock_ip(test_ip)
    assert not shield.is_blocked(test_ip)


def test_bola_shield_approval_and_finance():
    """전자결재 BOLA 순차 승인 및 지출결의서 위조 방어 검증."""
    bola = BolaShield()

    # 1. 결재 순서 새치기 방어 (현재 1단계인데 3단계 승인 시도 -> 거부)
    assert not bola.verify_approval_step(
        current_step=1, requested_step=3, user_role="director", required_role="manager"
    )

    # 2. 직급 권한 부족 방어 (사원이 팀장 결재 시도 -> 거부)
    assert not bola.verify_approval_step(
        current_step=1, requested_step=1, user_role="user", required_role="manager"
    )

    # 3. 정당한 결재 승인 (팀장이 1단계 팀장 결재 승인 -> 통과)
    assert bola.verify_approval_step(
        current_step=1, requested_step=1, user_role="manager", required_role="manager"
    )

    # 4. 재무 합계 위조 방어 (품목 합계 30,000인데 클라이언트가 10,000으로 보냄 -> 거부)
    items = [10000, 15000, 5000]
    assert not bola.verify_financial_integrity(items, claimed_total=10000)
    assert bola.verify_financial_integrity(items, claimed_total=30000)


def test_ast_query_guard():
    """AST 구문 분석을 통한 안전한 쿼리 검증."""
    import tempfile

    guard = AstQueryGuard()

    # 취약한 코드 파일 생성
    vuln_code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write(vuln_code)
        temp_path = Path(f.name)

    try:
        violations = guard.inspect_file(temp_path)
        assert len(violations) > 0
        assert "f-string" in violations[0][1]
    finally:
        temp_path.unlink(missing_ok=True)


def test_xdr_triage_engine():
    """XDR 트리아지 엔진 위협 분석 및 점수 산출 검증."""
    router = AiCascadeRouter()
    engine = XdrTriageEngine(router)

    event_log = {
        "event": "decoy_probe",
        "src_ip": "10.0.0.99",
        "path": "/.env",
    }
    result = engine.triage_event(event_log)
    assert "score" in result
    assert result["score"] >= 80
    assert result["decision"] == "BLOCK"


def test_sse_streamer():
    """SSE 감사 스트리머 브로드캐스트 검증."""
    streamer = SseAuditStreamer()
    q = streamer.subscribe()

    count = streamer.broadcast("alert", {"msg": "threat detected"})
    assert count == 1
    msg = q.get_nowait()
    assert "threat detected" in msg

    streamer.unsubscribe(q)


def test_nexus_guard_flask_extension():
    """Flask 앱에 NexusGuard 플러그인 장착 및 응답 헤더 주입 검증."""
    app = Flask(__name__)
    guard = NexusGuard(app)

    @app.route("/test")
    def test_view():
        return "OK"

    client = app.test_client()
    resp = client.get("/test")
    assert resp.status_code == 200
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("Server") == "NEXUS-GUARD/2.5"

    # 디코이 미끼 경로 접근 시 404 반환
    decoy_resp = client.get("/.env")
    assert decoy_resp.status_code == 404
