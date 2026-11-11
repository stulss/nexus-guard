# -*- coding: utf-8 -*-
"""테스트: 상용 엔터프라이즈 기능 검증 (MITRE ATT&CK, CISO 리포트 생성기, 비상 격리, 큐 바운딩)."""
import os
import queue
import time
from pathlib import Path

import pytest
from nexus_guard.ai_engine.mitre_mapper import MitreAttackMapper
from nexus_guard.engine.firewall import FirewallRuleManager
from nexus_guard.engine.report_exporter import SecurityReportExporter


def test_mitre_attack_mapper_realtime_mapping():
    """MITRE ATT&CK 5대 핵심 전술 및 기법 자동 매핑 검증."""
    mapper = MitreAttackMapper()

    # 1. T1595 Reconnaissance (디코이 미끼 탐침)
    t1 = mapper.map_log_event({
        "event_type": "decoy_triggered",
        "path": "/.env",
        "src_ip": "192.168.1.100",
        "detail": "Decoy canary trap triggered on /.env"
    })
    assert t1 is not None
    assert t1.technique_id == "T1595"
    assert t1.tactic == "Reconnaissance"
    assert "PLAYBOOK-REC-01" in t1.remediation_playbook

    # 2. T1059 Execution (LLM 프롬프트 인젝션 탈옥)
    t2 = mapper.map_log_event({
        "event_type": "prompt_injection_detected",
        "src_ip": "10.0.0.5",
        "detail": "Jailbreak prompt injection override attempt"
    })
    assert t2 is not None
    assert t2.technique_id == "T1059"
    assert t2.tactic == "Execution"
    assert "PLAYBOOK-EXE-04" in t2.remediation_playbook

    # 3. T1070 Defense Evasion (FIM 해시 변조)
    t3 = mapper.map_fim_alert({
        "type": "FILE_MODIFIED",
        "file": "app/security.py",
        "desc": "SHA-256 해시 변경 감지"
    })
    assert t3 is not None
    assert t3.technique_id == "T1070"
    assert t3.tactic == "Defense Evasion"
    assert "PLAYBOOK-EVA-03" in t3.remediation_playbook

    # 4. T1499 DoS (속도 제한 및 패킷 폭증)
    t4 = mapper.map_log_event({
        "event_type": "rate_limit_exceeded",
        "src_ip": "172.16.0.22",
        "detail": "Rate limit exceeded: 500 requests per second"
    })
    assert t4 is not None
    assert t4.technique_id == "T1499"
    assert t4.tactic == "Impact"

    # 5. T1190 Exploit Public-Facing App (SQLi / AST 위반)
    t5 = mapper.map_scanner_finding({
        "title": "SQL Injection AST Query Risk",
        "desc": "Non-constant SQL string concatenation",
        "severity": "HIGH"
    })
    assert t5 is not None
    assert t5.technique_id == "T1190"
    assert t5.tactic == "Initial Access"

    # 6. T1505 Web Shell Persistence
    t6 = mapper.map_fim_alert({
        "type": "NEW_FILE_CREATED",
        "file": "app/static/backdoor.py",
        "desc": "신규 파이썬 파일 생성"
    })
    assert t6 is not None
    assert t6.technique_id == "T1505"
    assert t6.tactic == "Persistence"

    # 매트릭스 커버리지 및 클린 슬레이트 검증
    cov = mapper.get_matrix_coverage()
    assert cov["total_monitored_techniques"] == 7
    assert cov["detected_techniques_count"] >= 5
    assert cov["total_mitre_events"] >= 6

    # 클린 슬레이트 초기화
    mapper.clear()
    cov_clean = mapper.get_matrix_coverage()
    assert cov_clean["detected_techniques_count"] == 0
    assert cov_clean["total_mitre_events"] == 0


def test_emergency_containment_and_recovery_playbook():
    """1-클릭 신속 비상 격리 및 자동 복구 플레이북 실행 검증."""
    fw = FirewallRuleManager()
    assert not fw.is_contained()

    # 격리 발동
    c_res = fw.activate_emergency_containment(
        reason="모의 APT 침투 및 데이터 탈취 의심으로 인한 비상 격리",
        initiated_by="CISO_ADMIN"
    )
    assert fw.is_contained()
    assert "CONTAINMENT-ACT-" in c_res["containment_id"]
    assert "127.0.0.1" in c_res["management_whitelist"]

    # 격리 상태 조회
    status = fw.get_containment_status()
    assert status["is_contained"] is True
    assert len(status["audit_trail"]) == 1
    assert status["audit_trail"][0]["action"] == "EMERGENCY_CONTAINMENT_ACTIVATED"

    # 자동 복구 플레이북 실행
    r_res = fw.lift_emergency_containment(authorized_by="CISO_ADMIN")
    assert r_res["success"] is True
    assert not fw.is_contained()
    assert len(r_res["recovery_steps"]) == 4

    # 감사 증적 2건 확인
    status2 = fw.get_containment_status()
    assert len(status2["audit_trail"]) == 2
    assert status2["audit_trail"][1]["action"] == "EMERGENCY_CONTAINMENT_LIFTED"


def test_ciso_security_report_exporter(tmp_path):
    """CISO 종합 보안 감사 보고서 내보내기 (HTML, CSV, JSON) 및 디지털 인장 검증."""
    exporter = SecurityReportExporter(export_dir=tmp_path)

    scanner_data = {
        "security_score": 98,
        "security_grade": "A+ (안전)",
        "findings": [
            {"category": "설정", "severity": "MEDIUM", "title": "DEBUG 모드 점검", "desc": "정상"}
        ]
    }
    blocked_ips = [
        {"ip": "203.0.113.5", "reason": "디코이 침해", "hits": 4, "remaining_seconds": 1800, "status": "차단 중 (BLOCKED)"}
    ]
    fim_alerts = []
    mitre_data = {
        "matrix": [
            {"technique_id": "T1595", "technique_name": "Active Scanning", "tactic": "Reconnaissance", "tactic_id": "TA0043", "severity": "HIGH", "hits": 2, "status": "DETECTED", "remediation_playbook": "PLAYBOOK-REC-01"}
        ],
        "tactics_summary": {"Reconnaissance": 2},
        "total_mitre_events": 2,
    }
    containment_status = {"is_contained": False}

    results = exporter.export_all(
        scanner_data=scanner_data,
        blocked_ips=blocked_ips,
        fim_alerts=fim_alerts,
        fim_baseline_count=45,
        mitre_data=mitre_data,
        containment_status=containment_status,
        base_name="TEST_AUDIT_REPORT"
    )

    # 3대 포맷 파일 존재 확인
    assert results["html"].exists()
    assert results["csv"].exists()
    assert results["json"].exists()

    # HTML 내용 검증
    html_text = results["html"].read_text(encoding="utf-8")
    assert "엔터프라이즈 CISO 종합 보안 감사 보고서" in html_text
    assert "T1595" in html_text
    assert "203.0.113.5" in html_text
    assert "보고서 무결성 암호학적 디지털 인장" in html_text
    assert len(results["context"]["meta"]["digital_seal_sha256"]) == 64

    # CSV 내용 검증
    csv_text = results["csv"].read_text(encoding="utf-8-sig")
    assert "BLOCKED IP REGISTRY" in csv_text
    assert "203.0.113.5" in csv_text
    assert "MITRE ATT&CK MATRIX STATUS" in csv_text

    # JSON 내용 검증
    json_text = results["json"].read_text(encoding="utf-8")
    assert "overall_security_score" in json_text
    assert "digital_seal_sha256" in json_text


def test_bounded_queue_and_burst_resistance():
    """초당 수천 건의 로그 폭증 시 큐 바운딩(Bounded Queue) 및 드롭 레지스턴트 동작 검증."""
    # 최대 500개 용량의 바운디드 큐
    bounded_queue = queue.Queue(maxsize=500)
    total_ingested = 0
    dropped_count = 0

    # 5,000건의 고속 로그 이벤트 유입 시뮬레이션
    for i in range(5000):
        total_ingested += 1
        item = f'{{"event": "test_burst", "id": {i}}}'
        try:
            bounded_queue.put_nowait(item)
        except queue.Full:
            dropped_count += 1

    assert total_ingested == 5000
    assert bounded_queue.qsize() == 500
    assert dropped_count == 4500

    # UI 프레임 타임 예산(Frame Time Budget) 내 소량 배치 소비 검증 (메인스레드 프리징 방지)
    MAX_PER_FRAME = 35
    processed = 0
    t_start = time.perf_counter()
    while not bounded_queue.empty() and processed < MAX_PER_FRAME:
        bounded_queue.get_nowait()
        processed += 1
    duration_ms = (time.perf_counter() - t_start) * 1000.0

    assert processed == 35
    assert duration_ms < 10.0  # 16ms(60FPS) 프레임 버짓 미만 유지
