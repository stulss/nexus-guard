# -*- coding: utf-8 -*-
"""NEXUS-GUARD Core: CISO 엔터프라이즈 감사 보고서 및 무결성 검증 테스트."""
import os
from pathlib import Path
import pytest
from nexus_guard.core.report_exporter import CisoReportExporter


@pytest.fixture
def exporter():
    return CisoReportExporter()


@pytest.fixture
def sample_events():
    return [
        {
            "timestamp": "2026-11-11 10:00:00 UTC",
            "src_ip": "192.168.7.77",
            "username": "attacker",
            "event": "decoy_probe",
            "path": "/.env",
            "action": "403 BLOCKED",
            "detail": "능동형 디코이 허니팟 탐침 감지 및 IP 차단",
        },
        {
            "timestamp": "2026-11-11 10:02:15 UTC",
            "src_ip": "192.168.7.77",
            "username": "anonymous",
            "event": "sqli_blocked",
            "path": "/api/users",
            "action": "403 BLOCKED",
            "detail": "AST 쿼리 정적 분석기: 불법 SQL 구문 차단",
        },
        {
            "timestamp": "2026-11-11 10:05:30 UTC",
            "src_ip": "10.0.0.12",
            "username": "user02",
            "event": "bola_blocked",
            "path": "/approval/sign/104",
            "action": "403 BLOCKED",
            "detail": "5단계 결재 BOLA 비인가 승인 시도 차단",
        },
        {
            "timestamp": "2026-11-11 10:07:00 UTC",
            "src_ip": "127.0.0.1",
            "username": "admin",
            "event": "page_view",
            "path": "/admin/overview",
            "action": "LOGGED",
            "detail": "관리자 대시보드 정상 접근",
        },
    ]


def test_generate_html_report_content_and_structure(exporter, sample_events):
    """HTML 보고서 생성 시 필수 섹션(KPI, MITRE 매트릭스, 컴플라이언스, 타임라인) 온전성 검증."""
    kpi_data = {
        "health_score": 98,
        "blocked_ips_count": 2,
        "containment_status": "NORMAL (대기)",
    }
    html = exporter.generate_html_report(sample_events, kpi_data)

    assert "<!DOCTYPE html>" in html
    assert "CISO 엔터프라이즈 보안 감사 및 위협 대응 보고서" in html
    assert "98 / 100" in html
    assert "A+ OPTIMAL" in html
    assert "T1083" in html  # decoy_probe
    assert "T1190" in html  # sqli_blocked
    assert "T1005" in html  # bola_blocked
    assert "ISO/IEC 27001:2022" in html
    assert "ISMS-P" in html
    assert "SOC 2 Type II" in html
    assert 'name="ciso-report-digest"' in html


def test_generate_csv_report_rfc4180_compliance(exporter, sample_events):
    """CSV 보고서가 RFC 4180 표준 규격 및 포렌식 필수 컬럼을 모두 포함하는지 검증."""
    csv_text = exporter.generate_csv_report(sample_events)
    lines = csv_text.strip().split("\r\n")

    assert len(lines) == 5  # 헤더 1줄 + 이벤트 4줄
    header = lines[0]
    assert "Timestamp" in header
    assert "Source_IP" in header
    assert "MITRE_Tactic" in header
    assert "MITRE_Technique_ID" in header
    assert "Event_Hash" in header

    # 행별 포렌식 데이터 검증
    assert "192.168.7.77" in lines[1]
    assert "T1083" in lines[1]
    assert "T1190" in lines[2]
    assert "T1005" in lines[3]


def test_cryptographic_integrity_verification_success(exporter, sample_events):
    """정상 생성된 HTML 보고서의 암호학적 SHA-256 Seal 무결성 검증 통과."""
    kpi_data = {"health_score": 100}
    html = exporter.generate_html_report(sample_events, kpi_data)
    expected_digest = exporter.calculate_data_digest(sample_events, kpi_data)

    # 1. 자체 무결성 검증
    ok, msg = exporter.verify_report_integrity(html)
    assert ok is True
    assert "무결성 검증 완료" in msg

    # 2. 기대 해시값 일치 검증
    ok_expected, _ = exporter.verify_report_integrity(html, expected_digest=expected_digest)
    assert ok_expected is True


def test_cryptographic_integrity_verification_tamper_detection(exporter, sample_events):
    """보고서 본문 또는 해시가 1글자라도 변조되었을 경우 위변조 탐지 즉시 실패 처리."""
    html = exporter.generate_html_report(sample_events)

    # 1. 임의의 오염된 해시로 기대값 전달 시 실패
    tampered_digest = "a" * 64
    ok, msg = exporter.verify_report_integrity(html, expected_digest=tampered_digest)
    assert ok is False
    assert "서명 불일치" in msg

    # 2. 메타 태그가 훼손되었을 경우 실패
    tampered_html = html.replace('name="ciso-report-digest"', 'name="invalid-tag"')
    ok_no_meta, msg_no_meta = exporter.verify_report_integrity(tampered_html)
    assert ok_no_meta is False
    assert "존재하지 않습니다" in msg_no_meta


def test_export_ciso_bundle_packaging(exporter, sample_events, tmp_path):
    """HTML, CSV, Manifest.json을 포함하는 CISO 엔터프라이즈 감사 증적 번들 생성 검증."""
    out_dir = tmp_path / "ciso_reports"
    bundle = exporter.export_ciso_bundle(sample_events, output_dir=out_dir)

    assert "manifest_path" in bundle
    assert "html_path" in bundle
    assert "csv_path" in bundle
    assert "digest" in bundle

    manifest_file = Path(bundle["manifest_path"])
    html_file = Path(bundle["html_path"])
    csv_file = Path(bundle["csv_path"])

    assert manifest_file.exists()
    assert html_file.exists()
    assert csv_file.exists()

    # 파일 크기 검증
    assert html_file.stat().st_size > 1000
    assert csv_file.stat().st_size > 200

    # 번들 파일 기반 무결성 검증
    ok, _ = exporter.verify_report_integrity(html_file, expected_digest=bundle["digest"])
    assert ok is True


def test_html_xss_injection_prevention(exporter):
    """이벤트 내용에 악의적인 XSS 스크립트가 포함되어 있어도 이스케이프되어 DOM을 오염시키지 않음 검증."""
    malicious_event = [{
        "timestamp": "2026-11-11",
        "src_ip": "1.2.3.4",
        "event": "xss_attempt",
        "path": "/search?q=<script>alert('XSS')</script>",
        "detail": "<img src=x onerror=alert(document.cookie)>",
    }]
    html = exporter.generate_html_report(malicious_event)

    # 원본 원시 태그가 직접 실행되지 않고 HTML 엔티티로 치환되었는지 검증
    assert "<script>alert('XSS')</script>" not in html
    assert "&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;" in html
    assert "&lt;img src=x onerror=alert(document.cookie)&gt;" in html
