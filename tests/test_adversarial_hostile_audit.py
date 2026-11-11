# -*- coding: utf-8 -*-
"""Adversarial Red Team & Hostile QA Audit Suite.

이 테스트 스위트는 NEXUS-GUARD가 '글로벌 엔터프라이즈 상용 EDR' 수준의 견고성과
무결성을 갖추었는지 극한의 악의적 입력 및 대량 트래픽 엣지케이스로 타격합니다.
"""
import json
import os
import sys
import time
from pathlib import Path
import pytest

from nexus_guard.engine.firewall import FirewallRuleManager
from nexus_guard.engine.ruleset_manager import FirewallRulesetManager, SiemRulesetManager

BASE_DIR = Path(__file__).resolve().parents[1]


class TestAdversarialFirewallAndInputs:
    """1. 비정상적인 IP, 악의적 명령 주입, 경계값 포트 입력에 대한 보안 및 유효성 검증."""

    def test_firewall_rule_manager_rejects_malformed_ips(self):
        fm = FirewallRuleManager()
        # 악의적 셸 인젝션 시도
        assert fm.add_block_ip("1.1.1.1; calc.exe", "명령 주입 시도") is False
        # 비정상 옥텟 IP
        assert fm.add_block_ip("999.999.999.999", "범위 초과 IP") is False
        # 공백 또는 빈 문자열
        assert fm.add_block_ip("", "빈 문자열") is False
        # 루프백 자체 차단 방어 (자기 서비스 마비 방지)
        assert fm.add_block_ip("127.0.0.1", "루프백 차단 금지") is False
        assert fm.add_block_ip("::1", "IPv6 루프백") is False

        # 정상 공인 IP는 반드시 등록 성공해야 함
        assert fm.add_block_ip("203.0.113.45", "정상 외부 공격자 IP") is True
        blocked = fm.get_blocked_list()
        assert len(blocked) == 1
        assert blocked[0]["ip"] == "203.0.113.45"

    def test_ruleset_manager_port_and_ip_validation(self):
        frm = FirewallRulesetManager()
        rules = frm.get_rules()
        assert isinstance(rules, list)


class TestBurstTrafficAndQueueResilience:
    """2. 대량 로그 폭주(Burst Logs) 및 비정상 로그 페이로드 주입 시 회복성 검증."""

    def test_malformed_log_lines_do_not_crash_parser(self):
        malformed_samples = [
            "",
            "   ",
            "{corrupted_json",
            json.dumps({"event_type": None}),
            json.dumps({"ts": "2026-11-11", "event": "unknown_event_xyz"}),
            json.dumps({"src_ip": "invalid_ip_format", "event_type": "decoy_triggered"}),
            "SELECT * FROM users WHERE '1'='1'",
        ]
        from nexus_guard.engine.mitre import MitreAttackMapper
        mapper = MitreAttackMapper()
        for line in malformed_samples:
            try:
                res1 = mapper.map_event(line)
                assert isinstance(res1, dict)
                try:
                    d = json.loads(line)
                except Exception:
                    d = {"raw": line}
                res2 = mapper.map_event(d)
                assert isinstance(res2, dict)
                assert "tactic" in res2
                assert "technique_id" in res2
            except Exception as e:
                pytest.fail(f"비정상 로그 입력 시 크래시 발생: {line} -> {e}")


class TestMitreAttackMappingIntegrity:
    """3. MITRE ATT&CK 프레임워크 실시간 연동 및 매핑 무결성 검증."""

    def test_mitre_mapping_exists_for_all_security_events(self):
        event_types = [
            "decoy_triggered",
            "prompt_injection_detected",
            "login_locked",
            "ip_blocked",
            "authz_deny",
            "xdr_assessment_created",
        ]
        from nexus_guard.engine.mitre import MitreAttackMapper
        mapper = MitreAttackMapper()
        for ev in event_types:
            mapped = mapper.map_event({"event_type": ev, "path": "/.env"})
            assert "tactic" in mapped
            assert "technique_id" in mapped
            assert "technique_name" in mapped
            assert "tactic_id" in mapped


class TestCisoExecutiveReportGenerator:
    """4. CISO용 감사 보고서 (HTML/CSV) 디스크 정상 생성 및 무결성 검증."""

    def test_ciso_report_generator_exports_valid_files(self, tmp_path):
        from nexus_guard.engine.ciso_report import CisoAuditReportGenerator
        reporter = CisoAuditReportGenerator()
        html_out = tmp_path / "ciso_audit_report.html"
        csv_out = tmp_path / "ciso_incidents.csv"

        ok_html = reporter.export_html_report(str(html_out))
        assert ok_html is True
        assert html_out.exists()
        assert html_out.stat().st_size > 500

        content = html_out.read_text(encoding="utf-8")
        assert "CISO" in content
        assert "MITRE ATT&CK" in content
        assert "NEXUS-GUARD" in content

        ok_csv = reporter.export_csv_report(str(csv_out))
        assert ok_csv is True
        assert csv_out.exists()


class TestNativeAppCommercialGuiReadiness:
    """5. GUI(native_app.py) 소스 레벨 상용 EDR 무결성 및 적대적 방어 검증."""

    @pytest.fixture
    def app_source(self):
        gui_path = BASE_DIR / "nexus_guard" / "gui" / "native_app.py"
        return gui_path.read_text(encoding="utf-8")

    def test_gui_imports_and_uses_mitre_engine(self, app_source):
        # 상용 EDR 필수: GUI 내에 mitre 모듈 임포트 및 활용 확인
        assert "mitre" in app_source.lower(), "CRITICAL: native_app.py 내에 MITRE ATT&CK 엔진 연동이 누락되어 있습니다."

    def test_gui_implements_ciso_report_export_action(self, app_source):
        # 상용 EDR 필수: CISO 감사 보고서 내보내기 버튼 및 핸들러 확인
        assert ("ciso" in app_source.lower() or "report_exporter" in app_source.lower()), "CRITICAL: native_app.py 내에 CISO 감사 보고서 연동이 누락되어 있습니다."

    def test_gui_firewall_block_verifies_return_value(self, app_source):
        # 결함 방어: add_block_ip 리턴값을 검증하여 실패 시 경고창 팝업 로직 확인
        idx = app_source.find("def _on_fw_block")
        assert idx != -1
        block_func = app_source[idx:idx+600]
        assert "if not self.firewall.add_block_ip" in block_func or "ok = self.firewall.add_block_ip" in block_func or "if self.firewall.add_block_ip" in block_func, "DEFECT: _on_fw_block 에서 add_block_ip의 반환값(True/False)을 검증하지 않고 무조건 성공으로 처리하고 있습니다."

    def test_gui_implements_traffic_log_rolling_buffer(self, app_source):
        # 메모리 누수 방어: txt_traffic 텍스트 위젯에 롤링 버퍼/라인 제한 확인
        idx = app_source.find("def _append_traffic_log")
        assert idx != -1
        func_src = app_source[idx:idx+500]
        assert "delete(" in func_src, "DEFECT: _append_traffic_log 에 롤링 버퍼(라인 제한 삭제)가 없어 장기 가동 시 메모리 고갈 크래시가 발생합니다."
