# -*- coding: utf-8 -*-
"""NEXUS-GUARD 클린 슬레이트 및 스캐너 초기화 상태 검증 테스트."""
import inspect
import pytest
from nexus_guard.gui import native_app, control_center


def test_native_app_no_startup_auto_audit():
    """앱 최초 실행 시 _startup_precision_audit 자동 호출 방지 (클린 슬레이트)."""
    init_src = inspect.getsource(native_app.NexusGuardNativeApp.__init__)
    assert "self._startup_precision_audit()" not in init_src, (
        "앱 기동 즉시 _startup_precision_audit()이 실행되면 스코어가 임의 감점되고 "
        "취약점이 사전 노출되므로 __init__에서 호출되어서는 안 됩니다."
    )


def test_native_app_initial_kpi_score_is_100():
    """대시보드 원형 링 게이지 점수 및 서브라벨 100점 클린 상태 검증."""
    sig = inspect.signature(native_app.SecurityScoreRingGauge.__init__)
    assert sig.parameters["score"].default == 100

    widget_src = inspect.getsource(native_app.NexusGuardNativeApp._kpi_score_radial_widget)
    assert "score=100" in widget_src
    assert "A+ 최고 안전 상태 유지" in widget_src
    assert "#10b981" in widget_src


def test_scanner_waiting_state_preserved():
    """취약점 전수 진단 탭 초기 렌더링 시 대기 상태 및 대기 카드 보장."""
    preview_src = inspect.getsource(native_app.NexusGuardNativeApp._render_initial_scan_preview)
    assert "[대기 상태]" in preview_src

    view_src = inspect.getsource(native_app.NexusGuardNativeApp._create_scanner_view)
    assert "대기 중 - [전체 시스템 정밀 진단 시작] 버튼을 눌러 점검을 시작하세요." in view_src
    assert "_render_initial_scan_preview" in view_src


def test_control_center_initial_score_is_100():
    """control_center.py 에서도 초기 안전도 점수가 100/100, A+ 최고 안전 상태 유지인지 검증."""
    dash_src = inspect.getsource(control_center.NexusGuardEnterpriseGUI._build_dashboard_tab)
    assert "100 / 100" in dash_src
    assert "A+ 최고 안전 상태 유지" in dash_src
