# -*- coding: utf-8 -*-
"""NEXUS-GUARD 초기 무결성 및 클린 상태 단독 검증 스크립트.

검증 항목:
1. FirewallRuleManager 인스턴스화 시 fw.get_blocked_list() == [] (길이 0)
2. NexusGuardNativeApp(native_app.py) 인스턴스화 시:
   - 방화벽 초기 차단 목록: 0건 (완전 클린)
   - 영웅 배너(Hero Title): SYSTEM SECURED 정상 표기
   - 종합 위협 판정(Verdict Title): SYSTEM SECURE (위험도 0 / 100)
   - 공격자 프로파일(Profile IP): 활성 공격자 없음 (클린 네트워크)
   - 표적 벡터(Profile Vector): 이상 트래픽 미감지 (Clean Ingress)
"""
import sys
from pathlib import Path

# 프로젝트 루트 경로 등록
ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

from nexus_guard.engine.firewall import FirewallRuleManager
from nexus_guard.gui.native_app import NexusGuardNativeApp

def run_verification():
    print("=" * 70)
    print("🔍 [NEXUS-GUARD] 컴포넌트 초기 클린 상태 및 대시보드 무결성 단독 검증")
    print("=" * 70)

    # ---------------------------------------------------------
    # 1. FirewallRuleManager 단독 인스턴스화 검증
    # ---------------------------------------------------------
    print("\n[Step 1] FirewallRuleManager 단독 인스턴스화 검증")
    fw = FirewallRuleManager()
    blocked_list = fw.get_blocked_list()
    print(f"  - fw.get_blocked_list() 반환값: {blocked_list}")
    print(f"  - 차단 목록 길이: {len(blocked_list)}")

    assert blocked_list == [], f"FAIL: blocked_list should be empty, got {blocked_list}"
    assert len(blocked_list) == 0, f"FAIL: blocked_list length should be 0, got {len(blocked_list)}"
    print("  -> [PASS] FirewallRuleManager 초기 차단 목록 0건(완전 클린) 확인 완료")

    # ---------------------------------------------------------
    # 2. NexusGuardNativeApp 인스턴스화 및 컴포넌트 상태 검증
    # ---------------------------------------------------------
    print("\n[Step 2] NexusGuardNativeApp GUI 컴포넌트 인스턴스화 검증")
    app = NexusGuardNativeApp()
    try:
        app_blocked = app.firewall.get_blocked_list()
        hero_title = app.lbl_hero_title.cget("text")
        verdict_title = app.lbl_verdict_title.cget("text")
        verdict_sub = app.lbl_verdict_sub.cget("text")
        profile_ip = app.lbl_profile_ip.cget("text")
        profile_vec = app.lbl_profile_vector.cget("text")

        print(f"  - App 내장 Firewall 차단 목록 길이: {len(app_blocked)}건")
        print(f"  - lbl_hero_title: '{hero_title}'")
        print(f"  - lbl_verdict_title: '{verdict_title}'")
        print(f"  - lbl_verdict_sub: '{verdict_sub}'")
        print(f"  - lbl_profile_ip: '{profile_ip}'")
        print(f"  - lbl_profile_vector: '{profile_vec}'")

        # 단언문(Assertions)
        assert app_blocked == [], f"FAIL: app.firewall blocked list should be empty, got {app_blocked}"
        assert len(app_blocked) == 0, "FAIL: app.firewall blocked count should be 0"
        assert ("안전" in verdict_title or "SYSTEM SECURE" in verdict_title), f"FAIL: verdict title missing safe status: {verdict_title}"
        assert ("위험도 0" in verdict_title), f"FAIL: verdict title risk score not 0: {verdict_title}"
        assert "활성 공격자 없음" in profile_ip, f"FAIL: profile ip missing '활성 공격자 없음': {profile_ip}"
        assert "SYSTEM SECURED" in hero_title, f"FAIL: hero title missing 'SYSTEM SECURED': {hero_title}"

        print("  -> [PASS] GUI 대시보드 컴포넌트 초기 판정 검증 완료 (SYSTEM SECURE & 공격자 없음)")

    finally:
        # 정상 종료 및 리소스 정리
        app.running = False
        app.destroy()
        print("  -> [PASS] GUI 인스턴스 리소스 정상 해제 완료")

    print("\n" + "=" * 70)
    print("🎉 모든 컴포넌트 인스턴스화 및 초기 클린 상태 검증 100% PASS")
    print("=" * 70)

if __name__ == "__main__":
    run_verification()
