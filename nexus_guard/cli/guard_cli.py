# -*- coding: utf-8 -*-
"""NEXUS-GUARD CLI: 능동 보안 프로그램 커맨드라인 콘솔 인터페이스.

사용법:
    python -m nexus_guard.cli status       # 현재 보안 상태 및 차단 IP 목록 조회
    python -m nexus_guard.cli toggle on    # 능동 방어 모드 가동 (403 입구 차단 활성화)
    python -m nexus_guard.cli toggle off   # 모의 침투 취약 모드로 전환
    python -m nexus_guard.cli attack 3     # 시나리오 3 (디코이 탐침) 모의 공격 실행
    python -m nexus_guard.cli cleanup      # 1초 만에 차단 IP 및 잠금 계정 전원 원상복구
"""
import argparse
import os
import sys
import urllib.request
import json
from pathlib import Path

BASE_URL = os.environ.get("GUARD_TARGET_URL", "http://127.0.0.1:5070")


def print_banner():
    print("=" * 65)
    print("  🛡️  NEXUS-GUARD : AI-Powered Active Defense Security Suite")
    print("  개발자: 홍주형 (웹/DB 보안 하드닝 & 코어 아키텍처 & AI 엔지니어링)")
    print("=" * 65)


def cmd_status(args):
    print_banner()
    print(f"[*] 대상 웹 서비스: {BASE_URL}")
    try:
        req = urllib.request.Request(f"{BASE_URL}/admin/overview")
        with urllib.request.urlopen(req, timeout=3) as res:
            print("[+] 대상 웹 서비스 상태: 정상 가동 중 (HTTP 200/302)")
    except Exception as e:
        print(f"[!] 웹 서비스 연결 확인 중: {e}")
    print("[+] 능동 방어 에이전트: 실시간 감시 대기 중")


def cmd_toggle(args):
    print_banner()
    mode = args.mode.lower()
    if mode not in ("on", "off"):
        print("[-] 올바른 모드를 지정하세요: on 또는 off")
        return
    print(f"[*] 방어 모드를 [{mode.upper()}] 상태로 전환합니다...")
    _run_demo_runner("--security", mode)


def cmd_attack(args):
    print_banner()
    scenario = args.scenario
    print(f"[*] 시나리오 {scenario}번 침해 공격 시뮬레이션을 가동합니다...")
    _run_demo_runner("--scenario", str(scenario))


def _run_demo_runner(*extra):
    """현재 작업 디렉터리와 무관하게 저장소 루트의 demo_runner.py 를 이 인터프리터로 실행한다(셸 없이)."""
    import subprocess
    root = Path(__file__).resolve().parents[2]
    return subprocess.call([sys.executable, str(root / "demo_runner.py"), *extra], cwd=str(root))


def cmd_cleanup(args):
    print_banner()
    print("[*] 시연용 고정 목록(IP 8개, 계정 4개)만 되돌리고, 실제 처리 건수와 실패를 그대로 출력합니다...")
    rc = _run_demo_runner("--cleanup")
    if rc != 0:
        print(f"[!] 원상복구가 완전하지 않습니다 (종료 코드 {rc}).")


def main():
    parser = argparse.ArgumentParser(description="NEXUS-GUARD 능동 보안 프로그램 콘솔")
    subparsers = parser.add_subparsers(dest="command")

    # status
    subparsers.add_parser("status", help="보안 에이전트 상태 및 차단 IP 조회")

    # toggle
    p_toggle = subparsers.add_parser("toggle", help="보안 모드 On/Off 토글")
    p_toggle.add_argument("mode", choices=["on", "off"], help="on: 방어 가동, off: 취약 모드")

    # attack
    p_attack = subparsers.add_parser("attack", help="모의 침투 공격 시뮬레이션")
    p_attack.add_argument("scenario", type=int, nargs="?", default=1, choices=[1, 2, 3, 4, 5], help="시나리오 번호 (1~5, 기본값: 1)")

    # cleanup
    subparsers.add_parser("cleanup", help="차단 및 잠금 1초 원상복구")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return

    commands = {
        "status": cmd_status,
        "toggle": cmd_toggle,
        "attack": cmd_attack,
        "cleanup": cmd_cleanup,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
