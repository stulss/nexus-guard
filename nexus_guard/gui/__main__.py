# -*- coding: utf-8 -*-
"""NEXUS-GUARD 데스크톱 GUI 콘솔 통합 진입점.

기본적으로 차세대 NativeApp(CustomTkinter HUD)을 기동하며,
`--control-center` 또는 `--classic` 인자 지정 시 클래식 ControlCenter(Tkinter)를 실행합니다.
"""
import argparse
import sys


def main():
    parser = argparse.ArgumentParser(
        description="NEXUS-GUARD Desktop GUI Console Launcher",
        add_help=True,
    )
    parser.add_argument(
        "--control-center",
        "--classic",
        action="store_true",
        dest="control_center",
        help="클래식 엔터프라이즈 관제 센터 (Tkinter 기반) 실행",
    )
    parser.add_argument(
        "--native",
        action="store_true",
        dest="native",
        help="차세대 네이티브 SOC 콘솔 (CustomTkinter HUD 기반, 기본값) 실행",
    )
    args, _ = parser.parse_known_args()

    if args.control_center:
        from .control_center import main as cc_main
        cc_main()
    else:
        from .native_app import main as native_main
        native_main()


if __name__ == "__main__":
    main()
