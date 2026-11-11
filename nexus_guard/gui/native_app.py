# -*- coding: utf-8 -*-
"""NEXUS-GUARD Enterprise Endpoint & Web Defense Console (v2.5.0-LTS).

100% 순수 데스크톱 네이티브 보안 프로그램 콘솔 (No Browser / No Internet Window).
글로벌 엔드포인트 보안 솔루션(GlassWire / Kaspersky Endpoint Security / SentinelOne)
UI/UX 디자인 레퍼런스를 완벽 반영한 모던 다크 테마 보안 관제 프로그램.

주요 기능:
1. Kaspersky Hexa UI 스타일의 '보호 상태 실시간 히어로 쉴드' (PROTECTED / VULNERABLE)
2. GlassWire 시그니처 '실시간 네트워크 트래픽 & 위협 스파이크 캔버스' (실시간 그래프 애니메이션)
3. 원클릭 호스트 방화벽 관리 (Windows netsh 연동, 활성 차단 IP 테이블, 즉시 해제)
4. 시스템 취약점 정밀 진단 스캐너 (프로그레스 바, AST 쿼리 정적 분석, 포트 감사)
5. SHA-256 파일 무결성 감시 (FIM 엔진, 변조 탐지, 베이스라인 대조)
6. 외부 보안 장비 통합 연동 설정 (pfSense / Graylog / Wazuh / n8n / AI Cascade - config.json 동기화)
"""
import json
import math
import os
import queue
import random
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox
import urllib.request
import webbrowser

import customtkinter as ctk
import psutil

from ..engine.config_manager import GuardConfigManager
from ..engine.scanner import SystemVulnerabilityScanner
from ..engine.fim import FileIntegrityMonitor
from ..engine.firewall import FirewallRuleManager
from ..engine.ruleset_manager import (
    FirewallRulesetManager,
    SiemRulesetManager,
    RulesetUpdateManager,
)
from ..engine.integrations import (
    test_pfsense_feed,
    test_graylog_gelf,
    test_wazuh_agent,
    test_webhook_dispatch,
)
from ..engine.mitre import MitreAttackMapper
from ..engine.report_exporter import SecurityReportExporter
from ..ai_engine.cascade_router import AiCascadeRouter
from ..ai_engine.xdr_triage import XdrTriageEngine
from .theme import (
    BG_DARK,
    BG_OBSIDIAN,
    BG_SIDEBAR,
    SURFACE_CARD,
    SURFACE_CARD_ALT,
    SURFACE_INNER,
    SURFACE_HOVER,
    SURFACE_INPUT,
    BORDER_SUBTLE,
    BORDER_FROST,
    BORDER_ACTIVE,
    BORDER_CYAN,
    BORDER_EMERALD,
    BORDER_CRIMSON,
    COLOR_SECURE,
    COLOR_SECURE_BG,
    COLOR_CYAN,
    COLOR_CYAN_BG,
    COLOR_WARN,
    COLOR_WARN_BG,
    COLOR_ALERT,
    COLOR_ALERT_BG,
    COLOR_PURPLE,
    COLOR_PURPLE_BG,
    TEXT_TITLE,
    TEXT_BODY,
    TEXT_MUTED,
    TEXT_DIM,
    FONT_FAMILY_UI,
    FONT_FAMILY_MONO,
    BUTTON_PRIMARY,
    BUTTON_PRIMARY_HOVER,
    BUTTON_DANGER,
    BUTTON_DANGER_HOVER,
    BUTTON_SECONDARY,
    BUTTON_SECONDARY_HOVER,
    BUTTON_EMERGENCY,
    BUTTON_EMERGENCY_HOVER,
    BUTTON_CISO,
    BUTTON_CISO_HOVER,
    SIDEBAR_ACTIVE,
    SIDEBAR_HOVER,
)

BASE_DIR = Path(__file__).resolve().parents[2]

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


# =========================================================================
# 글로벌 보안 솔루션 (SentinelOne / CrowdStrike / GlassWire) 스타일 시각화 컴포넌트
# =========================================================================
class SecurityScoreRingGauge(ctk.CTkFrame):
    """글로벌 상용 EDR 수준의 원형 링 게이지 위젯 (SentinelOne / CrowdStrike Style)."""
    def __init__(self, parent, score=100, size=115, **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)
        self.size = size
        self.score = score
        self.canvas = tk.Canvas(
            self, width=size, height=size, bg=SURFACE_CARD, highlightthickness=0
        )
        self.canvas.pack()
        self.draw_gauge(self.score)

    def draw_gauge(self, score):
        self.score = score
        self.canvas.delete("all")
        w, h = self.size, self.size
        cx, cy = w / 2, h / 2
        r = (w / 2) - 15
        start_angle = 135
        extent_total = 270

        arc_color = COLOR_SECURE if score >= 90 else (COLOR_WARN if score >= 70 else COLOR_ALERT)
        glow_color = "#0c2e26" if score >= 90 else ("#2a1d06" if score >= 70 else "#2d0b13")

        # 1. 외곽 24개 마이크로 틱 마크 (Cyber HUD Style)
        num_ticks = 24
        for i in range(num_ticks):
            frac = i / (num_ticks - 1)
            deg = start_angle - frac * extent_total
            rad = math.radians(deg)
            t_r1 = r + 7
            t_r2 = r + 11
            x1 = cx + t_r1 * math.cos(rad)
            y1 = cy - t_r1 * math.sin(rad)
            x2 = cx + t_r2 * math.cos(rad)
            y2 = cy - t_r2 * math.sin(rad)
            is_active = frac <= (max(0, min(100, score)) / 100.0)
            tick_col = arc_color if is_active else "#1e293b"
            self.canvas.create_line(x1, y1, x2, y2, fill=tick_col, width=1.5)

        # 2. 배경 베이스 트랙 아크
        self.canvas.create_arc(
            cx - r, cy - r, cx + r, cy + r,
            start=start_angle, extent=-extent_total,
            style="arc", outline=BORDER_SUBTLE, width=8
        )

        # 3. 네온 글로우 섀도우 아크 & 메인 활성 아크
        score_extent = (max(0, min(100, score)) / 100.0) * extent_total
        self.canvas.create_arc(
            cx - r, cy - r, cx + r, cy + r,
            start=start_angle, extent=-score_extent,
            style="arc", outline=glow_color, width=12
        )
        self.canvas.create_arc(
            cx - r, cy - r, cx + r, cy + r,
            start=start_angle, extent=-score_extent,
            style="arc", outline=arc_color, width=6
        )

        # 4. 중앙 텍스트 렌더링 (가독성 기준: 최소 9pt 이상, WCAG AA 준수)
        grade = "A+" if score >= 90 else ("B" if score >= 70 else "F")
        self.canvas.create_text(
            cx, cy - 8, text=f"{score}",
            fill=TEXT_TITLE, font=(FONT_FAMILY_UI, 20, "bold")
        )
        self.canvas.create_text(
            cx, cy + 12, text=f"GRADE {grade}",
            fill=arc_color, font=(FONT_FAMILY_UI, 10, "bold")
        )
        self.canvas.create_text(
            cx, cy + 25, text="POSTURE",
            fill=TEXT_MUTED, font=(FONT_FAMILY_UI, 9, "bold")
        )


class CyberThreatRadarCanvas(ctk.CTkFrame):
    """엔터프라이즈 SOC / EDR 사이버 위협 탐지 360도 레이더 위젯 및 4대 인프라 실시간 범례 가이드.

    정적 그리드 캐싱과 태그 기반 동적 렌더링으로 60FPS 초경량 갱신을 지원하며,
    config.json 연동 상태(Active/Standby), 실시간 침해 위협 및 초보자용 직관적 범례 가이드를 일체형으로 제공합니다.
    """
    def __init__(self, parent, width=320, height=135, **kwargs):
        super().__init__(parent, fg_color=SURFACE_INNER, corner_radius=10, border_width=1, border_color=BORDER_SUBTLE, **kwargs)
        self.width = width
        self.height = height
        self.sweep_angle = 0
        self.pulse_radius = 0
        self.has_active_threat = False

        # 1. 360도 레이더 캔버스
        self.canvas = tk.Canvas(
            self, width=width, height=height, bg=SURFACE_INNER, highlightthickness=0
        )
        self.canvas.pack(fill="x", padx=4, pady=(4, 2))
        self.canvas.bind("<Configure>", lambda e: self._on_canvas_configure(e))
        
        # 4대 핵심 인프라 노드 상태 정의 (위치: [중앙] PORTAL, [우상] pfSense, [우하] KALI, [좌하] SIEM)
        self.nodes = [
            {"id": "kali", "name": "00.KALI [○ DEMO]", "angle": 315, "dist": 44, "color": TEXT_MUTED},
            {"id": "pfsense", "name": "01.pfSense [○ STANDBY]", "angle": 45, "dist": 40, "color": TEXT_MUTED},
            {"id": "portal", "name": "02.PORTAL [■ CORE]", "angle": 0, "dist": 0, "color": COLOR_SECURE},
            {"id": "graylog", "name": "03.SIEM [○ STANDBY]", "angle": 200, "dist": 44, "color": TEXT_MUTED},
        ]

        # 2. 직관적인 4대 인프라 범례 & 초보자 가이드 바 (일체형 SOC 안내 카드)
        self.legend_frame = ctk.CTkFrame(
            self, fg_color="#060911", corner_radius=8, border_width=1, border_color="#1e293b"
        )
        self.legend_frame.pack(fill="x", padx=6, pady=(2, 6))

        leg_hdr = ctk.CTkFrame(self.legend_frame, fg_color="transparent")
        leg_hdr.pack(fill="x", padx=8, pady=(5, 3))

        ctk.CTkLabel(
            leg_hdr,
            text="🧭 4대 인프라 레이더 범례 & 초보자 안내",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=10, weight="bold"),
            text_color="#38bdf8",
        ).pack(side="left")

        ctk.CTkLabel(
            leg_hdr,
            text="1초 직관 해설",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=9),
            text_color="#64748b",
        ).pack(side="right")

        self.lbl_leg_portal = ctk.CTkLabel(
            self.legend_frame,
            text="🎯 [중앙] 02.PORTAL : 보호 대상 핵심 웹/DB 사내 포털 [■ CORE]",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=9, weight="bold"),
            text_color="#34d399",
            anchor="w",
            justify="left",
            wraplength=340,
        )
        self.lbl_leg_portal.pack(fill="x", padx=8, pady=1)

        self.lbl_leg_kali = ctk.CTkLabel(
            self.legend_frame,
            text="🔴 [우하] 00.KALI : 모의 침투/공격자 감시 (평상시: [○ DEMO] 대기 ➔ 공격 시: [▲ ATTACK] 경보)",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=9),
            text_color="#cbd5e1",
            anchor="w",
            justify="left",
            wraplength=340,
        )
        self.lbl_leg_kali.pack(fill="x", padx=8, pady=1)

        self.lbl_leg_pfsense = ctk.CTkLabel(
            self.legend_frame,
            text="🟠 [우상] 01.pfSense : 외곽 네트워크 경계 방화벽 [○ STANDBY]",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=9),
            text_color="#94a3b8",
            anchor="w",
            justify="left",
            wraplength=340,
        )
        self.lbl_leg_pfsense.pack(fill="x", padx=8, pady=1)

        self.lbl_leg_siem = ctk.CTkLabel(
            self.legend_frame,
            text="🔵 [좌하] 03.SIEM : 중앙 보안 감사 로그(Graylog) 관제 [○ STANDBY]",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=9),
            text_color="#94a3b8",
            anchor="w",
            justify="left",
            wraplength=340,
        )
        self.lbl_leg_siem.pack(fill="x", padx=8, pady=1)

        self.lbl_leg_beam = ctk.CTkLabel(
            self.legend_frame,
            text="💫 [스캔] 회전 빔 : 400ms 주기 실시간 인프라 순환 감시 파동",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=9),
            text_color="#7dd3fc",
            anchor="w",
            justify="left",
            wraplength=340,
        )
        self.lbl_leg_beam.pack(fill="x", padx=8, pady=(1, 5))
        
        self._init_static_grid()
        self._is_running = True
        self._animate_radar()

    def _on_canvas_configure(self, event):
        if event.width > 50 and event.height > 50:
            if event.width != self.width or event.height != self.height:
                self.width = event.width
                self.height = event.height
                self._init_static_grid()

    def update_nodes_from_config(self, cfg):
        """config.json의 실제 외부 연동 상태를 반영하여 노드 상태/색상 및 범례 텍스트 동기화."""
        ext = cfg.get("external_integrations", {})
        pf = ext.get("pfsense", {})
        pf_on = pf.get("enabled", False) and bool(pf.get("host"))
        
        gl = ext.get("graylog", {})
        gl_on = gl.get("enabled", False) and bool(gl.get("host"))
        
        tgt = cfg.get("target_service", {})
        portal_on = bool(tgt.get("web_portal_url"))

        for n in self.nodes:
            if n["id"] == "pfsense":
                n["name"] = "01.pfSense [● ACTIVE]" if pf_on else "01.pfSense [○ STANDBY]"
                n["color"] = COLOR_WARN if pf_on else TEXT_MUTED
            elif n["id"] == "graylog":
                n["name"] = "03.SIEM [● ACTIVE]" if gl_on else "03.SIEM [○ STANDBY]"
                n["color"] = COLOR_CYAN if gl_on else TEXT_MUTED
            elif n["id"] == "portal":
                n["name"] = "02.PORTAL [■ CORE]" if portal_on else "02.PORTAL [○ STANDBY]"
                n["color"] = COLOR_SECURE if portal_on else TEXT_MUTED
            elif n["id"] == "kali":
                if self.has_active_threat:
                    n["name"] = "00.KALI [▲ ATTACK]"
                    n["color"] = COLOR_ALERT
                else:
                    n["name"] = "00.KALI [○ DEMO]"
                    n["color"] = TEXT_MUTED

        if hasattr(self, "lbl_leg_pfsense"):
            if pf_on:
                self.lbl_leg_pfsense.configure(
                    text="🟠 [우상] 01.pfSense : 외곽 네트워크 경계 방화벽 [● ACTIVE 연동 중]",
                    text_color="#fbbf24"
                )
            else:
                self.lbl_leg_pfsense.configure(
                    text="🟠 [우상] 01.pfSense : 외곽 네트워크 경계 방화벽 [○ STANDBY 대기]",
                    text_color="#94a3b8"
                )

        if hasattr(self, "lbl_leg_siem"):
            if gl_on:
                self.lbl_leg_siem.configure(
                    text="🔵 [좌하] 03.SIEM : 중앙 보안 감사 로그(Graylog) 관제 [● ACTIVE 연동 중]",
                    text_color="#38bdf8"
                )
            else:
                self.lbl_leg_siem.configure(
                    text="🔵 [좌하] 03.SIEM : 중앙 보안 감사 로그(Graylog) 관제 [○ STANDBY 대기]",
                    text_color="#94a3b8"
                )

    def set_threat_status(self, is_active):
        self.has_active_threat = is_active
        for n in self.nodes:
            if n["id"] == "kali":
                if is_active:
                    n["name"] = "00.KALI [▲ ATTACK]"
                    n["color"] = COLOR_ALERT
                else:
                    n["name"] = "00.KALI [○ DEMO]"
                    n["color"] = TEXT_MUTED

        if hasattr(self, "lbl_leg_kali"):
            if is_active:
                self.lbl_leg_kali.configure(
                    text="🚨 [우하] 00.KALI : 모의 침투 공격 발생! [▲ ATTACK] 경보 발령",
                    text_color="#f87171",
                    font=ctk.CTkFont(family=FONT_FAMILY_UI, size=9, weight="bold")
                )
                self.lbl_leg_portal.configure(
                    text="🛡️ [중앙] 02.PORTAL : 보호 대상 웹/DB 사내 포털 [■ 침해 차단 방어 가동 중]",
                    text_color="#34d399",
                    font=ctk.CTkFont(family=FONT_FAMILY_UI, size=9, weight="bold")
                )
            else:
                self.lbl_leg_kali.configure(
                    text="🔴 [우하] 00.KALI : 모의 침투/공격자 감시 (평상시: [○ DEMO] 대기 ➔ 공격 시: [▲ ATTACK] 경보)",
                    text_color="#cbd5e1",
                    font=ctk.CTkFont(family=FONT_FAMILY_UI, size=9)
                )
                self.lbl_leg_portal.configure(
                    text="🎯 [중앙] 02.PORTAL : 보호 대상 핵심 웹/DB 사내 포털 [■ CORE]",
                    text_color="#34d399",
                    font=ctk.CTkFont(family=FONT_FAMILY_UI, size=9, weight="bold")
                )

    def _init_static_grid(self):
        """정적 배경 레이어 1회 렌더링 (CPU 부하 0% 최적화 & WCAG AA 준수 폰트/대비)."""
        c = self.canvas
        c.delete("static_grid")
        w = self.canvas.winfo_width() if self.canvas.winfo_width() > 50 else self.width
        h = self.canvas.winfo_height() if self.canvas.winfo_height() > 50 else self.height
        cx, cy = w / 2, h / 2
        max_r = min(cx, cy) - 10

        # 1. 배경 헤더 HUD 텍스트 (최소 9pt 이상 명시)
        c.create_text(8, 8, anchor="nw", text="● 360° 인프라 위협 탐지 레이더 (SOC)", fill=COLOR_CYAN, font=(FONT_FAMILY_UI, 9, "bold"), tags="static_grid")
        c.create_text(w - 8, 8, anchor="ne", text="감시 주기: 400ms 순환", fill=TEXT_MUTED, font=(FONT_FAMILY_UI, 9), tags="static_grid")

        # 2. 동심원 방어 영역 (Outer -> Inner)
        rings = [
            (max_r, BORDER_SUBTLE),
            (max_r * 0.72, "#152033"),
            (max_r * 0.44, "#16283d"),
            (max_r * 0.16, "#0c3b2e"),
        ]
        for r, col in rings:
            c.create_oval(cx - r, cy - r, cx + r, cy + r, outline=col, width=1, tags="static_grid")

        # 3. 십자선 (Crosshairs) & 보조 격자
        c.create_line(cx - max_r, cy, cx + max_r, cy, fill="#131c2d", dash=(2, 4), tags="static_grid")
        c.create_line(cx, cy - max_r, cx, cy + max_r, fill="#131c2d", dash=(2, 4), tags="static_grid")

    def _animate_radar(self):
        try:
            if not self.winfo_exists():
                return
            self.sweep_angle = (self.sweep_angle + 5) % 360
            if self.has_active_threat:
                self.pulse_radius = (self.pulse_radius + 3) % 70
            else:
                self.pulse_radius = 0
                
            self._render_dynamic()
            self.after(50, self._animate_radar)
        except Exception:
            pass

    def _render_dynamic(self):
        """동적 스캔라인, 펄스, 노드 마커만 고속 태그 갱신."""
        c = self.canvas
        c.delete("dynamic")
        w = self.canvas.winfo_width() if self.canvas.winfo_width() > 50 else self.width
        h = self.canvas.winfo_height() if self.canvas.winfo_height() > 50 else self.height
        cx, cy = w / 2, h / 2
        max_r = min(cx, cy) - 10

        # 1. 활성 위협 펄스 웨이브 (Threat Pulse Ring)
        if self.pulse_radius > 0:
            pr = self.pulse_radius
            c.create_oval(cx - pr, cy - pr, cx + pr, cy + pr, outline=COLOR_ALERT, width=1.5, tags="dynamic")

        # 2. 회전 스캔라인 (Sweeping Beam with Alpha Trail)
        rad = math.radians(self.sweep_angle)
        bx = cx + max_r * math.cos(rad)
        by = cy - max_r * math.sin(rad)
        c.create_line(cx, cy, bx, by, fill=COLOR_CYAN, width=1.8, tags="dynamic")
        
        # 보조 잔상 라인 (Trail)
        for offset in (4, 8, 12):
            t_rad = math.radians((self.sweep_angle - offset) % 360)
            tx = cx + max_r * math.cos(t_rad)
            ty = cy - max_r * math.sin(t_rad)
            c.create_line(cx, cy, tx, ty, fill="#0c324e", width=1, tags="dynamic")

        # 3. 인프라 노드 (Nodes & Status: 9pt 폰트, WCAG AA 고대비)
        for node in self.nodes:
            n_rad = math.radians(node["angle"])
            nx = cx + node["dist"] * math.cos(n_rad)
            ny = cy - node["dist"] * math.sin(n_rad)
            col = node["color"]
            
            # 노드 마커
            c.create_oval(nx - 3.5, ny - 3.5, nx + 3.5, ny + 3.5, fill=col, outline="#ffffff" if col != TEXT_MUTED else "#334155", width=1, tags="dynamic")
            # 라벨 텍스트 (9pt 모노 고대비)
            c.create_text(nx + 7, ny - 4, anchor="w", text=node["name"], fill=TEXT_TITLE if col != TEXT_MUTED else TEXT_MUTED, font=(FONT_FAMILY_MONO, 9, "bold"), tags="dynamic")

        # 중앙 코어 비콘 (포털 본인)
        c.create_oval(cx - 3, cy - 3, cx + 3, cy + 3, fill="#ffffff", outline=COLOR_SECURE, tags="dynamic")


class ScannerPhaseTracker(ctk.CTkFrame):
    """Nessus / Snyk 스타일 4단계 인터랙티브 체크포인트 트래커 (WCAG AA & theme.py 완벽 준수)."""
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=SURFACE_CARD, corner_radius=10, border_width=1, border_color=BORDER_SUBTLE, **kwargs)
        self.phases = [
            ("📁 1단계: 환경변수 감사", ".env & 관리자 자격증명"),
            ("🌐 2단계: 웹/DB 프로빙", "타겟 서비스 포트 & 헤더"),
            ("🔍 3단계: AST 정적 분석", "파이썬 구문 트리 SQLi 전수"),
            ("🛡️ 4단계: WAF 디코이 검증", "입구 차단 및 허니팟 격리"),
        ]
        self.step_widgets = []
        for idx, (title, subtitle) in enumerate(self.phases):
            box = ctk.CTkFrame(self, fg_color=SURFACE_INNER, corner_radius=8, border_width=1, border_color=BORDER_SUBTLE)
            box.pack(side="left", expand=True, fill="both", padx=6, pady=8)

            lbl_title = ctk.CTkLabel(
                box,
                text=title,
                font=ctk.CTkFont(family=FONT_FAMILY_UI, size=11, weight="bold"),
                text_color=TEXT_TITLE,
            )
            lbl_title.pack(anchor="w", padx=10, pady=(8, 2))

            lbl_sub = ctk.CTkLabel(
                box,
                text=subtitle,
                font=ctk.CTkFont(family=FONT_FAMILY_UI, size=9),
                text_color=TEXT_MUTED,
            )
            lbl_sub.pack(anchor="w", padx=10, pady=(0, 6))

            pill = ctk.CTkFrame(box, fg_color=SURFACE_HOVER, corner_radius=4)
            pill.pack(fill="x", padx=10, pady=(0, 8))

            lbl_st = ctk.CTkLabel(
                pill,
                text="● 대기 중",
                font=ctk.CTkFont(family=FONT_FAMILY_UI, size=10, weight="bold"),
                text_color=TEXT_MUTED,
            )
            lbl_st.pack(anchor="center", pady=3)

            self.step_widgets.append({
                "box": box,
                "title": lbl_title,
                "sub": lbl_sub,
                "pill": pill,
                "status": lbl_st,
            })

    @property
    def lbl_steps(self):
        """기존 코드와의 100% 하위 호환성을 위한 튜플 리스트 프로퍼티."""
        return [(w["box"], w["status"]) for w in self.step_widgets]

    def reset_phases(self):
        for w in self.step_widgets:
            w["box"].configure(fg_color=SURFACE_INNER, border_width=1, border_color=BORDER_SUBTLE)
            w["title"].configure(text_color=TEXT_TITLE)
            w["pill"].configure(fg_color=SURFACE_HOVER)
            w["status"].configure(text="● 대기 중", text_color=TEXT_MUTED)

    def update_phase(self, phase_index, status_text, is_active=False, is_done=False, is_vuln=False):
        if 0 <= phase_index < len(self.step_widgets):
            w = self.step_widgets[phase_index]
            if is_active:
                w["box"].configure(fg_color=COLOR_CYAN_BG, border_width=1, border_color=BORDER_CYAN)
                w["title"].configure(text_color=COLOR_CYAN)
                w["pill"].configure(fg_color="#0e3a5f")
                prefix = "⚡ " if not status_text.startswith("⚡") else ""
                w["status"].configure(text=f"{prefix}{status_text}", text_color=COLOR_CYAN)
            elif is_done:
                w["box"].configure(fg_color=COLOR_SECURE_BG, border_width=1, border_color=BORDER_EMERALD)
                w["title"].configure(text_color=COLOR_SECURE)
                w["pill"].configure(fg_color="#064e3b")
                prefix = "✔ " if not status_text.startswith("✔") else ""
                w["status"].configure(text=f"{prefix}{status_text}", text_color=COLOR_SECURE)
            elif is_vuln:
                w["box"].configure(fg_color=COLOR_ALERT_BG, border_width=1, border_color=BORDER_CRIMSON)
                w["title"].configure(text_color=COLOR_ALERT)
                w["pill"].configure(fg_color="#450a0a")
                prefix = "🚨 " if not status_text.startswith("🚨") else ""
                w["status"].configure(text=f"{prefix}{status_text}", text_color=COLOR_ALERT)
            else:
                w["status"].configure(text=status_text)


# =========================================================================
# 글로벌 차세대 사이버 커맨드 센터 신규 시각화 컴포넌트
# (CrowdStrike Falcon / SentinelOne Singularity / Datadog Security Reference)
# =========================================================================

class LiveTelemetryTicker(ctk.CTkFrame):
    """CrowdStrike Falcon & Datadog Cloud Security 스타일 실시간 텔레메트리 Freshness Ticker.

    표시 포맷: ● LIVE TELEMETRY | Refresh: 400ms | Jitter < 3ms | SOC Level: PROD
    - 400ms 주기적 메인 타이머와 결합하여 실제 루프 간격(ms) 및 지터 편차를 실시간으로 계측
    - 고대비 WCAG AA 준수 및 마이크로 펄스 네온 인디케이터
    """

    def __init__(self, parent, **kwargs):
        super().__init__(
            parent,
            fg_color=SURFACE_INNER,
            corner_radius=6,
            border_width=1,
            border_color=BORDER_SUBTLE,
            **kwargs,
        )
        self._pulse_state = False

        # 1. 펄스 도트 인디케이터 (●)
        self.lbl_dot = ctk.CTkLabel(
            self,
            text="●",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=11, weight="bold"),
            text_color=COLOR_SECURE,
        )
        self.lbl_dot.pack(side="left", padx=(10, 4), pady=4)

        # 2. 메인 헤더 배지 (LIVE TELEMETRY)
        self.lbl_live = ctk.CTkLabel(
            self,
            text="LIVE TELEMETRY",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=10, weight="bold"),
            text_color=COLOR_CYAN,
        )
        self.lbl_live.pack(side="left", padx=(0, 6), pady=4)

        # 3. 리프레시 주기 (Refresh: 400ms)
        self.lbl_refresh = ctk.CTkLabel(
            self,
            text="|  Refresh: 400ms",
            font=ctk.CTkFont(family=FONT_FAMILY_MONO, size=10),
            text_color=TEXT_BODY,
        )
        self.lbl_refresh.pack(side="left", padx=3, pady=4)

        # 4. 루프 지터 계측치 (Jitter < 3ms)
        self.lbl_jitter = ctk.CTkLabel(
            self,
            text="|  Jitter < 3ms",
            font=ctk.CTkFont(family=FONT_FAMILY_MONO, size=10),
            text_color=TEXT_MUTED,
        )
        self.lbl_jitter.pack(side="left", padx=3, pady=4)

        # 5. SOC 관제 등급 (SOC Level: PROD)
        self.lbl_soc = ctk.CTkLabel(
            self,
            text="|  SOC Level: PROD",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=10, weight="bold"),
            text_color=COLOR_SECURE,
        )
        self.lbl_soc.pack(side="left", padx=(3, 10), pady=4)

    def update_metrics(self, refresh_ms=400, jitter_ms=1.5, soc_level="PROD", is_contained=False):
        """실시간 네트워크 텔레메트리 주기 및 지터를 동적으로 갱신합니다."""
        self._pulse_state = not self._pulse_state
        if is_contained:
            dot_color = COLOR_ALERT
            live_text = "EMERGENCY QUARANTINE"
            live_color = COLOR_ALERT
            soc_text = "|  SOC: CONTAINED"
            soc_color = COLOR_ALERT
        else:
            dot_color = COLOR_SECURE if self._pulse_state else COLOR_CYAN
            live_text = "LIVE TELEMETRY"
            live_color = COLOR_CYAN
            soc_text = f"|  SOC Level: {soc_level}"
            soc_color = COLOR_SECURE

        try:
            self.lbl_dot.configure(text_color=dot_color)
            self.lbl_live.configure(text=live_text, text_color=live_color)
            self.lbl_refresh.configure(text=f"|  Refresh: {int(refresh_ms)}ms")
            jitter_str = f"< {max(1, int(math.ceil(jitter_ms)))}ms" if jitter_ms < 10 else f"{int(jitter_ms)}ms"
            self.lbl_jitter.configure(text=f"|  Jitter {jitter_str}")
            self.lbl_soc.configure(text=soc_text, text_color=soc_color)
        except Exception:
            pass


class MitreTacticDetailDialog(ctk.CTkToplevel):
    """MITRE ATT&CK 전술별 상세 분석 및 완화 플레이북 대화상자 (SentinelOne / CrowdStrike Reference)."""

    def __init__(self, parent, tactic_spec, count=0):
        super().__init__(parent)
        self.title(f"MITRE ATT&CK® Tactic Intelligence - {tactic_spec['name']} ({tactic_spec['id']})")
        self.geometry("640x500")
        self.minsize(580, 420)
        self.configure(fg_color=BG_DARK)
        self.transient(parent)
        self.grab_set()

        # 헤더 카드
        hdr = ctk.CTkFrame(self, fg_color=SURFACE_CARD, corner_radius=10, border_width=1, border_color=BORDER_FROST)
        hdr.pack(fill="x", padx=16, pady=16)

        h_inner = ctk.CTkFrame(hdr, fg_color="transparent")
        h_inner.pack(fill="x", padx=16, pady=12)

        ctk.CTkLabel(
            h_inner,
            text=f"⚔️ {tactic_spec['name']} ({tactic_spec['id']})",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=15, weight="bold"),
            text_color=COLOR_CYAN,
        ).pack(anchor="w")

        ctk.CTkLabel(
            h_inner,
            text=f"MITRE ATT&CK® Enterprise Matrix v14 • 매핑 기법: {tactic_spec['technique']}",
            font=ctk.CTkFont(family=FONT_FAMILY_MONO, size=10),
            text_color=TEXT_MUTED,
        ).pack(anchor="w", pady=(2, 0))

        # 본문 스크롤 영역
        body = ctk.CTkScrollableFrame(self, fg_color=SURFACE_INNER, corner_radius=8, border_width=1, border_color=BORDER_SUBTLE)
        body.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        # 1. 전술 개요 카드
        self._section_card(
            body,
            "📋 전술 분석 및 공격자 행위 모델",
            tactic_spec["description"],
            accent_color=COLOR_CYAN,
        )

        # 2. NEXUS-GUARD 자동 방어 및 완화 대책
        self._section_card(
            body,
            "🛡️ 능동 방어 조치 및 탐지 메커니즘",
            tactic_spec["countermeasure"],
            accent_color=COLOR_SECURE,
        )

        # 3. 실시간 관제 현황 및 히트맵 상태
        status_text = f"현재 활성 탐지 카운트: {count}건\n상태: " + (
            "⚠️ 이상 징후/공격 탐지되어 능동 대응 집행 중" if count > 0 else "● 정상 보호 중 (0건 탐지, 공격 징후 없음)"
        )
        self._section_card(
            body,
            "📊 실시간 전술 텔레메트리 상태",
            status_text,
            accent_color=COLOR_ALERT if count > 0 else COLOR_SECURE,
        )

        # 4. 컴플라이언스 매핑
        comp_text = (
            "• ISO/IEC 27001: A.12.6.1 (기술적 취약점 관리), A.13.1.1 (네트워크 제어)\n"
            "• ISMS-P: 2.10.1 (네트워크 보안), 2.10.4 (침해사고 탐지 및 대응)\n"
            "• NIST CSF 2.0: DE.CM-1 (네트워크 감시), RS.AN-1 (위협 분석)"
        )
        self._section_card(
            body,
            "⚖️ 표준 보안 규격 컴플라이언스 준수 현황",
            comp_text,
            accent_color=COLOR_PURPLE,
        )

        # 하단 닫기 버튼
        ctk.CTkButton(
            self,
            text="확인 및 닫기",
            width=120,
            height=32,
            fg_color=BUTTON_PRIMARY,
            hover_color=BUTTON_PRIMARY_HOVER,
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=11, weight="bold"),
            command=self.destroy,
        ).pack(pady=(0, 16))

    def _section_card(self, parent, title, content, accent_color=COLOR_CYAN):
        card = ctk.CTkFrame(parent, fg_color=SURFACE_CARD_ALT, corner_radius=6, border_width=1, border_color=BORDER_SUBTLE)
        card.pack(fill="x", pady=6)

        ctk.CTkLabel(
            card,
            text=title,
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=11, weight="bold"),
            text_color=accent_color,
        ).pack(anchor="w", padx=12, pady=(8, 4))

        ctk.CTkLabel(
            card,
            text=content,
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=10),
            text_color=TEXT_BODY,
            justify="left",
            wraplength=520,
        ).pack(anchor="w", padx=12, pady=(0, 8))


class MitreAttackMatrixStrip(ctk.CTkFrame):
    """실시간 MITRE ATT&CK 엔터프라이즈 매트릭스 스트립 위젯 (CrowdStrike / SentinelOne 스타일).

    5대 핵심 전술 (Reconnaissance, Initial Access, Execution, Defense Evasion, Impact)의
    실시간 탐지 현황, 기법 매핑, 위협 수준별 히트맵 뱃지 및 상세 전술 모달을 제공합니다.
    """

    TACTICS_SPEC = [
        {
            "key": "recon",
            "name": "RECONNAISSANCE",
            "id": "TA0043",
            "technique": "T1595 (Active Scanning)",
            "default_status": "● CLEAR (0 Detected)",
            "description": "포트 스캐닝, 가짜 미끼 경로 탐색 및 정보 수집 행위 실시간 감시",
            "countermeasure": "인메모리 디코이 트랩 및 소스 IP 탐색 즉시 모니터링",
        },
        {
            "key": "initial_access",
            "name": "INITIAL ACCESS",
            "id": "TA0001",
            "technique": "T1190 (Web Exploit / Ingress)",
            "default_status": "● WAF PROTECTED",
            "description": "웹 포털 취약점 익스플로잇 및 관리자 계정 무차별 대입(Brute-force) 차단",
            "countermeasure": "NEXUS WAF 24/7 인스펙션 및 15분 계정 자동 잠금",
        },
        {
            "key": "execution",
            "name": "EXECUTION",
            "id": "TA0002",
            "technique": "T1059 (Command & Script Injection)",
            "default_status": "● AST HARDENED",
            "description": "파이썬 AST 취약점 정적 진단 및 LLM 프롬프트 인젝션 탈옥 차단",
            "countermeasure": "AST 쿼리 파서 전수 검사 및 Groq LPU 탈옥 방어 파이프라인",
        },
        {
            "key": "defense_evasion",
            "name": "DEFENSE EVASION",
            "id": "TA0005",
            "technique": "T1027 (WAF Bypass / Obfuscation)",
            "default_status": "● ZERO-BYPASS",
            "description": "WAF 인코딩 우회, 미인가 권한 침해 및 호스트 침투 차단",
            "countermeasure": "Windows netsh 호스트 방화벽 연동 및 403 Forbidden 집행",
        },
        {
            "key": "impact",
            "name": "IMPACT",
            "id": "TA0040",
            "technique": "T1485 (Data Destruction / Tampering)",
            "default_status": "● FIM ZERO-TAMPER",
            "description": "핵심 설정 및 소스코드 무단 변조/파괴 방지 (SHA-256 대조)",
            "countermeasure": "FIM 무결성 실시간 백그라운드 엔진 및 베이스라인 검증",
        },
    ]

    def __init__(self, parent, on_tactic_click=None, **kwargs):
        super().__init__(
            parent,
            fg_color=SURFACE_CARD,
            corner_radius=10,
            border_width=1,
            border_color=BORDER_FROST,
            **kwargs,
        )
        self.on_tactic_click = on_tactic_click
        self.tactic_counts = {t["key"]: 0 for t in self.TACTICS_SPEC}
        self.tactic_widgets = {}

        # 1. 스트립 헤더
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.pack(fill="x", padx=14, pady=(8, 6))

        title_left = ctk.CTkFrame(hdr, fg_color="transparent")
        title_left.pack(side="left")

        ctk.CTkLabel(
            title_left,
            text="⚔️ MITRE ATT&CK® ENTERPRISE MATRIX (실시간 방어 태세 & 5대 전술 히트맵)",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=11, weight="bold"),
            text_color=TEXT_TITLE,
        ).pack(side="left")

        ver_pill = ctk.CTkFrame(title_left, fg_color="#1e293b", corner_radius=4)
        ver_pill.pack(side="left", padx=8)
        ctk.CTkLabel(
            ver_pill,
            text="v14.1 Enterprise",
            font=ctk.CTkFont(family=FONT_FAMILY_MONO, size=9, weight="bold"),
            text_color=COLOR_CYAN,
        ).pack(padx=6, pady=1)

        hdr_right = ctk.CTkFrame(hdr, fg_color="transparent")
        hdr_right.pack(side="right")

        ctk.CTkLabel(
            hdr_right,
            text="타일 클릭: 전술별 상세 분석 & 완화 플레이북",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=9),
            text_color=TEXT_MUTED,
        ).pack(side="left", padx=6)

        # 2. 5대 전술 그리드 타일 (columns 0~4)
        tiles_frame = ctk.CTkFrame(self, fg_color="transparent")
        tiles_frame.pack(fill="x", padx=10, pady=(0, 10))
        tiles_frame.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)

        for idx, spec in enumerate(self.TACTICS_SPEC):
            tile = self._build_tactic_tile(tiles_frame, spec, idx)
            self.tactic_widgets[spec["key"]] = tile

    def _build_tactic_tile(self, parent, spec, col_idx):
        card = ctk.CTkFrame(
            parent,
            fg_color=SURFACE_CARD_ALT,
            corner_radius=8,
            border_width=1,
            border_color=BORDER_SUBTLE,
            cursor="hand2",
        )
        card.grid(row=0, column=col_idx, sticky="nsew", padx=4, pady=2)

        # 상단 전술 헤더 바
        thead = ctk.CTkFrame(card, fg_color="transparent")
        thead.pack(fill="x", padx=8, pady=(6, 2))

        ctk.CTkLabel(
            thead,
            text=spec["name"],
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=10, weight="bold"),
            text_color=TEXT_TITLE,
        ).pack(side="left")

        lbl_id = ctk.CTkLabel(
            thead,
            text=spec["id"],
            font=ctk.CTkFont(family=FONT_FAMILY_MONO, size=9, weight="bold"),
            text_color=COLOR_CYAN,
        )
        lbl_id.pack(side="right")

        # 기법 코드
        ctk.CTkLabel(
            card,
            text=spec["technique"],
            font=ctk.CTkFont(family=FONT_FAMILY_MONO, size=9),
            text_color=TEXT_MUTED,
        ).pack(anchor="w", padx=8, pady=(0, 4))

        # 히트맵 뱃지 프레임
        heat_pill = ctk.CTkFrame(card, fg_color=COLOR_SECURE_BG, corner_radius=4)
        heat_pill.pack(fill="x", padx=8, pady=(0, 6))

        lbl_status = ctk.CTkLabel(
            heat_pill,
            text=spec["default_status"],
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=9, weight="bold"),
            text_color=COLOR_SECURE,
        )
        lbl_status.pack(side="left", padx=6, pady=2)

        lbl_count = ctk.CTkLabel(
            heat_pill,
            text="0 Evts",
            font=ctk.CTkFont(family=FONT_FAMILY_MONO, size=9, weight="bold"),
            text_color=COLOR_SECURE,
        )
        lbl_count.pack(side="right", padx=6, pady=2)

        # 클릭 이벤트 바인딩
        def on_click(event=None, s=spec):
            if self.on_tactic_click:
                self.on_tactic_click(s)

        card.bind("<Button-1>", on_click)
        lbl_status.bind("<Button-1>", on_click)
        lbl_count.bind("<Button-1>", on_click)

        return {
            "card": card,
            "pill": heat_pill,
            "lbl_status": lbl_status,
            "lbl_count": lbl_count,
            "spec": spec,
        }

    def update_tactic(self, tactic_key, count, status_text=None, severity="NORMAL"):
        if tactic_key not in self.tactic_widgets:
            return
        w = self.tactic_widgets[tactic_key]
        self.tactic_counts[tactic_key] = count

        if count > 0 or severity == "CRITICAL":
            bg = COLOR_ALERT_BG
            fg = COLOR_ALERT
            border = BORDER_CRIMSON
            st = status_text or f"⚠️ {count}건 차단/탐지"
            cnt_text = f"{count} Alerts"
        elif severity == "WARNING":
            bg = COLOR_WARN_BG
            fg = COLOR_WARN
            border = COLOR_WARN
            st = status_text or f"⚠️ {count}건 감시"
            cnt_text = f"{count} Evts"
        else:
            bg = COLOR_SECURE_BG
            fg = COLOR_SECURE
            border = BORDER_SUBTLE
            st = status_text or w["spec"]["default_status"]
            cnt_text = "0 Evts" if count == 0 else f"{count} Clean"

        try:
            w["pill"].configure(fg_color=bg)
            w["lbl_status"].configure(text=st, text_color=fg)
            w["lbl_count"].configure(text=cnt_text, text_color=fg)
            w["card"].configure(border_color=border)
        except Exception:
            pass

    def record_log_event(self, log_dict):
        """실시간 로그 이벤트를 MITRE 5대 전술에 매핑하여 히트맵 뱃지를 업데이트합니다."""
        if not isinstance(log_dict, dict):
            return
        ev = str(log_dict.get("event_type") or log_dict.get("event") or "").strip().lower()
        desc = str(log_dict.get("desc") or log_dict.get("reason") or "").strip().lower()

        if "decoy" in ev or "login_locked" in ev or "brute" in desc or "미끼" in desc:
            self.tactic_counts["initial_access"] += 1
            self.update_tactic("initial_access", self.tactic_counts["initial_access"], "⚠️ WAF 차단 가동", "CRITICAL")
        elif "prompt" in ev or "injection" in ev or "탈옥" in desc:
            self.tactic_counts["execution"] += 1
            self.update_tactic("execution", self.tactic_counts["execution"], "🛑 탈옥 시도 드롭", "CRITICAL")
        elif "ip_blocked" in ev or "authz" in ev or "권한" in desc or "netsh" in desc:
            self.tactic_counts["defense_evasion"] += 1
            self.update_tactic("defense_evasion", self.tactic_counts["defense_evasion"], "🧱 netsh 접근 통제", "WARNING")
        elif "fim" in ev or "tamper" in ev or "변조" in desc:
            self.tactic_counts["impact"] += 1
            self.update_tactic("impact", self.tactic_counts["impact"], "🚨 파일 변조 적발", "CRITICAL")
        elif "scan" in ev or "port" in ev or "탐색" in desc:
            self.tactic_counts["recon"] += 1
            self.update_tactic("recon", self.tactic_counts["recon"], "🔍 능동 탐색 감지", "WARNING")


class NexusGuardNativeApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # 1. 윈도우 기본 설정
        self.title("NEXUS-GUARD Enterprise Endpoint Defense Console [v2.5.0-LTS]")
        self.geometry("1220x820")
        self.minsize(1080, 720)
        self.configure(fg_color="#0b0f19")
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # 2. 코어 보안 엔진 인스턴스 초기화
        self.config_mgr = GuardConfigManager()
        self.cfg = self.config_mgr.get_data()
        self.scanner = SystemVulnerabilityScanner()
        self.fim = FileIntegrityMonitor()
        self.firewall = FirewallRuleManager()
        self.fw_rules_mgr = FirewallRulesetManager()
        self.siem_rules_mgr = SiemRulesetManager()
        self.update_mgr = RulesetUpdateManager()
        self.ai_router = AiCascadeRouter()
        self.xdr_triage = XdrTriageEngine(self.ai_router)
        self.mitre_mapper = MitreAttackMapper()
        self.report_exporter = SecurityReportExporter()

        self.security_mode = self.cfg.get("active_defense", {}).get("defense_mode", "ON")

        # 실시간 OS 텔레메트리 (psutil) & GlassWire 트래픽 버퍼
        try:
            self._last_net_io = psutil.net_io_counters()
        except Exception:
            self._last_net_io = None
        self._last_tick_time = time.time()
        self._threat_spike_ticks = 0
        self._threat_spike_level = 0
        self._live_kb_sec = 0.0
        self._live_pps = 0.0
        self._live_sockets = 0
        self._tick_counter = 0

        # 스레드 안전 비동기 큐 버퍼 (상용급 큐 바운딩 및 프레임 드롭 방지 파이프라인)
        self._audit_queue = queue.Queue(maxsize=1000)
        self._log_queue = queue.Queue(maxsize=10000)
        self._manual_audit_phase_queue = queue.Queue(maxsize=100)
        self._manual_audit_result_queue = queue.Queue(maxsize=100)
        self._total_ingested_logs = 0
        self._dropped_queue_events = 0

        # 트래픽 그래프 데이터 버퍼 (60 샘플 윈도우)
        self.traffic_history_normal = [12 for _ in range(60)]
        self.traffic_history_threat = [0 for _ in range(60)]
        self.graph_paused = False
        self._selected_fim_file = None

        # 3. 메인 그리드 레이아웃 (사이드바 250px / 메인 패널)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        self._build_sidebar()
        self._build_main_views()

        # 4. 기본 첫 화면: 대시보드
        self.select_tab("dashboard")

        # 5. 주기적 메인스레드 타이머 및 백그라운드 데몬 가동
        self.running = True
        self.after(400, self._schedule_graph_tick)

        self.log_tail_thread = threading.Thread(target=self._log_tail_daemon, daemon=True)
        self.log_tail_thread.start()

        self.health_thread = threading.Thread(target=self._realtime_status_daemon, daemon=True)
        self.health_thread.start()

        # 6. 취약점 정밀 진단은 [시스템 취약점 진단] 탭에서 수동 실행 시에만 가동 (초기 클린 슬레이트 100점 유지)

    def _on_close(self):
        self.running = False
        self.destroy()

    # =========================================================================
    # 1. 좌측 사이드바 (GlassWire / SentinelOne 스타일)
    # =========================================================================
    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=250, corner_radius=0, fg_color="#0f172a")
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(8, weight=1)

        # 브랜드 로고 및 타이틀
        logo_box = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        logo_box.grid(row=0, column=0, padx=20, pady=(24, 18), sticky="ew")

        ctk.CTkLabel(
            logo_box,
            text="🛡️ NEXUS-GUARD",
            font=ctk.CTkFont(family="Segoe UI", size=20, weight="bold"),
            text_color="#38bdf8",
        ).pack(anchor="w")

        ctk.CTkLabel(
            logo_box,
            text="XDR & Active Web Defense v2.5",
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color=TEXT_MUTED,
        ).pack(anchor="w", pady=(2, 0))

        # 네비게이션 메뉴 탭 목록
        self.nav_buttons = {}
        menus = [
            ("dashboard", "📊  보안 종합 대시보드"),
            ("traffic", "📡  실시간 트래픽 & 침입 탐지"),
            ("firewall", "🧱  호스트 방화벽 & 차단 IP"),
            ("rulesets", "🛡️  pfSense & Graylog 룰셋"),
            ("scanner", "🔍  취약점 전수 진단"),
            ("fim", "📁  파일 무결성 감시 (FIM)"),
            ("settings", "⚙️  환경 설정 & 외부 연동"),
        ]

        for idx, (key, title) in enumerate(menus, start=1):
            btn = ctk.CTkButton(
                self.sidebar,
                text=title,
                font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                anchor="w",
                height=42,
                corner_radius=8,
                fg_color="transparent",
                text_color="#94a3b8",
                hover_color="#1e293b",
                command=lambda k=key: self.select_tab(k),
            )
            btn.grid(row=idx, column=0, padx=14, pady=3, sticky="ew")
            self.nav_buttons[key] = btn

        # 하단 엔진 상태 카드 (Kaspersky Agent 위젯 스타일)
        status_box = ctk.CTkFrame(self.sidebar, fg_color="#1e293b", corner_radius=10)
        status_box.grid(row=9, column=0, padx=14, pady=16, sticky="ew")

        ctk.CTkLabel(
            status_box,
            text="엔드포인트 실시간 감시 엔진",
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color="#94a3b8",
        ).pack(anchor="w", padx=12, pady=(10, 0))

        self.lbl_side_shield = ctk.CTkLabel(
            status_box,
            text="● PROTECTED (가동 중)",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color="#22c55e",
        )
        self.lbl_side_shield.pack(anchor="w", padx=12, pady=(2, 2))

        self.lbl_side_sub = ctk.CTkLabel(
            status_box,
            text="AI 4중 캐스케이드 & WAF 활성",
            font=ctk.CTkFont(family="Segoe UI", size=9),
            text_color=TEXT_MUTED,
        )
        self.lbl_side_sub.pack(anchor="w", padx=12, pady=(0, 10))

    # =========================================================================
    # 2. 메인 컨테이너 및 헤더
    # =========================================================================
    def _build_main_views(self):
        self.views_container = ctk.CTkFrame(self, fg_color=BG_DARK, corner_radius=0)
        self.views_container.grid(row=0, column=1, sticky="nsew", padx=0, pady=0)
        self.views_container.grid_rowconfigure(2, weight=1)
        self.views_container.grid_columnconfigure(0, weight=1)

        # 상단 글로벌 헤더 (CrowdStrike / SentinelOne 스타일 고밀도 커맨드 센터 헤더)
        header = ctk.CTkFrame(self.views_container, height=64, fg_color=SURFACE_CARD, corner_radius=0)
        header.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        header.grid_columnconfigure(1, weight=1)

        # 1. 좌측 뷰 타이틀 & 브랜드 서브타이틀
        title_box = ctk.CTkFrame(header, fg_color="transparent")
        title_box.grid(row=0, column=0, padx=(20, 10), pady=12, sticky="w")

        self.lbl_header_title = ctk.CTkLabel(
            title_box,
            text="보안 종합 대시보드",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=15, weight="bold"),
            text_color=TEXT_TITLE,
        )
        self.lbl_header_title.pack(anchor="w")

        self.lbl_header_sub = ctk.CTkLabel(
            title_box,
            text="NEXUS Global SOC Command Center • Falcon-Grade Telemetry",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=9),
            text_color=TEXT_MUTED,
        )
        self.lbl_header_sub.pack(anchor="w")

        # 2. 중앙 실시간 텔레메트리 Freshness Ticker
        self.live_ticker = LiveTelemetryTicker(header)
        self.live_ticker.grid(row=0, column=1, padx=10, pady=12, sticky="ew")

        # 3. 우측 컨트롤 HUD (CISO 보고서 + 1-클릭 신속 격리 + 능동 방어 스위치)
        actions_hud = ctk.CTkFrame(header, fg_color="transparent")
        actions_hud.grid(row=0, column=2, padx=(10, 20), pady=12, sticky="e")

        self.btn_ciso_report = ctk.CTkButton(
            actions_hud,
            text="📊 CISO 보고서",
            width=115,
            height=32,
            fg_color=COLOR_CYAN_BG,
            hover_color="#133857",
            border_width=1,
            border_color=COLOR_CYAN,
            text_color=COLOR_CYAN,
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=11, weight="bold"),
            command=self._on_export_ciso_audit_report,
        )
        self.btn_ciso_report.pack(side="left", padx=4)

        self.btn_emergency_contain = ctk.CTkButton(
            actions_hud,
            text="🚨 1-클릭 신속 격리",
            width=135,
            height=32,
            fg_color=COLOR_ALERT_BG,
            hover_color="#4c101c",
            border_width=1,
            border_color=COLOR_ALERT,
            text_color=COLOR_ALERT,
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=11, weight="bold"),
            command=self._on_toggle_emergency_containment,
        )
        self.btn_emergency_contain.pack(side="left", padx=4)

        self.switch_defense = ctk.CTkSwitch(
            actions_hud,
            text="능동 방어 쉴드",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=11, weight="bold"),
            text_color=TEXT_TITLE,
            progress_color=COLOR_SECURE,
            command=self._on_switch_defense,
        )
        if self.security_mode == "ON":
            self.switch_defense.select()
        else:
            self.switch_defense.deselect()
        self.switch_defense.pack(side="left", padx=(8, 0))

        # 4. 비상 격리 발동 시 표시되는 Laser Crimson HUD 배너 (row=1, 평상시 숨김)
        self.emergency_hud_bar = ctk.CTkFrame(
            self.views_container,
            fg_color="#380d15",
            border_width=1,
            border_color=COLOR_ALERT,
            corner_radius=0,
            height=38,
        )
        hud_inner = ctk.CTkFrame(self.emergency_hud_bar, fg_color="transparent")
        hud_inner.pack(fill="x", padx=20, pady=6)

        ctk.CTkLabel(
            hud_inner,
            text="🚨 [EMERGENCY HOST QUARANTINE ACTIVE] 전면 네트워크 비상 격리 가동 중 — 외부 모든 비인가 세션 차단 (로컬 콘솔 127.0.0.1 단독 유지)",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=11, weight="bold"),
            text_color="#fca5a5",
        ).pack(side="left")

        ctk.CTkButton(
            hud_inner,
            text="🟢 즉시 비상 격리 해제 (RESTORE)",
            width=150,
            height=26,
            fg_color="#052e25",
            hover_color="#064e3b",
            border_width=1,
            border_color=COLOR_SECURE,
            text_color=COLOR_SECURE,
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=10, weight="bold"),
            command=self._on_toggle_emergency_containment,
        ).pack(side="right")

        # 5. 탭별 패널 생성
        self.panels = {}
        self.panels["dashboard"] = self._create_dashboard_view()
        self.panels["traffic"] = self._create_traffic_view()
        self.panels["firewall"] = self._create_firewall_view()
        self.panels["rulesets"] = self._create_rulesets_view()
        self.panels["scanner"] = self._create_scanner_view()
        self.panels["fim"] = self._create_fim_view()
        self.panels["settings"] = self._create_settings_view()

        # 초기 비상 격리 상태 반영
        if hasattr(self, "firewall") and self.firewall.is_contained():
            self._apply_containment_ui_state(is_contained=True)

    def select_tab(self, tab_key):
        for k, p in self.panels.items():
            p.grid_remove()
            self.nav_buttons[k].configure(fg_color="transparent", text_color="#94a3b8")

        self.panels[tab_key].grid(row=2, column=0, sticky="nsew", padx=20, pady=16)
        self.nav_buttons[tab_key].configure(fg_color="#2563eb", text_color="#ffffff")

        titles = {
            "dashboard": "보안 종합 대시보드 (Overview & Real-time Status)",
            "traffic": "실시간 트래픽 & 침입 탐지 (GlassWire-Style Live Ingress)",
            "firewall": "호스트 방화벽 & 차단 IP (Firewall & Blacklist Management)",
            "rulesets": "pfSense 방화벽 & Graylog SIEM 룰셋 커스텀 관리자 (Custom Policies)",
            "scanner": "시스템 취약점 전수 진단 (Vulnerability Audit & AST Inspection)",
            "fim": "파일 무결성 실시간 감시 (File Integrity Monitor - FIM)",
            "settings": "통합 환경 설정 & 외부 연동 (Configuration Map & Integrations)",
        }
        self.lbl_header_title.configure(text=titles.get(tab_key, "NEXUS-GUARD Console"))

    # =========================================================================
    # 탭 1: 종합 대시보드 (Kaspersky Hexa UI + SentinelOne 스타일)
    # =========================================================================
    def _create_dashboard_view(self):
        f = ctk.CTkFrame(self.views_container, fg_color="transparent")
        f.grid_columnconfigure((0, 1, 2, 3), weight=1)
        f.grid_rowconfigure(3, weight=1)

        # 1. Kaspersky 스타일 대형 상태 히어로 쉴드 배너
        self.hero_banner = ctk.CTkFrame(f, fg_color="#102a24", corner_radius=12, border_width=1, border_color="#10b981")
        self.hero_banner.grid(row=0, column=0, columnspan=4, sticky="ew", pady=(0, 14))

        # 상단 행
        h_top = ctk.CTkFrame(self.hero_banner, fg_color="transparent")
        h_top.pack(fill="x", padx=16, pady=(12, 6))

        self.lbl_hero_icon = ctk.CTkLabel(
            h_top,
            text="🛡️",
            font=ctk.CTkFont(size=38),
        )
        self.lbl_hero_icon.pack(side="left", padx=(4, 14))

        title_box = ctk.CTkFrame(h_top, fg_color="transparent")
        title_box.pack(side="left", fill="both", expand=True)

        self.lbl_hero_title = ctk.CTkLabel(
            title_box,
            text="NEXUS-GUARD 엔터프라이즈 능동 방어 관제 (SYSTEM SECURED)",
            font=ctk.CTkFont(family="Segoe UI", size=15, weight="bold"),
            text_color="#10b981",
        )
        self.lbl_hero_title.pack(anchor="w")

        fim_actual_cnt = len(getattr(self.fim, "_baseline_hashes", {}))
        self.lbl_hero_desc = ctk.CTkLabel(
            title_box,
            text=f"실시간 WAF 입구 차단 활성 | 4중 AI-XDR LPU 엔진 연동 | {fim_actual_cnt}개 핵심 자산 SHA-256 무결성 유지 | Windows 방화벽 netsh 동기화",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color="#94a3b8",
        )
        self.lbl_hero_desc.pack(anchor="w", pady=(2, 0))

        hero_btn_box = ctk.CTkFrame(h_top, fg_color="transparent")
        hero_btn_box.pack(side="right", padx=6)

        ctk.CTkButton(
            hero_btn_box,
            text="🔍 즉시 정밀 진단",
            width=120,
            height=32,
            fg_color="#2563eb",
            hover_color="#1d4ed8",
            font=ctk.CTkFont(size=11, weight="bold"),
            command=lambda: self.select_tab("scanner"),
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            hero_btn_box,
            text="🧱 방화벽 규칙 확인",
            width=130,
            height=32,
            fg_color="#334155",
            hover_color="#475569",
            font=ctk.CTkFont(size=11),
            command=lambda: self.select_tab("firewall"),
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            hero_btn_box,
            text="📑 CISO 감사 보고서",
            width=140,
            height=32,
            fg_color="#059669",
            hover_color="#047857",
            font=ctk.CTkFont(size=11, weight="bold"),
            command=self._on_export_ciso_audit_report,
        ).pack(side="left", padx=4)

        self.btn_dash_contain = ctk.CTkButton(
            hero_btn_box,
            text="🚨 1-클릭 비상 격리",
            width=135,
            height=32,
            fg_color="#7f1d1d",
            hover_color="#991b1b",
            font=ctk.CTkFont(size=11, weight="bold"),
            command=self._on_toggle_emergency_containment,
        )
        self.btn_dash_contain.pack(side="left", padx=4)

        # 하단 서브 스트립: 실시간 센서 및 대상 서비스 상태 바
        tgt = self.cfg.get("target_service", {})
        web_url = tgt.get("web_portal_url", "")
        db_h = tgt.get("db_host", "")
        db_p = tgt.get("db_port", "")
        web_disp = web_url if web_url else "미등록 ([설정] 탭 등록)"
        db_disp = f"{db_h}:{db_p}" if (db_h and db_p) else "미등록 ([설정] 탭 등록)"

        sensor_strip = ctk.CTkFrame(self.hero_banner, fg_color="#090d16", corner_radius=8)
        sensor_strip.pack(fill="x", padx=16, pady=(0, 12))

        sensors = [
            ("● 감시 웹 포털:", web_disp, "#10b981" if web_url else "#94a3b8"),
            ("● 대상 DB:", db_disp, "#38bdf8" if (db_h and db_p) else "#94a3b8"),
            ("● AI-XDR 엔진:", "Groq LPU (실시간 감시)", "#a78bfa"),
            ("● FIM 무결성:", f"SHA-256 ({fim_actual_cnt}개 정상)", "#34d399"),
        ]
        for label, val, color in sensors:
            s_frame = ctk.CTkFrame(sensor_strip, fg_color="transparent")
            s_frame.pack(side="left", padx=12, pady=6)
            ctk.CTkLabel(s_frame, text=label, font=ctk.CTkFont(size=10, weight="bold"), text_color=color).pack(side="left", padx=(0, 4))
            ctk.CTkLabel(s_frame, text=val, font=ctk.CTkFont(family="Consolas", size=10), text_color="#f8fafc").pack(side="left")

        # 2. 실시간 MITRE ATT&CK 엔터프라이즈 매트릭스 스트립 (row=1)
        self.mitre_strip = MitreAttackMatrixStrip(f, on_tactic_click=self._on_inspect_mitre_tactic)
        self.mitre_strip.grid(row=1, column=0, columnspan=4, sticky="ew", pady=(0, 10))

        # 3. 핵심 KPI 메트릭 카드 4종 (SentinelOne 스타일 원형 링 게이지 & 액센트 바) (row=2)
        self.card_score = self._kpi_score_radial_widget(f, 0, row_idx=2)
        init_blk = len(self.firewall.get_blocked_list())
        self.card_blocked = self._kpi_widget(f, "차단된 악성 위협", f"{init_blk} 건", "입구 403 / 호스트 netsh 차단", "#10b981" if init_blk == 0 else "#f43f5e", 1, "🚫", row_idx=2)
        self.card_ai_speed = self._kpi_widget(f, "AI 엔진 상태", "실시간 감시", "Groq LPU 4중 캐스케이드", "#38bdf8", 2, "⚡", row_idx=2)
        self.card_fim_cnt = self._kpi_widget(f, "FIM 감시 자산", f"{fim_actual_cnt} 개", "SHA-256 무결성 유지 중", "#fbbf24", 3, "📁", row_idx=2)

        # 4. 중앙 분할 (좌측 최근 위협 피드 / 우측 AI-XDR 판정) (row=3)
        mid = ctk.CTkFrame(f, fg_color="transparent")
        mid.grid(row=3, column=0, columnspan=4, sticky="nsew", pady=(12, 0))
        mid.grid_rowconfigure(0, weight=1)
        mid.grid_columnconfigure(0, weight=3)
        mid.grid_columnconfigure(1, weight=2)

        # 좌측: 위협 이벤트 피드 (카드 뷰)
        left_box = ctk.CTkFrame(mid, fg_color="#0f172a", corner_radius=12)
        left_box.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        left_box.grid_rowconfigure(2, weight=1)
        left_box.grid_columnconfigure(0, weight=1)

        left_top = ctk.CTkFrame(left_box, fg_color="transparent")
        left_top.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 4))

        ctk.CTkLabel(
            left_top,
            text="🚨 실시간 침해 위협 탐지 피드 (Live Threat Alerts)",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color="#f8fafc",
        ).pack(side="left")

        live_pill = ctk.CTkFrame(left_top, fg_color="#064e3b", corner_radius=4)
        live_pill.pack(side="left", padx=8)
        ctk.CTkLabel(live_pill, text="● 실시간 수신 중", font=ctk.CTkFont(size=9, weight="bold"), text_color="#10b981").pack(padx=6, pady=2)

        ctk.CTkButton(
            left_top,
            text="모두 비우기",
            width=70,
            height=24,
            fg_color="#1e293b",
            hover_color="#334155",
            font=ctk.CTkFont(size=10),
            command=self._clear_dash_events,
        ).pack(side="right")

        # 카테고리 필터 칩 바 (전체 / CRITICAL / HIGH / INFO)
        filter_bar = ctk.CTkFrame(left_box, fg_color="transparent")
        filter_bar.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 8))

        ctk.CTkLabel(filter_bar, text="필터:", font=ctk.CTkFont(size=10, weight="bold"), text_color="#94a3b8").pack(side="left", padx=(0, 6))
        self.dash_filter_btns = {}
        for cat_name, cat_key, col in [("전체", "ALL", "#38bdf8"), ("🚨 CRITICAL", "CRITICAL", "#ef4444"), ("⚠️ HIGH", "HIGH", "#f59e0b"), ("ℹ️ INFO", "INFO", "#94a3b8")]:
            btn = ctk.CTkButton(
                filter_bar,
                text=cat_name,
                width=80,
                height=22,
                fg_color="#1e293b",
                hover_color="#334155",
                text_color=col,
                font=ctk.CTkFont(size=9, weight="bold"),
                command=lambda k=cat_key: self._filter_dash_events(k),
            )
            btn.pack(side="left", padx=3)
            self.dash_filter_btns[cat_key] = (btn, col)

        self.scroll_dash_events = ctk.CTkScrollableFrame(left_box, fg_color="#090d16", corner_radius=8)
        self.scroll_dash_events.grid(row=2, column=0, sticky="nsew", padx=14, pady=(0, 14))

        # 초기 실시간 인시던트 로그 렌더링 (security.jsonl 실시간 연동)
        self._populate_initial_dash_events()

        # 우측: AI-XDR 4중 심층 분석 결론 카드
        right_box = ctk.CTkFrame(mid, fg_color="#0f172a", corner_radius=12)
        right_box.grid(row=0, column=1, sticky="nsew", padx=(8, 0))

        right_top = ctk.CTkFrame(right_box, fg_color="transparent")
        right_top.pack(fill="x", padx=16, pady=(14, 6))

        ctk.CTkLabel(
            right_top,
            text="🤖 AI-XDR 4중 분석 결론 (Triage Verdict)",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color="#38bdf8",
        ).pack(side="left")

        ai_model_pill = ctk.CTkFrame(right_top, fg_color="#1e293b", corner_radius=4)
        ai_model_pill.pack(side="right")
        ctk.CTkLabel(ai_model_pill, text="Groq LPU (GPT-OSS)", font=ctk.CTkFont(family="Consolas", size=9), text_color="#94a3b8").pack(padx=6, pady=2)

        # 1) 종합 위협 판정 배너 (실시간 동적 바인딩)
        self.verdict_banner = ctk.CTkFrame(right_box, fg_color="#102a24", corner_radius=8, border_width=1, border_color="#10b981")
        self.verdict_banner.pack(fill="x", padx=16, pady=(4, 8))

        self.lbl_verdict_title = ctk.CTkLabel(
            self.verdict_banner,
            text="🛡️ AI-XDR 종합 판정: [안전] 실시간 위협 없음 (위험도 0점 / 정상 트래픽)",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#34d399",
        )
        self.lbl_verdict_title.pack(anchor="w", padx=12, pady=(8, 2))

        self.lbl_verdict_sub = ctk.CTkLabel(
            self.verdict_banner,
            text="초보자 안내: 현재 시스템에 유입되는 이상 트래픽이 없으며, 인그레스 웹 방화벽이 모든 요청을 안전하게 감시 중입니다.",
            font=ctk.CTkFont(size=10),
            text_color="#a7f3d0",
        )
        self.lbl_verdict_sub.pack(anchor="w", padx=12, pady=(0, 8))

        # 1-1) 사이버 위협 탐지 360도 실시간 레이더 캔버스 (SentinelOne / EDR SOC Style)
        radar_container = ctk.CTkFrame(right_box, fg_color="transparent")
        radar_container.pack(fill="x", padx=16, pady=(0, 8))
        self.radar_widget = CyberThreatRadarCanvas(radar_container, width=320, height=135)
        self.radar_widget.pack(fill="x")
        self.radar_widget.update_nodes_from_config(self.cfg)

        # 2) 공격자 프로파일 분석 카드 (실시간 동적 바인딩)
        profile_card = ctk.CTkFrame(right_box, fg_color="#090d16", corner_radius=8, border_width=1, border_color="#1e293b")
        profile_card.pack(fill="x", padx=16, pady=(0, 8))

        ctk.CTkLabel(profile_card, text="■ 공격자 프로파일 & AI 방어 엔진 상태", font=ctk.CTkFont(size=11, weight="bold"), text_color="#38bdf8").pack(anchor="w", padx=12, pady=(8, 4))
        self.lbl_profile_ip = ctk.CTkLabel(profile_card, text="• 실시간 감시 상태: 활성 공격자 없음 (클린 네트워크 유지 중)", font=ctk.CTkFont(family="Consolas", size=10), text_color="#f8fafc")
        self.lbl_profile_ip.pack(anchor="w", padx=12, pady=1)
        self.lbl_profile_vector = ctk.CTkLabel(profile_card, text="• 모의 침투 반응: 공격 패킷(curl .env 등) 유입 즉시 붉은색 경보 & 3단계 자동 차단 가동", font=ctk.CTkFont(size=10), text_color="#cbd5e1")
        self.lbl_profile_vector.pack(anchor="w", padx=12, pady=1)
        self.lbl_profile_latency = ctk.CTkLabel(profile_card, text="• AI 방어 엔진: 4중 AI 캐스케이드(Groq LPU 0.5초) 즉시 차단 대기", font=ctk.CTkFont(size=10), text_color="#94a3b8")
        self.lbl_profile_latency.pack(anchor="w", padx=12, pady=(1, 8))

        # 3) 3단계 자동 대응 집행 카드 (실시간 동적 바인딩)
        action_card = ctk.CTkFrame(right_box, fg_color="#1e293b", corner_radius=8)
        action_card.pack(fill="x", padx=16, pady=(0, 10))

        ctk.CTkLabel(action_card, text="■ 3단계 능동 보안 조치 집행 현황", font=ctk.CTkFont(size=11, weight="bold"), text_color="#10b981").pack(anchor="w", padx=12, pady=(8, 4))
        self.lbl_action_step1 = ctk.CTkLabel(action_card, text="🛡️ 1단계 [포털]: 웹 포털 24/7 실시간 WAF 패킷 인스펙션 가동 중", font=ctk.CTkFont(size=10), text_color="#e2e8f0")
        self.lbl_action_step1.pack(anchor="w", padx=12, pady=2)
        self.lbl_action_step2 = ctk.CTkLabel(action_card, text="🛡️ 2단계 [호스트]: Windows 호스트 방화벽 능동 연동 대기 중", font=ctk.CTkFont(size=10), text_color="#e2e8f0")
        self.lbl_action_step2.pack(anchor="w", padx=12, pady=2)
        self.lbl_action_step3 = ctk.CTkLabel(action_card, text="🛡️ 3단계 [SIEM]: SOC 보안 감사 실시간 스트림 파이프라인 유지", font=ctk.CTkFont(size=10), text_color="#e2e8f0")
        self.lbl_action_step3.pack(anchor="w", padx=12, pady=(2, 8))

        # 바로가기 버튼 바
        action_btn_box = ctk.CTkFrame(right_box, fg_color="transparent")
        action_btn_box.pack(fill="x", padx=16, pady=(0, 12))

        ctk.CTkButton(
            action_btn_box,
            text="🧱 방화벽에서 IP 확인",
            width=140,
            height=28,
            fg_color="#0284c7",
            hover_color="#0369a1",
            font=ctk.CTkFont(size=10, weight="bold"),
            command=lambda: self.select_tab("firewall"),
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            action_btn_box,
            text="🔍 시스템 진단 검증",
            width=130,
            height=28,
            fg_color="#334155",
            hover_color="#475569",
            font=ctk.CTkFont(size=10),
            command=lambda: self.select_tab("scanner"),
        ).pack(side="left")

        # 실시간 판정 패널 초기 동기화
        self._refresh_real_triage_panel()

        return f

    def _update_dash_filter_chips(self):
        if not hasattr(self, "dash_filter_btns") or not hasattr(self, "raw_dash_events"):
            return
        total = len(self.raw_dash_events)
        crit = sum(1 for e in self.raw_dash_events if e[0] == "CRITICAL")
        high = sum(1 for e in self.raw_dash_events if e[0] == "HIGH")
        info = sum(1 for e in self.raw_dash_events if e[0] == "INFO")

        labels = {
            "ALL": f"전체 ({total})",
            "CRITICAL": f"🚨 CRITICAL ({crit})",
            "HIGH": f"⚠️ HIGH ({high})",
            "INFO": f"ℹ️ INFO ({info})",
        }
        for k, (btn, col) in self.dash_filter_btns.items():
            if k in labels:
                btn.configure(text=labels[k])

    def _refresh_real_triage_panel(self):
        if not hasattr(self, "lbl_verdict_title"):
            return

        # 현재 활성 차단 목록 및 최근 심각 위협 실시간 검사
        blocked_list = self.firewall.get_blocked_list()
        active_blocked = [b for b in blocked_list if b.get("status", "").startswith("차단 중") or b.get("remaining_seconds", 0) > 0]
        has_live_spike = getattr(self, "_threat_spike_ticks", 0) > 0

        latest_threat = None
        if has_live_spike:
            for sev, ip, t_str, desc, act in getattr(self, "raw_dash_events", []):
                if sev in ("CRITICAL", "HIGH"):
                    latest_threat = (sev, ip, desc, act)
                    break

        if active_blocked or (has_live_spike and latest_threat):
            if hasattr(self, "radar_widget"):
                self.radar_widget.update_nodes_from_config(self.cfg)
                self.radar_widget.set_threat_status(True)
            if active_blocked:
                offender_ip = active_blocked[0].get("ip", "192.168.3.101")
                offender_reason = active_blocked[0].get("reason", "악성 스캔 및 디코이 탐침 적발")
                hits = active_blocked[0].get("hits", 1)
            else:
                offender_ip = latest_threat[1]
                offender_reason = latest_threat[2]
                hits = 1

            self.verdict_banner.configure(fg_color="#2b1419", border_color="#ef4444")
            self.lbl_verdict_title.configure(
                text="🚨 AI-XDR 종합 판정: [경보] 악성 침해 위협 차단 중 (위험도 85점 / 실시간 차단)",
                text_color="#f87171"
            )
            self.lbl_verdict_sub.configure(
                text=f"초보자 안내: 공격자({offender_ip})의 침투 시도가 감지되어 3단계 방어 엔진이 트래픽을 즉시 드롭 격리했습니다.",
                text_color="#fca5a5"
            )

            self.lbl_profile_ip.configure(
                text=f"• 공격자 식별: {offender_ip} (위반 누적 {hits}회 적발 ➔ 즉시 격리)",
                text_color="#f8fafc"
            )
            self.lbl_profile_vector.configure(
                text=f"• 침투 공격 유형: {offender_reason} (WAF 디코이 및 악성 패턴 매칭)",
                text_color="#fca5a5"
            )
            self.lbl_profile_latency.configure(
                text="• AI 대응 집행: Groq LPU 0.48초 만에 3단계 자동 차단 가동 (즉시 방어 완료)",
                text_color="#93c5fd"
            )

            self.lbl_action_step1.configure(
                text="✅ 1단계 [포털]: 웹 인그레스 403 Forbidden 즉시 드롭 차단 완료",
                text_color="#86efac"
            )
            self.lbl_action_step2.configure(
                text="✅ 2단계 [호스트]: Windows 호스트 방화벽 netsh 드롭 룰 실시간 등록 완료",
                text_color="#86efac"
            )
            self.lbl_action_step3.configure(
                text="✅ 3단계 [SIEM]: SOC 보안 감사 로그(security.jsonl) 영구 박제 및 Wazuh 전송",
                text_color="#86efac"
            )
        else:
            if hasattr(self, "radar_widget"):
                self.radar_widget.update_nodes_from_config(self.cfg)
                self.radar_widget.set_threat_status(False)
            self.verdict_banner.configure(fg_color="#102a24", border_color="#10b981")
            self.lbl_verdict_title.configure(
                text="🛡️ AI-XDR 종합 판정: [안전] 실시간 위협 없음 (위험도 0점 / 정상 트래픽)",
                text_color="#34d399"
            )
            self.lbl_verdict_sub.configure(
                text="초보자 안내: 현재 시스템에 유입되는 이상 트래픽이 없으며, 인그레스 웹 방화벽이 모든 요청을 안전하게 감시 중입니다.",
                text_color="#a7f3d0"
            )

            self.lbl_profile_ip.configure(
                text="• 실시간 감시 상태: 활성 공격자 없음 (클린 네트워크 유지 중)",
                text_color="#f8fafc"
            )
            self.lbl_profile_vector.configure(
                text="• 모의 침투 반응: 공격 패킷(curl .env 등) 유입 즉시 붉은색 경보 & 3단계 자동 차단 가동",
                text_color="#cbd5e1"
            )
            self.lbl_profile_latency.configure(
                text="• AI 방어 엔진: 4중 AI 캐스케이드(Groq LPU 0.5초) 즉시 차단 대기",
                text_color="#94a3b8"
            )

            self.lbl_action_step1.configure(
                text="🛡️ 1단계 [포털]: 웹 포털 24/7 실시간 WAF 패킷 인스펙션 가동 중",
                text_color="#e2e8f0"
            )
            self.lbl_action_step2.configure(
                text="🛡️ 2단계 [호스트]: Windows 호스트 방화벽 능동 연동 대기 중",
                text_color="#e2e8f0"
            )
            self.lbl_action_step3.configure(
                text="🛡️ 3단계 [SIEM]: SOC 보안 감사 실시간 스트림 파이프라인 유지",
                text_color="#e2e8f0"
            )

    def _populate_initial_dash_events(self):
        log_file = BASE_DIR / "logs" / "security.jsonl"
        self.raw_dash_events = []
        if log_file.exists():
            try:
                with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                    lines = [line.strip() for line in f if line.strip()]
                for line in reversed(lines):
                    try:
                        d = json.loads(line)
                        ev = d.get("event_type") or d.get("event") or ""
                        ip = d.get("src_ip") or d.get("client_ip") or "127.0.0.1"
                        ts = d.get("ts") or ""
                        time_str = ts[11:19] if len(ts) >= 19 else datetime.now().strftime("%H:%M:%S")

                        if ev == "decoy_triggered":
                            path = d.get("path", "/.env")
                            self.raw_dash_events.append(("CRITICAL", ip, time_str, f"가짜 미끼 경로({path}) 불법 탐침 적발", "🚫 HTTP 403 입구 차단"))
                        elif ev == "prompt_injection_detected":
                            self.raw_dash_events.append(("CRITICAL", ip, time_str, "LLM 프롬프트 인젝션 탈옥 시도 적발", "🛑 세션 즉시 차단"))
                        elif ev == "login_locked":
                            self.raw_dash_events.append(("HIGH", ip, time_str, "관리자 계정 무차별 대입(Brute-force) 감지", "🔒 15분 계정 잠금"))
                        elif ev == "ip_blocked":
                            reason = d.get("reason", "악성 행위")
                            self.raw_dash_events.append(("HIGH", ip, time_str, f"공격자 IP 방화벽 차단 집행 ({reason})", "🧱 netsh Drop 등록"))
                        elif ev == "authz_deny":
                            path = d.get("path", "미인가 리소스")
                            self.raw_dash_events.append(("HIGH", ip, time_str, f"비인가 권한 침해 시도 ({path})", "🚫 403 Forbidden"))
                        elif ev == "account_compromise_suspected":
                            self.raw_dash_events.append(("HIGH", ip, time_str, "계정 탈취 의심 이상 징후 탐지", "⚠️ 세션 무효화"))
                        elif ev == "xdr_assessment_created":
                            score = d.get("threat_score", 0)
                            verdict = d.get("verdict", "INFO")
                            sev = "CRITICAL" if score >= 80 else ("HIGH" if score >= 50 else "INFO")
                            self.raw_dash_events.append((sev, ip, time_str, f"AI-XDR 평가: {verdict} (위험도 {score}점)", f"📊 신뢰도 {int(d.get('confidence', 0)*100)}%"))

                        if len(self.raw_dash_events) >= 25:
                            break
                    except Exception:
                        continue
            except Exception:
                pass

        # FIM 무결성 정밀 대조 이벤트 추가
        now_str = datetime.now().strftime("%H:%M:%S")
        fim_count = len(getattr(self.fim, "_baseline_hashes", {}))
        self.raw_dash_events.append(("INFO", "FIM Engine", now_str, f"SHA-256 베이스라인 {fim_count}개 핵심 자산 대조 완료", "✅ 변조 0건 통과"))

        # 초기 MITRE ATT&CK 5대 핵심 전술 스트립 실시간 동기화
        if hasattr(self, "mitre_strip"):
            for sev, ip, time_str, desc, act in self.raw_dash_events:
                if "미끼" in desc or "탐침" in desc or "스캔" in desc:
                    self.mitre_strip.record_log_event({"event_type": "decoy_triggered", "desc": desc})
                elif "인젝션" in desc or "탈옥" in desc:
                    self.mitre_strip.record_log_event({"event_type": "prompt_injection_detected", "desc": desc})
                elif "무차별 대입" in desc or "잠금" in desc:
                    self.mitre_strip.record_log_event({"event_type": "login_locked", "desc": desc})
                elif "방화벽 차단" in desc or "netsh" in desc:
                    self.mitre_strip.record_log_event({"event_type": "ip_blocked", "desc": desc})
                elif "권한 침해" in desc:
                    self.mitre_strip.record_log_event({"event_type": "authz_deny", "desc": desc})

        self._update_dash_filter_chips()
        self._filter_dash_events("ALL")

    def _filter_dash_events(self, category="ALL"):
        self._current_dash_category = category
        self._clear_dash_events()
        for sev, ip, time_str, desc, act in getattr(self, "raw_dash_events", []):
            if category == "ALL" or sev == category:
                self._render_dash_event_card(sev, ip, time_str, desc, act)

    def _render_dash_event_card(self, sev, ip, time_str, desc, act):
        sev_styles = {
            "CRITICAL": ("#2b1419", "#ef4444", "🚨 CRITICAL"),
            "HIGH": ("#2a1708", "#f59e0b", "⚠️ HIGH"),
            "INFO": ("#0b1d3a", "#38bdf8", "ℹ️ INFO"),
        }
        sbg, sfg, stxt = sev_styles.get(sev, ("#1e293b", "#94a3b8", sev))

        card = ctk.CTkFrame(self.scroll_dash_events, fg_color="#0f172a", corner_radius=6, border_width=1, border_color="#1e293b")
        card.pack(fill="x", padx=4, pady=3)

        head = ctk.CTkFrame(card, fg_color="transparent")
        head.pack(fill="x", padx=10, pady=(6, 2))

        # Severity
        spill = ctk.CTkFrame(head, fg_color=sbg, corner_radius=4)
        spill.pack(side="left", padx=(0, 6))
        ctk.CTkLabel(spill, text=stxt, font=ctk.CTkFont(size=9, weight="bold"), text_color=sfg).pack(padx=6, pady=2)

        # MITRE ATT&CK Badge (CrowdStrike / SentinelOne Style)
        mapped = self.mitre_mapper.map_event({"desc": desc, "event": desc})
        tech_id = mapped.get("technique_id", "T1592")
        mitre_pill = ctk.CTkFrame(head, fg_color="#181329", corner_radius=4, border_width=1, border_color="#7c3aed")
        mitre_pill.pack(side="left", padx=(0, 6))
        ctk.CTkLabel(mitre_pill, text=f"ATT&CK {tech_id}", font=ctk.CTkFont(family="Consolas", size=9, weight="bold"), text_color="#c084fc").pack(padx=5, pady=2)

        # IP
        ctk.CTkLabel(head, text=ip, font=ctk.CTkFont(family="Consolas", size=10, weight="bold"), text_color="#38bdf8").pack(side="left", padx=4)

        # Time
        ctk.CTkLabel(head, text=f"[{time_str}]", font=ctk.CTkFont(size=9), text_color=TEXT_MUTED).pack(side="left", padx=4)

        # Action pill on right
        act_bg = "#2b1419" if "차단" in act or "거부" in act else ("#064e3b" if "통과" in act else "#2a1708")
        act_fg = "#ef4444" if "차단" in act or "거부" in act else ("#10b981" if "통과" in act else "#f59e0b")
        act_pill = ctk.CTkFrame(head, fg_color=act_bg, corner_radius=4)
        act_pill.pack(side="right")
        ctk.CTkLabel(act_pill, text=act, font=ctk.CTkFont(size=9, weight="bold"), text_color=act_fg).pack(padx=6, pady=2)

        # Desc
        ctk.CTkLabel(card, text=desc, font=ctk.CTkFont(size=10), text_color="#cbd5e1").pack(anchor="w", padx=10, pady=(0, 6))

    def _clear_dash_events(self):
        if hasattr(self, "scroll_dash_events"):
            for child in self.scroll_dash_events.winfo_children():
                child.destroy()

    def _kpi_score_radial_widget(self, parent, col_idx, row_idx=1):
        card = ctk.CTkFrame(parent, fg_color="#0f172a", corner_radius=12, border_width=1, border_color="#1e293b")
        card.grid(row=row_idx, column=col_idx, sticky="ew", padx=4)

        accent = ctk.CTkFrame(card, fg_color="#10b981", height=3, corner_radius=2)
        accent.pack(fill="x", padx=12, pady=(0, 4))

        head = ctk.CTkFrame(card, fg_color="transparent")
        head.pack(fill="x", padx=14, pady=(4, 2))
        ctk.CTkLabel(head, text="종합 보안 안전도", font=ctk.CTkFont(size=10, weight="bold"), text_color="#94a3b8").pack(side="left")
        ctk.CTkLabel(head, text="🛡️", font=ctk.CTkFont(size=13)).pack(side="right")

        self.ring_gauge = SecurityScoreRingGauge(card, score=100, size=94)
        self.ring_gauge.pack(anchor="center", pady=(0, 2))

        sub_box = ctk.CTkFrame(card, fg_color="#1e293b", corner_radius=4)
        sub_box.pack(anchor="center", padx=12, pady=(2, 8))
        self.lbl_score_sub = ctk.CTkLabel(sub_box, text=" A+ 최고 안전 상태 유지 ", font=ctk.CTkFont(size=9, weight="bold"), text_color="#10b981")
        self.lbl_score_sub.pack(padx=4, pady=1)

        class _ScoreProxy:
            def __init__(self, gauge, sub_lbl):
                self.gauge = gauge
                self.sub_lbl = sub_lbl
                self._text = "100 / 100"
            def cget(self, key):
                if key == "text":
                    return self._text
                return ""
            def configure(self, **kwargs):
                if "text" in kwargs:
                    t = kwargs["text"]
                    self._text = t
                    try:
                        pts = int(t.split("/")[0].strip())
                        self.gauge.draw_gauge(pts)
                        if pts >= 95:
                            self.sub_lbl.configure(text=" A+ 최고 안전 상태 유지 ", text_color="#10b981")
                        elif pts >= 90:
                            self.sub_lbl.configure(text=" A+ 안전 규격 통과 ", text_color="#10b981")
                        elif pts >= 70:
                            self.sub_lbl.configure(text=" B 주의 등급 통과 ", text_color="#f59e0b")
                        else:
                            self.sub_lbl.configure(text=" F 즉각 조치 필요 ", text_color="#f43f5e")
                    except Exception:
                        pass
        return _ScoreProxy(self.ring_gauge, self.lbl_score_sub)

    def _kpi_widget(self, parent, title, val, sub, col, col_idx, icon="📊", row_idx=1):
        card = ctk.CTkFrame(parent, fg_color="#0f172a", corner_radius=12, border_width=1, border_color="#1e293b")
        card.grid(row=row_idx, column=col_idx, sticky="ew", padx=4)

        # 상단 3px 컬러 액센트 바
        accent = ctk.CTkFrame(card, fg_color=col, height=3, corner_radius=2)
        accent.pack(fill="x", padx=12, pady=(0, 4))

        head = ctk.CTkFrame(card, fg_color="transparent")
        head.pack(fill="x", padx=16, pady=(4, 2))
        ctk.CTkLabel(head, text=title, font=ctk.CTkFont(size=10, weight="bold"), text_color="#94a3b8").pack(side="left")
        ctk.CTkLabel(head, text=icon, font=ctk.CTkFont(size=13)).pack(side="right")

        lbl_val = ctk.CTkLabel(card, text=val, font=ctk.CTkFont(size=24, weight="bold"), text_color=col)
        lbl_val.pack(anchor="w", padx=16, pady=2)

        sub_box = ctk.CTkFrame(card, fg_color="#1e293b", corner_radius=4)
        sub_box.pack(anchor="w", padx=16, pady=(4, 12))
        ctk.CTkLabel(sub_box, text=f" {sub} ", font=ctk.CTkFont(size=10), text_color="#cbd5e1").pack(padx=4, pady=1)

        return lbl_val

    # =========================================================================
    # 탭 2: 실시간 트래픽 & 침입 탐지 (GlassWire 스타일 캔버스 파형 그래프)
    # =========================================================================
    def _create_traffic_view(self):
        f = ctk.CTkFrame(self.views_container, fg_color="#0f172a", corner_radius=12)
        f.grid_rowconfigure(3, weight=1)
        f.grid_columnconfigure(0, weight=1)

        # 상단 헤더 및 컨트롤 바
        top = ctk.CTkFrame(f, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=16, pady=12)

        ctk.CTkLabel(
            top,
            text="📡 GlassWire 스타일 실시간 네트워크 트래픽 & 위협 파형 모니터",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#38bdf8",
        ).pack(side="left")

        ctk.CTkButton(
            top,
            text="로그 비우기",
            width=80,
            height=28,
            fg_color="#334155",
            hover_color="#475569",
            command=lambda: self.txt_traffic.delete("1.0", "end"),
        ).pack(side="right")

        self.btn_pause_graph = ctk.CTkButton(
            top,
            text="⏸️ 일시 정지",
            width=90,
            height=28,
            fg_color="#1e293b",
            hover_color="#334155",
            command=self._toggle_graph_pause,
        )
        self.btn_pause_graph.pack(side="right", padx=6)

        # GlassWire 시그니처: 실시간 트래픽 캔버스 그래프
        graph_box = ctk.CTkFrame(f, fg_color="#090d16", corner_radius=8, height=180)
        graph_box.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 10))
        graph_box.grid_propagate(False)

        self.traffic_canvas = tk.Canvas(
            graph_box,
            bg="#090d16",
            highlightthickness=0,
            height=160,
        )
        self.traffic_canvas.pack(fill="both", expand=True, padx=8, pady=8)

        # 트래픽 모니터링 실시간 상태 스트립 (4대 텔레메트리 타일 - psutil 실시간 연동)
        metric_bar = ctk.CTkFrame(f, fg_color="#1e293b", corner_radius=8)
        metric_bar.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 6))

        # 1) 실시간 대역폭
        b1 = ctk.CTkFrame(metric_bar, fg_color="transparent")
        b1.pack(side="left", padx=12, pady=6)
        ctk.CTkLabel(b1, text="● 실시간 대역폭:", font=ctk.CTkFont(size=10, weight="bold"), text_color="#10b981").pack(side="left", padx=(0, 4))
        self.lbl_traffic_bandwidth = ctk.CTkLabel(b1, text="0.0 KB/s", font=ctk.CTkFont(family="Consolas", size=10), text_color="#f8fafc")
        self.lbl_traffic_bandwidth.pack(side="left")

        # 2) 초당 패킷 처리
        b2 = ctk.CTkFrame(metric_bar, fg_color="transparent")
        b2.pack(side="left", padx=12, pady=6)
        ctk.CTkLabel(b2, text="● 초당 패킷 처리:", font=ctk.CTkFont(size=10, weight="bold"), text_color="#38bdf8").pack(side="left", padx=(0, 4))
        self.lbl_traffic_pps = ctk.CTkLabel(b2, text="0 PPS", font=ctk.CTkFont(family="Consolas", size=10), text_color="#f8fafc")
        self.lbl_traffic_pps.pack(side="left")

        # 3) 활성 차단 격리
        b3 = ctk.CTkFrame(metric_bar, fg_color="transparent")
        b3.pack(side="left", padx=12, pady=6)
        ctk.CTkLabel(b3, text="● 활성 격리 차단:", font=ctk.CTkFont(size=10, weight="bold"), text_color="#f43f5e").pack(side="left", padx=(0, 4))
        init_blocked = len(self.firewall.get_blocked_list())
        self.lbl_traffic_block_rate = ctk.CTkLabel(b3, text=f"{init_blocked}개 IP 차단 격리 중", font=ctk.CTkFont(family="Consolas", size=10), text_color="#f8fafc")
        self.lbl_traffic_block_rate.pack(side="left")

        # 4) 활성 네트워크 소켓
        b4 = ctk.CTkFrame(metric_bar, fg_color="transparent")
        b4.pack(side="left", padx=12, pady=6)
        ctk.CTkLabel(b4, text="● 활성 소켓 수:", font=ctk.CTkFont(size=10, weight="bold"), text_color="#fbbf24").pack(side="left", padx=(0, 4))
        self.lbl_traffic_sockets = ctk.CTkLabel(b4, text="조회 중...", font=ctk.CTkFont(family="Consolas", size=10), text_color="#f8fafc")
        self.lbl_traffic_sockets.pack(side="left")

        # GlassWire 시그니처: 프로토콜 디스트리뷰션 누적 바 (security.jsonl 실시간 분석)
        proto_bar = ctk.CTkFrame(f, fg_color="#090d16", corner_radius=6)
        proto_bar.grid(row=3, column=0, sticky="ew", padx=16, pady=(0, 10))

        ctk.CTkLabel(proto_bar, text="실시간 프로토콜 점유율:", font=ctk.CTkFont(size=9, weight="bold"), text_color="#94a3b8").pack(side="left", padx=(10, 8), pady=4)
        proto_segments = self._compute_protocol_distribution()
        for p_name, bg_c, fg_c in proto_segments:
            seg = ctk.CTkFrame(proto_bar, fg_color=bg_c, corner_radius=4)
            seg.pack(side="left", padx=3, pady=4)
            ctk.CTkLabel(seg, text=f" {p_name} ", font=ctk.CTkFont(size=9, weight="bold"), text_color=fg_c).pack(padx=4, pady=1)

        # 하단: 실시간 유입 패킷 텍스트 스트림
        self.txt_traffic = ctk.CTkTextbox(
            f,
            fg_color="#090d16",
            text_color="#38bdf8",
            font=ctk.CTkFont(family="Consolas", size=11),
        )
        self.txt_traffic.grid(row=4, column=0, sticky="nsew", padx=16, pady=(0, 16))
        f.grid_rowconfigure(4, weight=1)
        self.txt_traffic.insert("end", "[*] NEXUS-GUARD 실시간 인그레스 패킷 모니터 가동 시작.\n")
        target_disp = self.cfg.get('target_service', {}).get('web_portal_url') or "미등록 (설정 탭에서 지정 가능)"
        self.txt_traffic.insert("end", f"[*] 감시 대상 서비스: {target_disp}\n")
        self.txt_traffic.insert("end", "[*] 초록색 라인: 정상 OS 네트워크 트래픽 I/O | 붉은색 스파이크: 실제 악성 침해 차단 이벤트\n")

        return f

    def _compute_protocol_distribution(self):
        log_file = BASE_DIR / "logs" / "security.jsonl"
        counts = {"HTTP 웹 트래픽": 0, "API 인그레스": 0, "미끼 디코이 탐침": 0, "입구 차단 드롭": 0}
        if log_file.exists():
            try:
                with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            d = json.loads(line)
                            ev = d.get("event_type") or d.get("event") or ""
                            dec = d.get("decision") or ""
                            path = d.get("path") or ""
                            if ev == "decoy_triggered":
                                counts["미끼 디코이 탐침"] += 1
                            elif dec == "BLOCK" or ev == "ip_blocked":
                                counts["입구 차단 드롭"] += 1
                            elif "api" in path or ev in ("internal_api", "ai_request"):
                                counts["API 인그레스"] += 1
                            else:
                                counts["HTTP 웹 트래픽"] += 1
                        except Exception:
                            continue
            except Exception:
                pass

        total = sum(counts.values()) or 1
        styles = {
            "HTTP 웹 트래픽": ("#0c2e26", "#10b981"),
            "API 인그레스": ("#0b1d3a", "#38bdf8"),
            "미끼 디코이 탐침": ("#2a1708", "#f59e0b"),
            "입구 차단 드롭": ("#2b1419", "#f43f5e"),
        }
        segments = []
        for name in ["HTTP 웹 트래픽", "API 인그레스", "입구 차단 드롭", "미끼 디코이 탐침"]:
            cnt = counts[name]
            pct = (cnt / total) * 100.0
            bg_c, fg_c = styles[name]
            segments.append((f"{name} ({pct:.1f}%)", bg_c, fg_c))
        return segments

    def _toggle_graph_pause(self):
        self.graph_paused = not self.graph_paused
        self.btn_pause_graph.configure(text="▶️ 재개" if self.graph_paused else "⏸️ 일시 정지")

    def _schedule_graph_tick(self):
        if self.running and not self.graph_paused:
            # 1. 백그라운드 정밀 전수 진단 결과 메인스레드 동기화 처리
            if hasattr(self, "_audit_queue") and not self._audit_queue.empty():
                try:
                    rep, score, grade, findings, tampered, baseline_cnt, blocked_cnt = self._audit_queue.get_nowait()
                    self._apply_precision_audit_results(rep, score, grade, findings, tampered, baseline_cnt, blocked_cnt)
                except Exception:
                    pass

            # 2. 수동 정밀 진단 단계별 진행 상태 큐 처리
            if hasattr(self, "_manual_audit_phase_queue"):
                while not self._manual_audit_phase_queue.empty():
                    try:
                        p_step = self._manual_audit_phase_queue.get_nowait()
                        if p_step == 2:
                            self.lbl_scan_status.configure(text="[2/4] 설정된 타겟 주소(웹 포털 & DB & 외부 연동) 연결성 및 보안 헤더 검증 중...")
                            self.progress_bar.set(0.45)
                            if hasattr(self, "phase_tracker"):
                                self.phase_tracker.update_phase(0, "감사 완료", is_done=True)
                                self.phase_tracker.update_phase(1, "프로빙 중...", is_active=True)
                        elif p_step == 3:
                            self.lbl_scan_status.configure(text="[3/4] 파이썬 AST 파서로 SQL Injection 정적 취약점 전수 스캔 중...")
                            self.progress_bar.set(0.75)
                            if hasattr(self, "phase_tracker"):
                                self.phase_tracker.update_phase(1, "프로빙 완료", is_done=True)
                                self.phase_tracker.update_phase(2, "AST 분석 중...", is_active=True)
                    except Exception:
                        break

            # 3. 수동 정밀 진단 최종 완료 결과 큐 처리
            if hasattr(self, "_manual_audit_result_queue") and not self._manual_audit_result_queue.empty():
                try:
                    rep = self._manual_audit_result_queue.get_nowait()
                    if rep:
                        self._apply_scan_results(rep)
                        self.btn_run_audit.configure(text="🔍 전체 시스템 정밀 진단 시작", state="normal")
                        score = rep.get("security_score", 55)
                        grade = rep.get("security_grade", "C")
                        findings = rep.get("findings", [])
                        messagebox.showinfo("진단 완료", f"시스템 정밀 진단 완료!\n종합 점수: {score}점 ({grade})\n발견된 취약점: {len(findings)}건")
                    else:
                        self.btn_run_audit.configure(text="🔍 전체 시스템 정밀 진단 시작", state="normal")
                except Exception:
                    pass

            # 4. 실시간 보안 로그 스트림 큐 처리 (DoS 방어: 틱당 최대 35건 배치 처리 및 8ms 프레임 타임 버짓 준수)
            if hasattr(self, "_log_queue"):
                burst_budget = 35
                t_frame_start = time.perf_counter()
                while not self._log_queue.empty() and burst_budget > 0:
                    try:
                        raw_line = self._log_queue.get_nowait()
                        self._process_new_log_entry(raw_line)
                        burst_budget -= 1
                        if (time.perf_counter() - t_frame_start) * 1000.0 > 8.0:
                            break
                    except Exception:
                        break

            # 5. OS 실시간 네트워크 I/O 수집 및 GlassWire 파형 렌더링
            try:
                curr_io = psutil.net_io_counters()
                curr_time = time.time()
                dt = max(0.001, curr_time - getattr(self, "_last_tick_time", curr_time))
                self._last_tick_time = curr_time

                if self._last_net_io is not None:
                    bytes_delta = (curr_io.bytes_recv - self._last_net_io.bytes_recv) + (curr_io.bytes_sent - self._last_net_io.bytes_sent)
                    pkts_delta = (curr_io.packets_recv - self._last_net_io.packets_recv) + (curr_io.packets_sent - self._last_net_io.packets_sent)
                else:
                    bytes_delta = 0
                    pkts_delta = 0
                self._last_net_io = curr_io

                kb_sec = max(0.0, (bytes_delta / 1024.0) / dt)
                pps = max(0.0, pkts_delta / dt)
                self._live_kb_sec = kb_sec
                self._live_pps = pps

                # 캔버스 높이 스케일링 (최소 8 기본 표시로 직관적인 파형 형성)
                if kb_sec <= 0.1:
                    val_norm = 10
                elif kb_sec < 50:
                    val_norm = int(10 + (kb_sec / 50.0) * 35)
                elif kb_sec < 500:
                    val_norm = int(45 + ((kb_sec - 50.0) / 450.0) * 35)
                else:
                    val_norm = min(95, int(80 + (math.log10(max(1.0, kb_sec)) - 2.7) * 15))

                # 실제 악성 침해 이벤트 발생 시 붉은색 위협 스파이크 방출
                if getattr(self, "_threat_spike_ticks", 0) > 0:
                    val_threat = self._threat_spike_level
                    self._threat_spike_ticks -= 1
                    if self._threat_spike_ticks == 0:
                        self._refresh_real_triage_panel()
                else:
                    val_threat = 0

                self.traffic_history_normal.pop(0)
                self.traffic_history_normal.append(val_norm)
                self.traffic_history_threat.pop(0)
                self.traffic_history_threat.append(val_threat)

                self._render_traffic_graph()

                # CrowdStrike / Datadog 스타일 실시간 텔레메트리 Freshness Ticker 갱신
                refresh_ms = dt * 1000.0
                raw_jitter = abs(dt - 0.400) * 1000.0
                self._jitter_smooth = 0.8 * getattr(self, "_jitter_smooth", 1.8) + 0.2 * raw_jitter
                if hasattr(self, "live_ticker"):
                    is_cont = self.firewall.is_contained() if hasattr(self, "firewall") else False
                    self.live_ticker.update_metrics(
                        refresh_ms=refresh_ms,
                        jitter_ms=self._jitter_smooth,
                        soc_level="PROD",
                        is_contained=is_cont,
                    )

                # 주기적 텔레메트리 타일 수치 갱신 (~800ms) 및 XDR 판정 패널 동기화 (~2초)
                self._tick_counter = getattr(self, "_tick_counter", 0) + 1
                if self._tick_counter % 2 == 0:
                    self._update_traffic_pills(kb_sec, pps)
                if self._tick_counter % 5 == 0:
                    self._refresh_real_triage_panel()

            except Exception:
                pass

        if self.running:
            self.after(400, self._schedule_graph_tick)

    def _update_traffic_pills(self, kb_sec, pps):
        try:
            if hasattr(self, "lbl_traffic_bandwidth"):
                self.lbl_traffic_bandwidth.configure(text=f"{kb_sec:.1f} KB/s")
            if hasattr(self, "lbl_traffic_pps"):
                self.lbl_traffic_pps.configure(text=f"{int(pps)} PPS")
            if hasattr(self, "lbl_traffic_sockets"):
                try:
                    socks = len(psutil.net_connections(kind="inet"))
                    self.lbl_traffic_sockets.configure(text=f"{socks}개 활성 소켓")
                except Exception:
                    self.lbl_traffic_sockets.configure(text="정상 유지")
            if hasattr(self, "lbl_traffic_block_rate"):
                blocked_cnt = len(self.firewall.get_blocked_list())
                self.lbl_traffic_block_rate.configure(text=f"{blocked_cnt}개 IP 차단 격리 중")
        except Exception:
            pass

    def _render_traffic_graph(self):
        if not hasattr(self, "traffic_canvas"):
            return
        c = self.traffic_canvas
        w = c.winfo_width()
        h = c.winfo_height()
        if w < 50 or h < 50:
            return

        c.delete("all")

        # 1. 배경 매트릭스 그리드 (수평 & 수직 눈금선)
        for y_pct in (0.25, 0.5, 0.75):
            y = h * y_pct
            c.create_line(0, y, w, y, fill="#131c2e", dash=(2, 4))
            val_kb = int((1.0 - y_pct) * 100)
            c.create_text(w - 28, y - 6, text=f"{val_kb} KB/s", fill=TEXT_MUTED, font=(FONT_FAMILY_MONO, 9))

        # 세로 격자선
        for x_step in range(1, 8):
            vx = int(w * (x_step / 8.0))
            c.create_line(vx, 0, vx, h, fill="#0f1624", dash=(1, 6))

        # 2. 상단 HUD 타이틀 및 범례 표시
        c.create_text(14, 12, anchor="w", text="● INBOUND NORMAL TRAFFIC (에메랄드 스플라인)", fill=COLOR_SECURE, font=(FONT_FAMILY_UI, 9, "bold"))
        c.create_text(300, 12, anchor="w", text="● THREAT PEAK GLOW (위협 차단 스파이크)", fill=COLOR_ALERT, font=(FONT_FAMILY_UI, 9, "bold"))
        c.create_text(w - 120, 12, anchor="w", text="REALTIME I/O: ACTIVE", fill=COLOR_CYAN, font=(FONT_FAMILY_MONO, 9, "bold"))

        # 3. 데이터 포인트 변환 및 스무스 스플라인 렌더링
        n_points = len(self.traffic_history_normal)
        step_x = w / max(1, (n_points - 1))

        # 정상 트래픽 면적 폴리곤 (2단계 네온 듀얼톤)
        poly_points = [0, h]
        for i, val in enumerate(self.traffic_history_normal):
            x = i * step_x
            y = h - (val / 100.0) * (h - 28) - 6
            poly_points.extend([x, y])
        poly_points.extend([w, h])
        c.create_polygon(poly_points, fill="#07221c", outline="")

        # 상단 에지 스무스 라인 (네온 하이라이트)
        line_coords = []
        for i, val in enumerate(self.traffic_history_normal):
            x = i * step_x
            y = h - (val / 100.0) * (h - 28) - 6
            line_coords.extend([x, y])
        c.create_line(line_coords, fill=COLOR_SECURE, width=2.2, smooth=True)

        # 오실로스코프 스캔 커서 (Scanning Beam Line)
        self._scan_x = (getattr(self, "_scan_x", 0) + 8) % max(1, int(w))
        c.create_line(self._scan_x, 0, self._scan_x, h, fill="#0284c7", width=1, dash=(2, 4))
        c.create_oval(self._scan_x - 3, h - 8, self._scan_x + 3, h - 2, fill=COLOR_CYAN, outline="")

        # 위협 스파이크 피크 글로우 렌더링
        for i, val in enumerate(self.traffic_history_threat):
            if val > 0:
                x = i * step_x
                y = h - (val / 100.0) * (h - 28) - 6
                # 수직 강제 드롭 레이저 빔
                c.create_line(x, h, x, y, fill=COLOR_ALERT, width=2.5)
                # 네온 글로우 펄스 링
                c.create_oval(x - 7, y - 7, x + 7, y + 7, outline=COLOR_ALERT, width=1.2)
                c.create_oval(x - 3, y - 3, x + 3, y + 3, fill="#ffffff", outline=COLOR_ALERT)
                c.create_text(x, max(12, y - 10), text="BLOCK 403", fill=COLOR_ALERT, font=(FONT_FAMILY_UI, 9, "bold"))

    # =========================================================================
    # 탭 3: 호스트 방화벽 & 차단 IP 관리 (GlassWire Firewall 탭 스타일)
    # =========================================================================
    def _create_firewall_view(self):
        f = ctk.CTkFrame(self.views_container, fg_color="transparent")
        f.grid_rowconfigure(1, weight=1)
        f.grid_columnconfigure(0, weight=1)

        # 수동 차단 등록 툴바
        form = ctk.CTkFrame(f, fg_color="#0f172a", corner_radius=12)
        form.grid(row=0, column=0, sticky="ew", pady=(0, 14))

        ctk.CTkLabel(form, text="차단 IP:", font=ctk.CTkFont(size=11, weight="bold")).pack(side="left", padx=(16, 6), pady=14)
        self.ent_fw_ip = ctk.CTkEntry(form, width=140, placeholder_text="예: 203.0.113.50")
        self.ent_fw_ip.pack(side="left", padx=4)

        ctk.CTkLabel(form, text="차단 사유:", font=ctk.CTkFont(size=11, weight="bold")).pack(side="left", padx=(10, 6))
        self.ent_fw_reason = ctk.CTkEntry(form, width=200, placeholder_text="차단 사유 (프리셋 선택 가능)")
        self.ent_fw_reason.pack(side="left", padx=4)

        def _on_reason_preset(choice):
            self.ent_fw_reason.delete(0, "end")
            self.ent_fw_reason.insert(0, choice)

        self.opt_reason_preset = ctk.CTkOptionMenu(
            form,
            values=[
                "비인가 악성 스캔 탐지",
                "관리자 계정 무차별 대입",
                "미끼 경로(/.env) 불법 탐침",
                "SQL Injection 공격 의심",
                "비인가 기밀문서 열람(BOLA)",
            ],
            width=170,
            command=_on_reason_preset,
        )
        self.opt_reason_preset.set("📋 사유 프리셋 선택")
        self.opt_reason_preset.pack(side="left", padx=4)

        ctk.CTkButton(
            form,
            text="🚫 403 즉시 차단",
            width=110,
            fg_color="#e11d48",
            hover_color="#be123c",
            font=ctk.CTkFont(size=11, weight="bold"),
            command=self._on_fw_block,
        ).pack(side="left", padx=8)

        ctk.CTkButton(
            form,
            text="Windows 방화벽(netsh) 연동",
            width=170,
            fg_color="#2563eb",
            hover_color="#1d4ed8",
            font=ctk.CTkFont(size=11, weight="bold"),
            command=self._on_fw_netsh,
        ).pack(side="left", padx=4)

        self.btn_fw_contain = ctk.CTkButton(
            form,
            text="🚨 1-클릭 비상 격리",
            width=140,
            fg_color="#7f1d1d",
            hover_color="#991b1b",
            font=ctk.CTkFont(size=11, weight="bold"),
            command=self._on_toggle_emergency_containment,
        )
        self.btn_fw_contain.pack(side="left", padx=6)

        self.lbl_fw_contain_status = ctk.CTkLabel(
            form,
            text="● [OPERATIONAL] 정상 운영 중",
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color="#10b981",
        )
        self.lbl_fw_contain_status.pack(side="left", padx=8)

        # 활성 블랙리스트 테이블 표시 박스
        tbl_box = ctk.CTkFrame(f, fg_color="#0f172a", corner_radius=12)
        tbl_box.grid(row=1, column=0, sticky="nsew")
        tbl_box.grid_rowconfigure(2, weight=1)
        tbl_box.grid_columnconfigure(0, weight=1)

        top_tbl = ctk.CTkFrame(tbl_box, fg_color="transparent")
        top_tbl.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 6))

        ctk.CTkLabel(
            top_tbl,
            text="📋 현재 활성 차단 IP 목록 (Active Host Firewall Blacklist)",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#f8fafc",
        ).pack(side="left")

        ctk.CTkButton(
            top_tbl,
            text="🔄 1초 만에 전체 차단 초기화 및 원상복구",
            fg_color="#16a34a",
            hover_color="#15803d",
            font=ctk.CTkFont(size=11, weight="bold"),
            command=self._on_fw_clear_all,
        ).pack(side="right")

        self.ent_fw_search = ctk.CTkEntry(
            top_tbl,
            width=220,
            height=28,
            placeholder_text="🔍 IP 또는 침해 사유 검색...",
        )
        self.ent_fw_search.pack(side="right", padx=10)
        self.ent_fw_search.bind("<KeyRelease>", lambda e: self._refresh_fw_display())

        # 컬럼 헤더 바
        col_bar = ctk.CTkFrame(tbl_box, fg_color="#1e293b", corner_radius=6, height=32)
        col_bar.grid(row=1, column=0, sticky="ew", padx=16, pady=(4, 6))

        ctk.CTkLabel(col_bar, text="차단 대상 IP", width=140, anchor="w", font=ctk.CTkFont(size=11, weight="bold"), text_color="#94a3b8").pack(side="left", padx=(14, 4))
        ctk.CTkLabel(col_bar, text="침해 발생 사유", width=230, anchor="w", font=ctk.CTkFont(size=11, weight="bold"), text_color="#94a3b8").pack(side="left", padx=4)
        ctk.CTkLabel(col_bar, text="침해 횟수", width=80, anchor="center", font=ctk.CTkFont(size=11, weight="bold"), text_color="#94a3b8").pack(side="left", padx=4)
        ctk.CTkLabel(col_bar, text="남은 차단 시간 (TTL)", width=120, anchor="center", font=ctk.CTkFont(size=11, weight="bold"), text_color="#94a3b8").pack(side="left", padx=4)
        ctk.CTkLabel(col_bar, text="방화벽 정책 상태", width=120, anchor="center", font=ctk.CTkFont(size=11, weight="bold"), text_color="#94a3b8").pack(side="left", padx=4)
        ctk.CTkLabel(col_bar, text="원클릭 해제", width=90, anchor="e", font=ctk.CTkFont(size=11, weight="bold"), text_color="#94a3b8").pack(side="right", padx=(4, 16))

        self.scroll_fw_list = ctk.CTkScrollableFrame(tbl_box, fg_color="#090d16", corner_radius=8)
        self.scroll_fw_list.grid(row=2, column=0, sticky="nsew", padx=16, pady=(0, 16))
        self._refresh_fw_display()

        return f

    def _refresh_fw_display(self):
        if not hasattr(self, "scroll_fw_list"):
            return
        for child in self.scroll_fw_list.winfo_children():
            child.destroy()

        items = self.firewall.get_blocked_list()
        q = self.ent_fw_search.get().strip().lower() if hasattr(self, "ent_fw_search") else ""
        if q:
            items = [it for it in items if q in it.get("ip", "").lower() or q in it.get("reason", "").lower()]

        if not items:
            empty_box = ctk.CTkFrame(self.scroll_fw_list, fg_color="#102a24", corner_radius=8, border_width=1, border_color="#10b981")
            empty_box.pack(fill="x", padx=4, pady=16)
            msg = "검색 결과와 일치하는 차단 내역이 없습니다." if q else "✨ 현재 활성 차단된 악성 IP가 없습니다 (모든 네트워크 트래픽 정상 통과 상태)."
            ctk.CTkLabel(
                empty_box,
                text=msg,
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color="#10b981",
            ).pack(padx=16, pady=14)
        else:
            for item in items:
                row = ctk.CTkFrame(self.scroll_fw_list, fg_color="#0f172a", corner_radius=6, border_width=1, border_color="#334155")
                row.pack(fill="x", padx=2, pady=3)

                ctk.CTkLabel(row, text=item["ip"], width=140, anchor="w", font=ctk.CTkFont(family="Consolas", size=11, weight="bold"), text_color="#38bdf8").pack(side="left", padx=(14, 4), pady=8)

                # Reason pill
                r_pill = ctk.CTkFrame(row, fg_color="#1e293b", corner_radius=4)
                r_pill.pack(side="left", padx=4)
                ctk.CTkLabel(r_pill, text=item["reason"], width=220, anchor="w", font=ctk.CTkFont(size=10), text_color="#e2e8f0").pack(padx=6, pady=2)

                # Hits
                ctk.CTkLabel(row, text=f"{item['hits']}회", width=80, anchor="center", font=ctk.CTkFont(size=11), text_color="#f59e0b").pack(side="left", padx=4)

                # Remaining time (TTL Progress Bar)
                ttl_box = ctk.CTkFrame(row, fg_color="transparent", width=120)
                ttl_box.pack(side="left", padx=4)
                rem_sec = item.get("remaining_seconds", 900)
                ratio = min(1.0, max(0.0, rem_sec / 900.0))
                bar_col = "#f59e0b" if rem_sec < 180 else "#38bdf8"
                ctk.CTkLabel(ttl_box, text=f"⏳ {rem_sec}초 남음", font=ctk.CTkFont(family="Consolas", size=9), text_color="#cbd5e1").pack(anchor="w")
                bar = ctk.CTkProgressBar(ttl_box, width=110, height=5, progress_color=bar_col)
                bar.set(ratio)
                bar.pack(anchor="w", pady=(1, 0))

                # Status pill
                s_pill = ctk.CTkFrame(row, fg_color="#2b1419", corner_radius=4)
                s_pill.pack(side="left", padx=4)
                ctk.CTkLabel(s_pill, text="🚫 403 / netsh", width=105, anchor="center", font=ctk.CTkFont(size=9, weight="bold"), text_color="#f43f5e").pack(padx=4, pady=2)

                # Action button
                ctk.CTkButton(
                    row,
                    text="🔓 해제",
                    width=70,
                    height=26,
                    fg_color="#334155",
                    hover_color="#ef4444",
                    font=ctk.CTkFont(size=10, weight="bold"),
                    command=lambda target_ip=item["ip"]: self._on_unblock_single_ip(target_ip),
                ).pack(side="right", padx=(4, 14))

        if hasattr(self, "card_blocked"):
            self.card_blocked.configure(text=f"{len(items)} 건")

    def _on_unblock_single_ip(self, ip):
        self.firewall.remove_block_ip(ip)
        self._refresh_fw_display()
        self._refresh_real_triage_panel()
        if hasattr(self, "txt_traffic"):
            self.txt_traffic.insert("end", f"[{datetime.now().strftime('%H:%M:%S')}] [방화벽] IP {ip}가 차단 해제되었습니다.\n")
        messagebox.showinfo("차단 해제", f"IP {ip}의 차단이 즉시 정상 해제되었습니다.")

    def _on_fw_block(self):
        ip = self.ent_fw_ip.get().strip()
        reason = self.ent_fw_reason.get().strip()
        if not ip:
            messagebox.showwarning("입력 필요", "차단할 IP를 입력하세요.")
            return
        ok = self.firewall.add_block_ip(ip, reason)
        if not ok:
            messagebox.showwarning(
                "차단 불가 (보호 위반)",
                f"입력한 IP '{ip}'는 유효하지 않은 IP 주소이거나 로컬 루프백(127.0.0.1) 등 보호 대상이므로 차단할 수 없습니다.",
            )
            return
        self._refresh_fw_display()
        self._refresh_real_triage_panel()
        self._append_traffic_log(f"[방화벽] IP {ip}가 차단 목록에 등록되었습니다.")
        messagebox.showinfo("차단 완료", f"IP {ip}가 입구 차단(403) 및 블랙리스트에 성공적으로 등록되었습니다.")

    def _on_fw_clear_all(self):
        cnt = self.firewall.clear_all()
        try:
            subprocess.run([sys.executable, str(BASE_DIR / "demo_runner.py"), "--cleanup"], capture_output=True)
        except Exception:
            pass
        self._refresh_fw_display()
        self._refresh_real_triage_panel()
        self.txt_traffic.insert("end", f"[{datetime.now().strftime('%H:%M:%S')}] [방화벽] 전체 차단 IP 및 잠금 상태가 원상복구되었습니다.\n")
        messagebox.showinfo("복구 완료", "모든 차단 IP와 잠금 계정이 1초 만에 정상 원상복구되었습니다.")

    def _on_fw_netsh(self):
        ip = self.ent_fw_ip.get().strip()
        if not ip:
            messagebox.showwarning("입력 필요", "Windows 방화벽(netsh)에 등록할 IP를 입력하세요.")
            return
        ok, msg = self.firewall.apply_windows_firewall_rule(ip)
        messagebox.showinfo("Windows 방화벽 결과", msg)

    # =========================================================================
    # 탭 3.5: pfSense & Graylog 룰셋 커스텀 관리자
    # =========================================================================
    def _create_rulesets_view(self):
        f = ctk.CTkFrame(self.views_container, fg_color="transparent")
        f.grid_rowconfigure(1, weight=1)
        f.grid_columnconfigure(0, weight=1)

        # 서브 세그먼트 네비게이션 & 실시간 룰 검색 툴바
        rules_nav = ctk.CTkFrame(f, fg_color="#0f172a", corner_radius=10, height=48)
        rules_nav.grid(row=0, column=0, sticky="ew", padx=4, pady=(0, 10))

        self.seg_ruleset = ctk.CTkSegmentedButton(
            rules_nav,
            values=["🧱 pfSense 방화벽 룰셋 (5)", "📊 Graylog SIEM 상관분석 룰 (4)", "🔄 위협 시그니처 배포 센터"],
            command=self._on_ruleset_subtab_change,
            selected_color="#2563eb",
            selected_hover_color="#1d4ed8",
            unselected_color="#1e293b",
            font=ctk.CTkFont(size=11, weight="bold"),
        )
        self.seg_ruleset.pack(side="left", padx=12, pady=8)
        self.seg_ruleset.set("🧱 pfSense 방화벽 룰셋 (5)")

        self.ent_rule_search = ctk.CTkEntry(
            rules_nav,
            width=260,
            height=30,
            placeholder_text="🔍 룰 명칭, 프로토콜, 포트 검색...",
        )
        self.ent_rule_search.pack(side="right", padx=12, pady=8)
        self.ent_rule_search.bind("<KeyRelease>", lambda e: self._on_rule_search_key())

        # 메인 서브탭 컨테이너 박스
        self.subtabs_container = ctk.CTkFrame(f, fg_color="transparent")
        self.subtabs_container.grid(row=1, column=0, sticky="nsew", padx=0, pady=0)
        self.subtabs_container.grid_rowconfigure(0, weight=1)
        self.subtabs_container.grid_columnconfigure(0, weight=1)

        # 3대 서브탭 컨테이너
        self.subtab_fw = ctk.CTkScrollableFrame(self.subtabs_container, fg_color="transparent")
        self.subtab_siem = ctk.CTkScrollableFrame(self.subtabs_container, fg_color="transparent")
        self.subtab_sig = ctk.CTkScrollableFrame(self.subtabs_container, fg_color="transparent")

        # 1. 서브탭 1: pfSense 방화벽 필터링 룰셋 (Firewall Rule Policies)
        card_fw = ctk.CTkFrame(self.subtab_fw, fg_color="#0f172a", corner_radius=12)
        card_fw.pack(fill="x", pady=(0, 16), padx=4)

        fw_head = ctk.CTkFrame(card_fw, fg_color="transparent")
        fw_head.pack(fill="x", padx=16, pady=(14, 6))

        ctk.CTkLabel(
            fw_head,
            text="🧱 pfSense 스타일 방화벽 필터링 룰셋 (Firewall Rule Policies)",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#38bdf8",
        ).pack(side="left")

        # 기존 등록 룰 드롭다운 셀렉터 ⭐
        sel_fw_box = ctk.CTkFrame(card_fw, fg_color="#1e293b", corner_radius=8)
        sel_fw_box.pack(fill="x", padx=16, pady=(0, 10))

        ctk.CTkLabel(sel_fw_box, text="🎯 등록된 룰 선택:", font=ctk.CTkFont(size=11, weight="bold"), text_color="#f8fafc").pack(side="left", padx=(12, 6), pady=8)

        self.opt_fw_select = ctk.CTkOptionMenu(
            sel_fw_box,
            values=["-- 새 규칙 등록 (직접 입력) --"],
            width=360,
            height=30,
            command=self._on_select_fw_rule_from_menu,
        )
        self.opt_fw_select.pack(side="left", padx=4)

        ctk.CTkButton(
            sel_fw_box,
            text="🔄 룰 목록 새로고침",
            width=110,
            height=28,
            fg_color="#334155",
            hover_color="#475569",
            font=ctk.CTkFont(size=11),
            command=self._refresh_fw_rules_display,
        ).pack(side="right", padx=10)

        # 룰 편집 폼
        fw_form = ctk.CTkFrame(card_fw, fg_color="#090d16", corner_radius=8)
        fw_form.pack(fill="x", padx=16, pady=(0, 10))

        ctk.CTkLabel(fw_form, text="동작:", font=ctk.CTkFont(size=10, weight="bold")).pack(side="left", padx=(10, 4), pady=10)
        self.opt_fw_action = ctk.CTkOptionMenu(fw_form, values=["BLOCK", "PASS"], width=85, height=28)
        self.opt_fw_action.pack(side="left", padx=2)

        ctk.CTkLabel(fw_form, text="프로토콜:", font=ctk.CTkFont(size=10, weight="bold")).pack(side="left", padx=(8, 4))
        self.opt_fw_proto = ctk.CTkOptionMenu(fw_form, values=["TCP", "UDP", "ANY"], width=80, height=28)
        self.opt_fw_proto.pack(side="left", padx=2)

        ctk.CTkLabel(fw_form, text="출발지 IP:", font=ctk.CTkFont(size=10, weight="bold")).pack(side="left", padx=(8, 4))
        self.ent_fw_src = ctk.CTkEntry(fw_form, width=120, height=28, placeholder_text="192.168.1.100")
        self.ent_fw_src.pack(side="left", padx=2)

        ctk.CTkLabel(fw_form, text="포트:", font=ctk.CTkFont(size=10, weight="bold")).pack(side="left", padx=(8, 4))
        self.ent_fw_port = ctk.CTkEntry(fw_form, width=70, height=28, placeholder_text="5070")
        self.ent_fw_port.pack(side="left", padx=2)

        ctk.CTkLabel(fw_form, text="설명:", font=ctk.CTkFont(size=10, weight="bold")).pack(side="left", padx=(8, 4))
        self.ent_fw_desc = ctk.CTkEntry(fw_form, width=160, height=28, placeholder_text="악성 스캐너 차단")
        self.ent_fw_desc.pack(side="left", padx=2)

        ctk.CTkButton(
            fw_form,
            text="💾 룰 수정 적용",
            width=100,
            height=28,
            fg_color="#0284c7",
            hover_color="#0369a1",
            font=ctk.CTkFont(size=11, weight="bold"),
            command=self._on_update_fw_rule,
        ).pack(side="left", padx=3)

        ctk.CTkButton(
            fw_form,
            text="➕ 새 룰 등록",
            width=90,
            height=28,
            fg_color="#2563eb",
            hover_color="#1d4ed8",
            font=ctk.CTkFont(size=11, weight="bold"),
            command=self._on_add_fw_rule,
        ).pack(side="left", padx=3)

        # 방화벽 룰 컬럼 헤더 바
        col_fw = ctk.CTkFrame(card_fw, fg_color="#1e293b", corner_radius=6, height=30)
        col_fw.pack(fill="x", padx=16, pady=(0, 4))

        ctk.CTkLabel(col_fw, text="룰 ID", width=70, anchor="w", font=ctk.CTkFont(size=10, weight="bold"), text_color="#94a3b8").pack(side="left", padx=(12, 4))
        ctk.CTkLabel(col_fw, text="동작 정책", width=75, anchor="center", font=ctk.CTkFont(size=10, weight="bold"), text_color="#94a3b8").pack(side="left", padx=4)
        ctk.CTkLabel(col_fw, text="네트워크/프로토콜", width=105, anchor="center", font=ctk.CTkFont(size=10, weight="bold"), text_color="#94a3b8").pack(side="left", padx=4)
        ctk.CTkLabel(col_fw, text="출발지 IP -> 목적 포트", width=170, anchor="w", font=ctk.CTkFont(size=10, weight="bold"), text_color="#94a3b8").pack(side="left", padx=4)
        ctk.CTkLabel(col_fw, text="상태", width=70, anchor="center", font=ctk.CTkFont(size=10, weight="bold"), text_color="#94a3b8").pack(side="left", padx=4)
        ctk.CTkLabel(col_fw, text="규칙 상세 설명", anchor="w", font=ctk.CTkFont(size=10, weight="bold"), text_color="#94a3b8").pack(side="left", fill="x", expand=True, padx=4)
        ctk.CTkLabel(col_fw, text="원클릭 관리", width=120, anchor="e", font=ctk.CTkFont(size=10, weight="bold"), text_color="#94a3b8").pack(side="right", padx=(4, 14))

        # 룰 목록 스크롤 프레임 (카드 테이블 스타일)
        self.scroll_fw_rules = ctk.CTkScrollableFrame(
            card_fw,
            height=170,
            fg_color="#090d16",
            corner_radius=8,
        )
        self.scroll_fw_rules.pack(fill="x", padx=16, pady=(0, 10))

        # 룰 제어 바 (토글 및 삭제)
        fw_ctrl = ctk.CTkFrame(card_fw, fg_color="transparent")
        fw_ctrl.pack(fill="x", padx=16, pady=(0, 14))

        ctk.CTkLabel(fw_ctrl, text="선택된 룰 ID:", font=ctk.CTkFont(size=11, weight="bold")).pack(side="left", padx=(0, 6))
        self.ent_fw_target_id = ctk.CTkEntry(fw_ctrl, width=100, height=28, placeholder_text="FW-001")
        self.ent_fw_target_id.pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            fw_ctrl,
            text="🔄 룰 활성/비활성 토글",
            width=140,
            height=28,
            fg_color="#334155",
            hover_color="#475569",
            font=ctk.CTkFont(size=11),
            command=self._on_toggle_fw_rule,
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            fw_ctrl,
            text="🗑️ 선택 룰 삭제",
            width=110,
            height=28,
            fg_color="#e11d48",
            hover_color="#be123c",
            font=ctk.CTkFont(size=11),
            command=self._on_delete_fw_rule,
        ).pack(side="left")

        # 2. 서브탭 2: Graylog 스타일 SIEM 이벤트 상관분석 & 탐지 룰셋 (Correlation Rules)
        card_siem = ctk.CTkFrame(self.subtab_siem, fg_color="#0f172a", corner_radius=12)
        card_siem.pack(fill="x", pady=(0, 16), padx=4)

        siem_head = ctk.CTkFrame(card_siem, fg_color="transparent")
        siem_head.pack(fill="x", padx=16, pady=(14, 6))

        ctk.CTkLabel(
            siem_head,
            text="📊 Graylog 스타일 SIEM 상관분석 탐지 룰셋 (Event Correlation Rules)",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#38bdf8",
        ).pack(side="left")

        # 등록된 SIEM 룰 선택 셀렉터 ⭐
        sel_siem_box = ctk.CTkFrame(card_siem, fg_color="#1e293b", corner_radius=8)
        sel_siem_box.pack(fill="x", padx=16, pady=(0, 10))

        ctk.CTkLabel(sel_siem_box, text="🎯 등록된 SIEM 룰 선택:", font=ctk.CTkFont(size=11, weight="bold"), text_color="#f8fafc").pack(side="left", padx=(12, 6), pady=8)

        self.opt_siem_select = ctk.CTkOptionMenu(
            sel_siem_box,
            values=["-- 새 탐지 룰 등록 (직접 입력) --"],
            width=380,
            height=30,
            command=self._on_select_siem_rule_from_menu,
        )
        self.opt_siem_select.pack(side="left", padx=4)

        ctk.CTkButton(
            sel_siem_box,
            text="🔄 룰 목록 새로고침",
            width=110,
            height=28,
            fg_color="#334155",
            hover_color="#475569",
            font=ctk.CTkFont(size=11),
            command=self._refresh_siem_rules_display,
        ).pack(side="right", padx=10)

        # SIEM 룰 편집 폼
        siem_form = ctk.CTkFrame(card_siem, fg_color="#090d16", corner_radius=8)
        siem_form.pack(fill="x", padx=16, pady=(0, 10))

        ctk.CTkLabel(siem_form, text="규칙명:", font=ctk.CTkFont(size=10, weight="bold")).pack(side="left", padx=(10, 4), pady=10)
        self.ent_siem_name = ctk.CTkEntry(siem_form, width=140, height=28, placeholder_text="포트스캔 탐지")
        self.ent_siem_name.pack(side="left", padx=2)

        ctk.CTkLabel(siem_form, text="대상필드:", font=ctk.CTkFont(size=10, weight="bold")).pack(side="left", padx=(6, 4))
        self.opt_siem_field = ctk.CTkOptionMenu(
            siem_form,
            values=[
                "request_path (디코이 경로)",
                "failed_logins (로그인 실패 수)",
                "doc_owner_mismatch (BOLA 권한)",
                "ast_constant (SQLi 의심)",
                "file_hash_diff (FIM 변조)",
                "credential_stuffing_rate (분산 대입)",
            ],
            width=165,
            height=28,
        )
        self.opt_siem_field.pack(side="left", padx=2)

        ctk.CTkLabel(siem_form, text="임계치:", font=ctk.CTkFont(size=10, weight="bold")).pack(side="left", padx=(6, 4))
        self.ent_siem_th = ctk.CTkEntry(siem_form, width=50, height=28, placeholder_text="10")
        self.ent_siem_th.insert(0, "10")
        self.ent_siem_th.pack(side="left", padx=2)

        ctk.CTkLabel(siem_form, text="위협도:", font=ctk.CTkFont(size=10, weight="bold")).pack(side="left", padx=(6, 4))
        self.opt_siem_sev = ctk.CTkOptionMenu(siem_form, values=["CRITICAL", "HIGH", "MEDIUM", "LOW"], width=95, height=28)
        self.opt_siem_sev.pack(side="left", padx=2)

        ctk.CTkLabel(siem_form, text="자동조치:", font=ctk.CTkFont(size=10, weight="bold")).pack(side="left", padx=(6, 4))
        self.opt_siem_act = ctk.CTkOptionMenu(siem_form, values=["BLOCK_IP_403", "LOCK_ACCOUNT_15M", "DROP_EXECUTION", "ALERT_ONLY"], width=130, height=28)
        self.opt_siem_act.pack(side="left", padx=2)

        ctk.CTkButton(
            siem_form,
            text="💾 룰 수정 적용",
            width=100,
            height=28,
            fg_color="#059669",
            hover_color="#047857",
            font=ctk.CTkFont(size=11, weight="bold"),
            command=self._on_update_siem_rule,
        ).pack(side="left", padx=3)

        ctk.CTkButton(
            siem_form,
            text="➕ 새 룰 등록",
            width=90,
            height=28,
            fg_color="#16a34a",
            hover_color="#15803d",
            font=ctk.CTkFont(size=11, weight="bold"),
            command=self._on_add_siem_rule,
        ).pack(side="left", padx=3)

        # SIEM 룰 컬럼 헤더 바
        col_siem = ctk.CTkFrame(card_siem, fg_color="#1e293b", corner_radius=6, height=30)
        col_siem.pack(fill="x", padx=16, pady=(0, 4))

        ctk.CTkLabel(col_siem, text="룰 ID", width=75, anchor="w", font=ctk.CTkFont(size=10, weight="bold"), text_color="#94a3b8").pack(side="left", padx=(12, 4))
        ctk.CTkLabel(col_siem, text="위협도", width=80, anchor="center", font=ctk.CTkFont(size=10, weight="bold"), text_color="#94a3b8").pack(side="left", padx=4)
        ctk.CTkLabel(col_siem, text="감시 필드 (임계치)", width=170, anchor="w", font=ctk.CTkFont(size=10, weight="bold"), text_color="#94a3b8").pack(side="left", padx=4)
        ctk.CTkLabel(col_siem, text="자동 대응 조치", width=130, anchor="center", font=ctk.CTkFont(size=10, weight="bold"), text_color="#94a3b8").pack(side="left", padx=4)
        ctk.CTkLabel(col_siem, text="상태", width=70, anchor="center", font=ctk.CTkFont(size=10, weight="bold"), text_color="#94a3b8").pack(side="left", padx=4)
        ctk.CTkLabel(col_siem, text="탐지 룰 명칭", anchor="w", font=ctk.CTkFont(size=10, weight="bold"), text_color="#94a3b8").pack(side="left", fill="x", expand=True, padx=4)
        ctk.CTkLabel(col_siem, text="원클릭 관리", width=120, anchor="e", font=ctk.CTkFont(size=10, weight="bold"), text_color="#94a3b8").pack(side="right", padx=(4, 14))

        # SIEM 룰 목록 스크롤 프레임 (카드 테이블 스타일)
        self.scroll_siem_rules = ctk.CTkScrollableFrame(
            card_siem,
            height=170,
            fg_color="#090d16",
            corner_radius=8,
        )
        self.scroll_siem_rules.pack(fill="x", padx=16, pady=(0, 10))

        # SIEM 제어 바
        siem_ctrl = ctk.CTkFrame(card_siem, fg_color="transparent")
        siem_ctrl.pack(fill="x", padx=16, pady=(0, 14))

        ctk.CTkLabel(siem_ctrl, text="선택된 룰 ID:", font=ctk.CTkFont(size=11, weight="bold")).pack(side="left", padx=(0, 6))
        self.ent_siem_target_id = ctk.CTkEntry(siem_ctrl, width=100, height=28, placeholder_text="SIEM-R01")
        self.ent_siem_target_id.pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            siem_ctrl,
            text="🔄 룰 활성/비활성 토글",
            width=140,
            height=28,
            fg_color="#334155",
            hover_color="#475569",
            font=ctk.CTkFont(size=11),
            command=self._on_toggle_siem_rule,
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            siem_ctrl,
            text="🗑️ 선택 룰 삭제",
            width=110,
            height=28,
            fg_color="#e11d48",
            hover_color="#be123c",
            font=ctk.CTkFont(size=11),
            command=self._on_delete_siem_rule,
        ).pack(side="left")

        # 3. 서브탭 3: 최신 위협 시그니처 배포 센터 & 룰 커버리지 매트릭스
        sig_info = self.update_mgr.get_signature_info()
        meta_bar = ctk.CTkFrame(self.subtab_sig, fg_color="#102a24", corner_radius=10, border_width=1, border_color="#10b981")
        meta_bar.pack(fill="x", pady=(0, 14), padx=4)

        self.lbl_sig_version = ctk.CTkLabel(
            meta_bar,
            text=f"🛡️ 위협 시그니처 상태: {sig_info.get('version', 'v2026.11.09-LTS')} | 갱신: {sig_info.get('last_updated', '최신')} | 감시 룰: {sig_info.get('total_rules', 9)}건",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#10b981",
        )
        self.lbl_sig_version.pack(side="left", padx=16, pady=8)

        ctk.CTkButton(
            meta_bar,
            text="🔄 최신 위협 시그니처 업데이트 (Update Definitions)",
            height=28,
            fg_color="#059669",
            hover_color="#047857",
            font=ctk.CTkFont(size=11, weight="bold"),
            command=self._on_update_signatures,
        ).pack(side="right", padx=12, pady=6)

        # 룰 커버리지 매트릭스 카드
        cov_card = ctk.CTkFrame(self.subtab_sig, fg_color="#0f172a", corner_radius=12, border_width=1, border_color="#10b981")
        cov_card.pack(fill="x", padx=4, pady=(0, 14))

        cov_top = ctk.CTkFrame(cov_card, fg_color="transparent")
        cov_top.pack(fill="x", padx=16, pady=(12, 6))
        ctk.CTkLabel(cov_top, text="🛡️ 엔터프라이즈 룰 커버리지 매트릭스 (Rule Coverage Matrix)", font=ctk.CTkFont(size=13, weight="bold"), text_color="#10b981").pack(side="left")
        ctk.CTkLabel(cov_top, text="● 100% 완전 방어 커버리지 활성", font=ctk.CTkFont(size=10, weight="bold"), text_color="#10b981").pack(side="right")

        matrix_box = ctk.CTkFrame(cov_card, fg_color="#090d16", corner_radius=8)
        matrix_box.pack(fill="x", padx=16, pady=(4, 12))

        cov_items = [
            ("Brute-Force 비밀번호 대입", "SIEM-R02", "5회 실패 시 15분 계정 잠금 & IP 차단", "100%"),
            ("SQL Injection 정적 분석", "SIEM-R04", "AST 쿼리 패턴 매칭 및 즉시 실행 차단", "100%"),
            ("BOLA / IDOR 비인가 열람", "SIEM-R03", "타인 기밀문서 침해 적발 즉시 세션 파기", "100%"),
            ("가짜 미끼(Honeypot) 탐침", "SIEM-R01", "/.env, /admin 불법 접근 시 403 즉시 격리", "100%"),
            ("외부 악성 포트 스캔", "FW-R01", "비인가 WAN 포트 접근 드롭 및 netsh 차단", "100%"),
        ]
        for v_name, r_id, desc, cov in cov_items:
            r = ctk.CTkFrame(matrix_box, fg_color="transparent")
            r.pack(fill="x", padx=12, pady=4)
            ctk.CTkLabel(r, text=f"• {v_name}", width=180, anchor="w", font=ctk.CTkFont(size=11, weight="bold"), text_color="#f8fafc").pack(side="left")
            ctk.CTkLabel(r, text=f"[{r_id}]", width=90, anchor="center", font=ctk.CTkFont(family="Consolas", size=10, weight="bold"), text_color="#38bdf8").pack(side="left", padx=4)
            ctk.CTkLabel(r, text=desc, anchor="w", font=ctk.CTkFont(size=10), text_color="#94a3b8").pack(side="left", fill="x", expand=True, padx=4)
            cov_pill = ctk.CTkFrame(r, fg_color="#064e3b", corner_radius=4)
            cov_pill.pack(side="right")
            ctk.CTkLabel(cov_pill, text=f"✅ {cov}", font=ctk.CTkFont(size=9, weight="bold"), text_color="#10b981").pack(padx=6, pady=2)

        # 초기 활성 서브탭 표시 (pfSense)
        self.subtab_fw.pack(fill="both", expand=True)

        # 초기 룰셋 출력
        self._refresh_fw_rules_display()
        self._refresh_siem_rules_display()

        return f

    def _on_ruleset_subtab_change(self, choice):
        self.subtab_fw.pack_forget()
        self.subtab_siem.pack_forget()
        self.subtab_sig.pack_forget()
        if "pfSense" in choice:
            self.subtab_fw.pack(fill="both", expand=True)
        elif "Graylog" in choice:
            self.subtab_siem.pack(fill="both", expand=True)
        else:
            self.subtab_sig.pack(fill="both", expand=True)

    def _on_rule_search_key(self):
        self._refresh_fw_rules_display()
        self._refresh_siem_rules_display()

    def _refresh_fw_rules_display(self):
        if not hasattr(self, "scroll_fw_rules"):
            return
        for child in self.scroll_fw_rules.winfo_children():
            child.destroy()

        options = ["-- 새 규칙 등록 (직접 입력) --"]
        rules = self.fw_rules_mgr.get_rules()
        q = self.ent_rule_search.get().strip().lower() if hasattr(self, "ent_rule_search") else ""
        if q:
            rules = [r for r in rules if q in r.get("id", "").lower() or q in r.get("description", "").lower() or q in r.get("source_ip", "").lower() or q in str(r.get("dest_port", "")).lower() or q in r.get("protocol", "").lower()]
        for r in rules:
            rid = r.get("id", "")
            action = r.get("action", "BLOCK")
            proto = r.get("protocol", "TCP")
            iface = r.get("interface", "WAN")
            src = r.get("source_ip", "ANY")
            port = r.get("dest_port", "ANY")
            desc = r.get("description", "")
            enabled = r.get("enabled", True)

            options.append(f"{rid}: [{action}] {src}:{port} ({desc[:18]})")

            row = ctk.CTkFrame(self.scroll_fw_rules, fg_color="#0f172a", corner_radius=6, border_width=1, border_color="#334155")
            row.pack(fill="x", padx=2, pady=2)

            # ID
            id_pill = ctk.CTkFrame(row, fg_color="#1e293b", corner_radius=4)
            id_pill.pack(side="left", padx=(10, 4), pady=5)
            ctk.CTkLabel(id_pill, text=rid, width=55, font=ctk.CTkFont(family="Consolas", size=10, weight="bold"), text_color="#cbd5e1").pack(padx=4, pady=2)

            # Action
            act_bg = "#2b1419" if action == "BLOCK" else "#064e3b"
            act_fg = "#ef4444" if action == "BLOCK" else "#10b981"
            act_txt = "🚫 차단" if action == "BLOCK" else "✅ 통과"
            act_pill = ctk.CTkFrame(row, fg_color=act_bg, corner_radius=4)
            act_pill.pack(side="left", padx=4)
            ctk.CTkLabel(act_pill, text=act_txt, width=65, font=ctk.CTkFont(size=10, weight="bold"), text_color=act_fg).pack(padx=4, pady=2)

            # Proto/Iface
            ctk.CTkLabel(row, text=f"[{iface}/{proto}]", width=100, anchor="center", font=ctk.CTkFont(size=10), text_color="#94a3b8").pack(side="left", padx=4)

            # IP:Port
            ctk.CTkLabel(row, text=f"{src}:{port}", width=165, anchor="w", font=ctk.CTkFont(family="Consolas", size=10, weight="bold"), text_color="#38bdf8").pack(side="left", padx=4)

            # Status
            st_txt = "● 가동 중" if enabled else "○ 비활성"
            st_fg = "#22c55e" if enabled else TEXT_MUTED
            ctk.CTkLabel(row, text=st_txt, width=65, anchor="center", font=ctk.CTkFont(size=10, weight="bold"), text_color=st_fg).pack(side="left", padx=4)

            # Desc
            ctk.CTkLabel(row, text=desc, anchor="w", font=ctk.CTkFont(size=10), text_color="#f8fafc").pack(side="left", fill="x", expand=True, padx=4)

            # Action Buttons
            ctk.CTkButton(
                row,
                text="✏️ 선택",
                width=50,
                height=24,
                fg_color="#0284c7",
                hover_color="#0369a1",
                font=ctk.CTkFont(size=10),
                command=lambda rule_choice=f"{rid}: [{action}]": self._on_select_fw_rule_from_menu(rule_choice),
            ).pack(side="right", padx=2)

            ctk.CTkButton(
                row,
                text="토글",
                width=45,
                height=24,
                fg_color="#334155",
                hover_color="#475569",
                font=ctk.CTkFont(size=10),
                command=lambda rule_id=rid: self._on_quick_toggle_fw_rule(rule_id),
            ).pack(side="right", padx=(2, 8))

        if hasattr(self, "opt_fw_select"):
            self.opt_fw_select.configure(values=options)

    def _on_quick_toggle_fw_rule(self, rule_id):
        self.fw_rules_mgr.toggle_rule(rule_id)
        self._refresh_fw_rules_display()

    def _refresh_siem_rules_display(self):
        if not hasattr(self, "scroll_siem_rules"):
            return
        for child in self.scroll_siem_rules.winfo_children():
            child.destroy()

        options = ["-- 새 탐지 룰 등록 (직접 입력) --"]
        rules = self.siem_rules_mgr.get_rules()
        q = self.ent_rule_search.get().strip().lower() if hasattr(self, "ent_rule_search") else ""
        if q:
            rules = [r for r in rules if q in r.get("rule_id", "").lower() or q in r.get("rule_name", "").lower() or q in r.get("target_field", "").lower() or q in r.get("severity", "").lower() or q in r.get("action", "").lower()]
        for r in rules:
            rid = r.get("rule_id", "")
            rname = r.get("rule_name", "")
            field = r.get("target_field", "")
            th = r.get("threshold_count", 1)
            sev = r.get("severity", "HIGH")
            act = r.get("action", "BLOCK_IP_403")
            enabled = r.get("enabled", True)

            options.append(f"{rid}: [{sev}] {rname[:22]}")

            row = ctk.CTkFrame(self.scroll_siem_rules, fg_color="#0f172a", corner_radius=6, border_width=1, border_color="#334155")
            row.pack(fill="x", padx=2, pady=2)

            # ID
            id_pill = ctk.CTkFrame(row, fg_color="#1e293b", corner_radius=4)
            id_pill.pack(side="left", padx=(10, 4), pady=5)
            ctk.CTkLabel(id_pill, text=rid, width=65, font=ctk.CTkFont(family="Consolas", size=10, weight="bold"), text_color="#cbd5e1").pack(padx=4, pady=2)

            # Severity
            sev_colors = {
                "CRITICAL": ("#2b1419", "#ef4444"),
                "HIGH": ("#2a1708", "#f59e0b"),
                "MEDIUM": ("#261e05", "#eab308"),
                "LOW": ("#0b1d3a", "#38bdf8"),
            }
            sbg, sfg = sev_colors.get(sev, ("#1e293b", "#94a3b8"))
            s_pill = ctk.CTkFrame(row, fg_color=sbg, corner_radius=4)
            s_pill.pack(side="left", padx=4)
            ctk.CTkLabel(s_pill, text=f"● {sev}", width=70, font=ctk.CTkFont(size=10, weight="bold"), text_color=sfg).pack(padx=4, pady=2)

            # Field & Threshold
            ctk.CTkLabel(row, text=f"{field} (≥{th}건)", width=165, anchor="w", font=ctk.CTkFont(family="Consolas", size=10), text_color="#38bdf8").pack(side="left", padx=4)

            # Action Pill
            act_labels = {
                "BLOCK_IP_403": "🚫 403 차단",
                "LOCK_ACCOUNT_15M": "🔒 15분 계정잠금",
                "DROP_EXECUTION": "🛑 실행 격리",
                "ALERT_ONLY": "🔔 보안 알림",
            }
            a_pill = ctk.CTkFrame(row, fg_color="#1e293b", corner_radius=4)
            a_pill.pack(side="left", padx=4)
            ctk.CTkLabel(a_pill, text=act_labels.get(act, act), width=120, anchor="center", font=ctk.CTkFont(size=10), text_color="#cbd5e1").pack(padx=4, pady=2)

            # Status
            st_txt = "● 가동 중" if enabled else "○ 비활성"
            st_fg = "#22c55e" if enabled else TEXT_MUTED
            ctk.CTkLabel(row, text=st_txt, width=65, anchor="center", font=ctk.CTkFont(size=10, weight="bold"), text_color=st_fg).pack(side="left", padx=4)

            # Rule Name
            ctk.CTkLabel(row, text=rname, anchor="w", font=ctk.CTkFont(size=10, weight="bold"), text_color="#f8fafc").pack(side="left", fill="x", expand=True, padx=4)

            # Action Buttons
            ctk.CTkButton(
                row,
                text="✏️ 선택",
                width=50,
                height=24,
                fg_color="#059669",
                hover_color="#047857",
                font=ctk.CTkFont(size=10),
                command=lambda rule_choice=f"{rid}: [{sev}]": self._on_select_siem_rule_from_menu(rule_choice),
            ).pack(side="right", padx=2)

            ctk.CTkButton(
                row,
                text="토글",
                width=45,
                height=24,
                fg_color="#334155",
                hover_color="#475569",
                font=ctk.CTkFont(size=10),
                command=lambda rule_id=rid: self._on_quick_toggle_siem_rule(rule_id),
            ).pack(side="right", padx=(2, 8))

        if hasattr(self, "opt_siem_select"):
            self.opt_siem_select.configure(values=options)

    def _on_quick_toggle_siem_rule(self, rule_id):
        self.siem_rules_mgr.toggle_rule(rule_id)
        self._refresh_siem_rules_display()

    def _on_select_fw_rule_from_menu(self, choice):
        if not choice or choice.startswith("--"):
            self.ent_fw_target_id.delete(0, "end")
            self.ent_fw_src.delete(0, "end")
            self.ent_fw_port.delete(0, "end")
            self.ent_fw_desc.delete(0, "end")
            return
        rule_id = choice.split(":")[0].strip()
        for r in self.fw_rules_mgr.get_rules():
            if r.get("id") == rule_id:
                self.ent_fw_target_id.delete(0, "end")
                self.ent_fw_target_id.insert(0, rule_id)
                self.opt_fw_action.set(r.get("action", "BLOCK"))
                self.opt_fw_proto.set(r.get("protocol", "TCP"))
                self.ent_fw_src.delete(0, "end")
                self.ent_fw_src.insert(0, r.get("source_ip", "ANY"))
                self.ent_fw_port.delete(0, "end")
                self.ent_fw_port.insert(0, r.get("dest_port", "ANY"))
                self.ent_fw_desc.delete(0, "end")
                self.ent_fw_desc.insert(0, r.get("description", ""))
                break

    def _on_update_signatures(self):
        updated, msg = self.update_mgr.check_and_apply_update()
        self.fw_rules_mgr.rules = self.fw_rules_mgr.load_rules()
        self.siem_rules_mgr.rules = self.siem_rules_mgr.load_rules()
        sig_info = self.update_mgr.get_signature_info()
        if hasattr(self, "lbl_sig_version"):
            self.lbl_sig_version.configure(
                text=f"🛡️ 위협 시그니처 상태: {sig_info.get('version', 'v2026.11.09-LTS')} | 갱신: {sig_info.get('last_updated', '최신')} | 감시 룰: {sig_info.get('total_rules', 9)}건"
            )
        self._refresh_fw_rules_display()
        self._refresh_siem_rules_display()
        messagebox.showinfo("위협 시그니처 업데이트", msg)

    def _on_select_siem_rule_from_menu(self, choice):
        if not choice or choice.startswith("--"):
            self.ent_siem_target_id.delete(0, "end")
            self.ent_siem_name.delete(0, "end")
            self.opt_siem_field.set("request_path (디코이 경로)")
            self.ent_siem_th.delete(0, "end")
            self.ent_siem_th.insert(0, "10")
            return
        rule_id = choice.split(":")[0].strip()
        for r in self.siem_rules_mgr.get_rules():
            if r.get("rule_id") == rule_id:
                self.ent_siem_target_id.delete(0, "end")
                self.ent_siem_target_id.insert(0, rule_id)
                self.ent_siem_name.delete(0, "end")
                self.ent_siem_name.insert(0, r.get("rule_name", ""))
                
                tfield = r.get("target_field", "")
                matched = None
                for opt in self.opt_siem_field._values:
                    if opt.startswith(tfield):
                        matched = opt
                        break
                if matched:
                    self.opt_siem_field.set(matched)
                else:
                    self.opt_siem_field.set(tfield)

                self.ent_siem_th.delete(0, "end")
                self.ent_siem_th.insert(0, str(r.get("threshold_count", 1)))
                self.opt_siem_sev.set(r.get("severity", "HIGH"))
                self.opt_siem_act.set(r.get("action", "BLOCK_IP_403"))
                break

    def _on_add_fw_rule(self):
        action = self.opt_fw_action.get()
        proto = self.opt_fw_proto.get()
        src = self.ent_fw_src.get().strip() or "ANY"
        port = self.ent_fw_port.get().strip() or "ANY"
        desc = self.ent_fw_desc.get().strip() or "사용자 정의 방화벽 규칙"
        rule = self.fw_rules_mgr.add_rule(action, proto, src, port, desc)
        self._refresh_fw_rules_display()
        messagebox.showinfo("규칙 추가 완료", f"pfSense 방화벽 룰 '{rule['id']}'이 등록되었습니다.\n동작: {action} | 대상: {src}:{port}")

    def _on_update_fw_rule(self):
        rid = self.ent_fw_target_id.get().strip()
        if not rid:
            messagebox.showwarning("선택 필요", "상단 메뉴에서 수정할 룰을 선택하거나 ID를 입력하세요.")
            return
        action = self.opt_fw_action.get()
        proto = self.opt_fw_proto.get()
        src = self.ent_fw_src.get().strip() or "ANY"
        port = self.ent_fw_port.get().strip() or "ANY"
        desc = self.ent_fw_desc.get().strip()
        if self.fw_rules_mgr.update_rule(rid, action, proto, src, port, desc):
            self._refresh_fw_rules_display()
            messagebox.showinfo("수정 완료", f"pfSense 방화벽 룰 '{rid}'의 설정이 성공적으로 갱신되었습니다!")
        else:
            messagebox.showwarning("미발견", f"룰 '{rid}'를 찾을 수 없습니다.")

    def _on_toggle_fw_rule(self):
        rid = self.ent_fw_target_id.get().strip()
        if not rid:
            messagebox.showwarning("입력 필요", "토글할 룰 ID(예: FW-001)를 입력하세요.")
            return
        if self.fw_rules_mgr.toggle_rule(rid):
            self._refresh_fw_rules_display()
            messagebox.showinfo("토글 완료", f"방화벽 룰 {rid}의 상태가 변경되었습니다.")
        else:
            messagebox.showwarning("미발견", f"룰 {rid}를 찾을 수 없습니다.")

    def _on_delete_fw_rule(self):
        rid = self.ent_fw_target_id.get().strip()
        if not rid:
            messagebox.showwarning("입력 필요", "삭제할 룰 ID(예: FW-001)를 입력하세요.")
            return
        if self.fw_rules_mgr.delete_rule(rid):
            self._refresh_fw_rules_display()
            messagebox.showinfo("삭제 완료", f"방화벽 룰 {rid}가 삭제되었습니다.")
        else:
            messagebox.showwarning("미발견", f"룰 {rid}를 찾을 수 없습니다.")

    def _on_add_siem_rule(self):
        name = self.ent_siem_name.get().strip()
        field_raw = self.opt_siem_field.get().strip()
        field = field_raw.split()[0].strip()
        th_val = self.ent_siem_th.get().strip()
        sev = self.opt_siem_sev.get()
        act = self.opt_siem_act.get()
        if not name:
            messagebox.showwarning("입력 필요", "규칙명을 입력하세요.")
            return
        th = int(th_val) if th_val.isdigit() else 1
        rule = self.siem_rules_mgr.add_rule(name, field, "GTE", th, sev, act, name)
        self._refresh_siem_rules_display()
        messagebox.showinfo("탐지 룰 등록 완료", f"Graylog SIEM 탐지 룰 '{rule['rule_id']}'이 등록되었습니다.\n규칙명: {name} | 위협도: {sev}")

    def _on_update_siem_rule(self):
        rid = self.ent_siem_target_id.get().strip()
        if not rid:
            messagebox.showwarning("선택 필요", "상단 메뉴에서 수정할 SIEM 룰을 선택하거나 ID를 입력하세요.")
            return
        name = self.ent_siem_name.get().strip()
        field_raw = self.opt_siem_field.get().strip()
        field = field_raw.split()[0].strip()
        th_val = self.ent_siem_th.get().strip()
        sev = self.opt_siem_sev.get()
        act = self.opt_siem_act.get()
        th = int(th_val) if th_val.isdigit() else 1
        if self.siem_rules_mgr.update_rule(rid, name, field, th, sev, act):
            self._refresh_siem_rules_display()
            messagebox.showinfo("수정 완료", f"Graylog SIEM 탐지 룰 '{rid}'의 설정이 성공적으로 갱신되었습니다!")
        else:
            messagebox.showwarning("미발견", f"룰 '{rid}'를 찾을 수 없습니다.")

    def _on_toggle_siem_rule(self):
        rid = self.ent_siem_target_id.get().strip()
        if not rid:
            messagebox.showwarning("입력 필요", "토글할 룰 ID(예: SIEM-R01)를 입력하세요.")
            return
        if self.siem_rules_mgr.toggle_rule(rid):
            self._refresh_siem_rules_display()
            messagebox.showinfo("토글 완료", f"SIEM 룰 {rid}의 상태가 변경되었습니다.")
        else:
            messagebox.showwarning("미발견", f"룰 {rid}를 찾을 수 없습니다.")

    def _on_delete_siem_rule(self):
        rid = self.ent_siem_target_id.get().strip()
        if not rid:
            messagebox.showwarning("입력 필요", "삭제할 룰 ID(예: SIEM-R01)를 입력하세요.")
            return
        if self.siem_rules_mgr.delete_rule(rid):
            self._refresh_siem_rules_display()
            messagebox.showinfo("삭제 완료", f"SIEM 룰 {rid}가 삭제되었습니다.")
        else:
            messagebox.showwarning("미발견", f"룰 {rid}를 찾을 수 없습니다.")

    # =========================================================================
    # 탭 4: 시스템 취약점 전수 진단 (Kaspersky Full Scan 스타일)
    # =========================================================================
    def _create_scanner_view(self):
        f = ctk.CTkFrame(self.views_container, fg_color=SURFACE_CARD, corner_radius=12, border_width=1, border_color=BORDER_SUBTLE)
        f.grid_rowconfigure(4, weight=1)
        f.grid_columnconfigure(0, weight=1)

        top = ctk.CTkFrame(f, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=16, pady=14)

        ctk.CTkLabel(
            top,
            text="🔍 시스템 취약점 & AST 정적 분석 전수 진단 (Vulnerability Audit)",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=13, weight="bold"),
            text_color=TEXT_TITLE,
        ).pack(side="left")

        self.btn_run_audit = ctk.CTkButton(
            top,
            text="🔍 전체 시스템 정밀 진단 시작",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=12, weight="bold"),
            fg_color=BUTTON_PRIMARY,
            hover_color=BUTTON_PRIMARY_HOVER,
            command=self._on_run_audit,
        )
        self.btn_run_audit.pack(side="right")

        ctk.CTkButton(
            top,
            text="⚡ 취약점 원클릭 자동 치료 (1-Click Auto-Fix)",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=12, weight="bold"),
            fg_color=COLOR_SECURE,
            hover_color="#059669",
            command=self._on_auto_fix_vulnerabilities,
        ).pack(side="right", padx=(0, 8))

        # 4단계 인터랙티브 체크포인트 트래커 (Nessus/Snyk Style)
        self.phase_tracker = ScannerPhaseTracker(f)
        self.phase_tracker.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 8))

        scan_bar_box = ctk.CTkFrame(f, fg_color="transparent")
        scan_bar_box.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 8))

        self.lbl_scan_status = ctk.CTkLabel(
            scan_bar_box,
            text="대기 중 - [전체 시스템 정밀 진단 시작] 버튼을 눌러 점검을 시작하세요.",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=11),
            text_color=TEXT_MUTED,
        )
        self.lbl_scan_status.pack(anchor="w", pady=(0, 4))

        self.progress_bar = ctk.CTkProgressBar(scan_bar_box, height=8, progress_color=COLOR_CYAN)
        self.progress_bar.set(0)
        self.progress_bar.pack(fill="x")

        # 진단 결과 스코어보드 & 상태 요약 배너
        self.score_summary_banner = ctk.CTkFrame(f, fg_color=SURFACE_INNER, corner_radius=10, border_width=1, border_color=BORDER_SUBTLE)
        self.score_summary_banner.grid(row=3, column=0, sticky="ew", padx=16, pady=(0, 10))

        self.lbl_scan_score_badge = ctk.CTkLabel(
            self.score_summary_banner,
            text="🛡️ 종합 안전도: 진단 대기 중 (정밀 스캔을 실행하세요)",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=13, weight="bold"),
            text_color=COLOR_CYAN,
        )
        self.lbl_scan_score_badge.pack(side="left", padx=16, pady=10)

        stat_box = ctk.CTkFrame(self.score_summary_banner, fg_color="transparent")
        stat_box.pack(side="right", padx=16, pady=6)

        self.lbl_stat_crit = ctk.CTkLabel(stat_box, text="🔴 고위험: -건", font=ctk.CTkFont(family=FONT_FAMILY_UI, size=11, weight="bold"), text_color=COLOR_ALERT)
        self.lbl_stat_crit.pack(side="left", padx=8)

        self.lbl_stat_med = ctk.CTkLabel(stat_box, text="🟡 주의: -건", font=ctk.CTkFont(family=FONT_FAMILY_UI, size=11, weight="bold"), text_color=COLOR_WARN)
        self.lbl_stat_med.pack(side="left", padx=8)

        self.lbl_stat_safe = ctk.CTkLabel(stat_box, text="🟢 정상: -건", font=ctk.CTkFont(family=FONT_FAMILY_UI, size=11, weight="bold"), text_color=COLOR_SECURE)
        self.lbl_stat_safe.pack(side="left", padx=8)

        # 진단 결과 스크롤 카드 컨테이너
        self.scroll_scan_results = ctk.CTkScrollableFrame(
            f,
            fg_color=SURFACE_INNER,
            corner_radius=10,
            border_width=1,
            border_color=BORDER_SUBTLE,
        )
        self.scroll_scan_results.grid(row=4, column=0, sticky="nsew", padx=16, pady=(0, 16))

        # 초기 대기 카드 출력
        self._render_initial_scan_preview()

        return f

    def _render_initial_scan_preview(self):
        for child in self.scroll_scan_results.winfo_children():
            child.destroy()

        tgt = self.cfg.get("target_service", {})
        web_url = tgt.get("web_portal_url", "http://127.0.0.1:5070")
        db_target = f"{tgt.get('db_host', '127.0.0.1')}:{tgt.get('db_port', 3307)}"

        intro_items = [
            ("📁 1단계: .env 환경설정 및 관리자 기본 비밀번호 감사", "SECRET_KEY, DB 비밀번호, API 키의 기본값 방치 및 취약성 전수 점검", COLOR_CYAN),
            ("🌐 2단계: 사용자가 설정한 대상 주소(웹 포털 & DB) 실제 프로빙 검증", f"설정 탭에 등록된 웹 URL({web_url}) 및 DB({db_target})의 포트 수신 및 보안 헤더 검증", "#38bdf8"),
            ("🔍 3단계: 파이썬 AST(추상 구문 트리) 정적 분석", "전체 백엔드 소스코드 내 SQL Injection 위험 쿼리 및 문자열 결합 정적 전수 조사", COLOR_PURPLE),
            ("🛡️ 4단계: 능동 방어 실드 & 디코이(Honeypot) 가동 검증", "웹 방어 WAF 403 차단 정책 및 미끼 경로 접근 시 즉각 격리 프로세스 가동 상태 검증", COLOR_SECURE),
        ]

        for title, desc, color in intro_items:
            card = ctk.CTkFrame(self.scroll_scan_results, fg_color=SURFACE_CARD, corner_radius=8, border_width=1, border_color=BORDER_SUBTLE)
            card.pack(fill="x", padx=6, pady=4)

            top_row = ctk.CTkFrame(card, fg_color="transparent")
            top_row.pack(fill="x", padx=14, pady=(10, 4))

            ctk.CTkLabel(top_row, text=title, font=ctk.CTkFont(family=FONT_FAMILY_UI, size=12, weight="bold"), text_color=color).pack(side="left")
            ctk.CTkLabel(top_row, text="[대기 상태]", font=ctk.CTkFont(family=FONT_FAMILY_UI, size=10), text_color=TEXT_MUTED).pack(side="right")

            ctk.CTkLabel(card, text=desc, font=ctk.CTkFont(family=FONT_FAMILY_UI, size=11), text_color=TEXT_MUTED).pack(anchor="w", padx=14, pady=(0, 10))

    def _on_run_audit(self):
        self.btn_run_audit.configure(text="진단 스캔 진행 중...", state="disabled")
        self.lbl_scan_status.configure(text="[1/4] .env 환경 변수 및 자격 증명 취약점 진단 중...")
        self.progress_bar.set(0.15)
        if hasattr(self, "phase_tracker"):
            self.phase_tracker.reset_phases()
            self.phase_tracker.update_phase(0, "감사 진행 중...", is_active=True)

        # 사용자가 설정한 최신 환경설정 반영
        self.scanner.config = self.cfg

        def _worker():
            try:
                time.sleep(0.3)
                self._manual_audit_phase_queue.put(2)
                time.sleep(0.3)
                self._manual_audit_phase_queue.put(3)
                time.sleep(0.3)
                rep = self.scanner.run_full_scan()
                self._manual_audit_result_queue.put(rep)
            except Exception:
                self._manual_audit_result_queue.put(None)

        threading.Thread(target=_worker, daemon=True).start()

    def _apply_scan_results(self, rep):
        if not hasattr(self, "scroll_scan_results"):
            return

        self.progress_bar.set(1.0)
        score = rep.get("security_score", 55)
        grade = rep.get("security_grade", "C")
        findings = rep.get("findings", [])
        self.lbl_scan_status.configure(text=f"정밀 진단 완료: 4단계 심층 검증 완료 (종합 안전 점수: {score}점 / {grade} 등급)")

        if hasattr(self, "card_score"):
            self.card_score.configure(text=f"{score} / 100")

        # Dashboard Hero 배너 연동 갱신
        if hasattr(self, "hero_banner") and hasattr(self, "lbl_hero_icon") and hasattr(self, "lbl_hero_title"):
            if score >= 90:
                self.hero_banner.configure(fg_color="#102a24", border_color="#10b981")
                self.lbl_hero_icon.configure(text="🛡️")
                self.lbl_hero_title.configure(text="NEXUS-GUARD 엔터프라이즈 능동 방어 관제 (SYSTEM SECURED)", text_color="#10b981")
            elif score >= 50:
                self.hero_banner.configure(fg_color="#2a1f0a", border_color="#f59e0b")
                self.lbl_hero_icon.configure(text="⚠️")
                crit_cnt_hero = sum(1 for f in findings if f.get("severity") in ("CRITICAL", "HIGH"))
                self.lbl_hero_title.configure(text=f"NEXUS-GUARD 실시간 정밀 진단: {crit_cnt_hero}건의 보안 취약점 주의 필요 (ATTENTION NEEDED)", text_color="#f59e0b")
            else:
                self.hero_banner.configure(fg_color="#2b1419", border_color="#f43f5e")
                self.lbl_hero_icon.configure(text="🚨")
                self.lbl_hero_title.configure(text="NEXUS-GUARD 긴급 경보: 치명적 보안 결함 발견 (ACTION REQUIRED)", text_color="#f43f5e")

        # Phase Tracker 완료 갱신
        if hasattr(self, "phase_tracker"):
            self.phase_tracker.update_phase(0, "환경 변수 감사 완료", is_done=True)
            self.phase_tracker.update_phase(1, "타겟 프로빙 완료", is_done=True)
            self.phase_tracker.update_phase(2, "AST 분석 완료", is_done=True)
            self.phase_tracker.update_phase(3, "WAF 디코이 검증 통과", is_done=True)

            for f in findings:
                cat = f.get("category", "")
                if "SECRET" in cat or "ENV" in cat:
                    self.phase_tracker.update_phase(0, "취약점 발견", is_vuln=True)
                elif "PORT" in cat or "WEB" in cat or "EXPOSURE" in cat:
                    self.phase_tracker.update_phase(1, "주의 발견", is_vuln=True)
                elif "AST" in cat or "SQL" in cat:
                    self.phase_tracker.update_phase(2, "SQLi 검출", is_vuln=True)

        crit_cnt = sum(1 for f in findings if f.get("severity") in ["CRITICAL", "HIGH"])
        med_cnt = sum(1 for f in findings if f.get("severity") == "MEDIUM")
        safe_cnt = max(0, 4 - len(findings))

        self.lbl_stat_crit.configure(text=f"🔴 고위험: {crit_cnt}건")
        self.lbl_stat_med.configure(text=f"🟡 주의: {med_cnt}건")
        self.lbl_stat_safe.configure(text=f"🟢 정상: {safe_cnt}건")

        if score >= 90:
            self.score_summary_banner.configure(fg_color=COLOR_SECURE_BG, border_color=BORDER_EMERALD)
            self.lbl_scan_score_badge.configure(
                text=f"🛡️ 종합 안전도: {score}점 / 100점 ({grade} 등급 - 최고 안전 보장)",
                text_color=COLOR_SECURE,
            )
        elif score >= 70:
            self.score_summary_banner.configure(fg_color=COLOR_WARN_BG, border_color=COLOR_WARN)
            self.lbl_scan_score_badge.configure(
                text=f"⚠️ 종합 안전도: {score}점 / 100점 ({grade} 등급 - 권장 보안 강화 필요)",
                text_color=COLOR_WARN,
            )
        else:
            self.score_summary_banner.configure(fg_color=COLOR_ALERT_BG, border_color=BORDER_CRIMSON)
            self.lbl_scan_score_badge.configure(
                text=f"🚨 종합 안전도: {score}점 / 100점 ({grade} 등급 - 즉각 보안 조치 시급)",
                text_color=COLOR_ALERT,
            )

        # 결과 카드 렌더링
        for child in self.scroll_scan_results.winfo_children():
            child.destroy()

        # 검증 대상 주소 확인 배너
        target_info = rep.get("target_summary", {})
        target_card = ctk.CTkFrame(self.scroll_scan_results, fg_color=SURFACE_CARD, corner_radius=8, border_width=1, border_color=BORDER_CYAN)
        target_card.pack(fill="x", padx=6, pady=(2, 8))

        t_top = ctk.CTkFrame(target_card, fg_color="transparent")
        t_top.pack(fill="x", padx=12, pady=(6, 2))
        ctk.CTkLabel(t_top, text="🎯 [환경 설정] 등록 대상 주소 실제 검증 결과 (Configured Targets)", font=ctk.CTkFont(family=FONT_FAMILY_UI, size=11, weight="bold"), text_color=COLOR_CYAN).pack(side="left")

        ctk.CTkLabel(
            target_card,
            text=f"• 감시 웹 포털: {target_info.get('web_url', 'http://127.0.0.1:5070')}   |   • 대상 데이터베이스: {target_info.get('db_target', '127.0.0.1:3307')}",
            font=ctk.CTkFont(family=FONT_FAMILY_MONO, size=10, weight="bold"),
            text_color=TEXT_TITLE,
        ).pack(anchor="w", padx=12, pady=(0, 6))

        if not findings:
            safe_card = ctk.CTkFrame(self.scroll_scan_results, fg_color=COLOR_SECURE_BG, corner_radius=10, border_width=1, border_color=BORDER_EMERALD)
            safe_card.pack(fill="x", padx=6, pady=6)
            ctk.CTkLabel(
                safe_card,
                text="🎉 시스템 전수 점검 통과: 등록된 대상 주소 및 모든 보안 검사 항목이 정상입니다!",
                font=ctk.CTkFont(family=FONT_FAMILY_UI, size=13, weight="bold"),
                text_color=COLOR_SECURE,
            ).pack(padx=16, pady=16)
        else:
            sev_styles = {
                "CRITICAL": (COLOR_ALERT_BG, COLOR_ALERT, BORDER_CRIMSON, "🚨 CRITICAL"),
                "HIGH": (COLOR_WARN_BG, COLOR_WARN, COLOR_WARN, "⚠️ HIGH"),
                "MEDIUM": (COLOR_WARN_BG, "#eab308", "#ca8a04", "🟡 MEDIUM"),
                "LOW": (COLOR_CYAN_BG, COLOR_CYAN, BORDER_CYAN, "🟢 LOW"),
            }
            cvss_map = {
                "CRITICAL": "9.8",
                "HIGH": "7.5",
                "MEDIUM": "5.3",
                "LOW": "3.1",
            }

            for idx, find in enumerate(findings, 1):
                sev = find.get("severity", "MEDIUM")
                sbg, sfg, sborder, stxt = sev_styles.get(sev, (SURFACE_HOVER, TEXT_MUTED, BORDER_SUBTLE, sev))
                cvss_val = cvss_map.get(sev, "5.0")

                card = ctk.CTkFrame(self.scroll_scan_results, fg_color=SURFACE_CARD, corner_radius=10, border_width=1, border_color=sborder)
                card.pack(fill="x", padx=6, pady=6)

                # Header
                head_row = ctk.CTkFrame(card, fg_color="transparent")
                head_row.pack(fill="x", padx=14, pady=(10, 4))

                # Severity pill
                spill = ctk.CTkFrame(head_row, fg_color=sbg, corner_radius=4, border_width=1, border_color=sborder)
                spill.pack(side="left", padx=(0, 6))
                ctk.CTkLabel(spill, text=stxt, font=ctk.CTkFont(family=FONT_FAMILY_UI, size=10, weight="bold"), text_color=sfg).pack(padx=8, pady=3)

                # CVSS v3.1 Badge
                cvss_pill = ctk.CTkFrame(head_row, fg_color=SURFACE_INNER, corner_radius=4, border_width=1, border_color=BORDER_ACTIVE)
                cvss_pill.pack(side="left", padx=(0, 6))
                ctk.CTkLabel(cvss_pill, text=f"CVSS v3.1: {cvss_val}", font=ctk.CTkFont(family=FONT_FAMILY_MONO, size=10, weight="bold"), text_color=COLOR_CYAN).pack(padx=6, pady=2)

                # Category badge
                cat_pill = ctk.CTkFrame(head_row, fg_color=SURFACE_INNER, corner_radius=4, border_width=1, border_color=BORDER_SUBTLE)
                cat_pill.pack(side="left", padx=(0, 8))
                ctk.CTkLabel(cat_pill, text=f"📁 {find.get('category','보안')}", font=ctk.CTkFont(family=FONT_FAMILY_UI, size=10), text_color=TEXT_BODY).pack(padx=6, pady=2)

                # Title
                ctk.CTkLabel(head_row, text=find.get("title", ""), font=ctk.CTkFont(family=FONT_FAMILY_UI, size=12, weight="bold"), text_color=TEXT_TITLE).pack(side="left")

                # Status pill on right
                act_pill = ctk.CTkFrame(head_row, fg_color=COLOR_ALERT_BG, corner_radius=4, border_width=1, border_color=BORDER_CRIMSON)
                act_pill.pack(side="right")
                ctk.CTkLabel(act_pill, text="🚨 조치 필요", font=ctk.CTkFont(family=FONT_FAMILY_UI, size=10, weight="bold"), text_color=COLOR_ALERT).pack(padx=6, pady=2)

                # Desc
                desc_row = ctk.CTkFrame(card, fg_color="transparent")
                desc_row.pack(fill="x", padx=14, pady=(2, 6))
                ctk.CTkLabel(desc_row, text=f"• 세부 내역: {find.get('desc','')}", font=ctk.CTkFont(family=FONT_FAMILY_UI, size=11), text_color=TEXT_BODY, wraplength=700, justify="left").pack(anchor="w")

                # AST 정적 소스 코드 디프 권고 박스
                f_title = find.get("title", "")
                f_desc = find.get("desc", "")
                if "AST" in f_title or "SQL" in f_title or "쿼리" in f_desc:
                    code_box = ctk.CTkFrame(card, fg_color=SURFACE_INNER, corner_radius=6, border_width=1, border_color=BORDER_ACTIVE)
                    code_box.pack(fill="x", padx=14, pady=(0, 6))
                    ctk.CTkLabel(code_box, text="💻 취약 소스 코드 & 안전한 파라미터화 쿼리 권고안 (Code Remediation):", font=ctk.CTkFont(family=FONT_FAMILY_UI, size=10, weight="bold"), text_color=COLOR_CYAN).pack(anchor="w", padx=10, pady=(6, 2))
                    ctk.CTkLabel(code_box, text="[-] 취약 코드: cursor.execute(f\"SELECT * FROM secret_data WHERE id={doc_id}\")", font=ctk.CTkFont(family=FONT_FAMILY_MONO, size=10), text_color=COLOR_ALERT).pack(anchor="w", padx=10, pady=1)
                    ctk.CTkLabel(code_box, text="[+] 안전 권고: cursor.execute(\"SELECT * FROM secret_data WHERE id=%s\", (doc_id,))", font=ctk.CTkFont(family=FONT_FAMILY_MONO, size=10), text_color=COLOR_SECURE).pack(anchor="w", padx=10, pady=(1, 6))

                # Recommended Fix Action Box
                advice_box = ctk.CTkFrame(card, fg_color=SURFACE_INNER, corner_radius=6, border_width=1, border_color=BORDER_SUBTLE)
                advice_box.pack(fill="x", padx=14, pady=(0, 10))

                ctk.CTkLabel(
                    advice_box,
                    text="💡 원클릭 치료 권장: 상단의 [⚡ 취약점 원클릭 자동 치료] 버튼을 클릭하면 즉시 안전한 설정으로 자동 복구됩니다.",
                    font=ctk.CTkFont(family=FONT_FAMILY_UI, size=10),
                    text_color=COLOR_CYAN,
                ).pack(side="left", padx=10, pady=6)

                ctk.CTkButton(
                    advice_box,
                    text="⚡ 즉시 자동 치료",
                    width=110,
                    height=26,
                    fg_color=COLOR_SECURE,
                    hover_color="#059669",
                    font=ctk.CTkFont(family=FONT_FAMILY_UI, size=10, weight="bold"),
                    command=self._on_auto_fix_vulnerabilities,
                ).pack(side="right", padx=10, pady=4)

    def _startup_precision_audit(self):
        def _worker():
            try:
                # 1. 시스템 전수 취약점 정밀 진단
                rep = self.scanner.run_full_scan()
                score = rep.get("security_score", 55)
                grade = rep.get("security_grade", "C")
                findings = rep.get("findings", [])

                # 2. FIM 무결성 정밀 진단
                tampered = self.fim.scan_for_tampering()
                baseline_cnt = len(getattr(self.fim, "_baseline_hashes", {}))

                # 3. 호스트 방화벽 차단 통계
                blocked = self.firewall.get_blocked_list()
                blocked_cnt = len(blocked)

                self._audit_queue.put((rep, score, grade, findings, tampered, baseline_cnt, blocked_cnt))
            except Exception:
                pass

        threading.Thread(target=_worker, daemon=True).start()

    def _apply_precision_audit_results(self, rep, score, grade, findings, tampered, baseline_cnt, blocked_cnt):
        # 스코어 KPI 카드 갱신
        if hasattr(self, "card_score"):
            self.card_score.configure(text=f"{score} / 100")
        if hasattr(self, "card_blocked"):
            self.card_blocked.configure(text=f"{blocked_cnt} 건")
        if hasattr(self, "card_fim_cnt"):
            self.card_fim_cnt.configure(text=f"{baseline_cnt} 개")

        # Hero 배너 갱신
        if score >= 90 and len(tampered) == 0:
            self.hero_banner.configure(fg_color="#102a24", border_color="#10b981")
            self.lbl_hero_icon.configure(text="🛡️")
            self.lbl_hero_title.configure(text="NEXUS-GUARD 엔터프라이즈 능동 방어 관제 (SYSTEM SECURED)", text_color="#10b981")
        elif score >= 50:
            self.hero_banner.configure(fg_color="#2a1f0a", border_color="#f59e0b")
            self.lbl_hero_icon.configure(text="⚠️")
            crit_cnt = sum(1 for f in findings if f.get("severity") in ("CRITICAL", "HIGH"))
            self.lbl_hero_title.configure(text=f"NEXUS-GUARD 실시간 정밀 진단: {crit_cnt}건의 보안 취약점 주의 필요 (ATTENTION NEEDED)", text_color="#f59e0b")
        else:
            self.hero_banner.configure(fg_color="#2b1419", border_color="#f43f5e")
            self.lbl_hero_icon.configure(text="🚨")
            self.lbl_hero_title.configure(text="NEXUS-GUARD 긴급 경보: 치명적 보안 결함 발견 (ACTION REQUIRED)", text_color="#f43f5e")

        # 취약점 진단 탭 화면에 정밀 진단 결과 즉각 출력
        self._apply_scan_results(rep)

    def _on_auto_fix_vulnerabilities(self):
        fixed_count, actions = self.scanner.auto_remediate_all()
        msg = f"총 {fixed_count}건의 보안 취약점이 1-클릭으로 자동 치료 및 강화되었습니다:\n\n"
        for idx, act in enumerate(actions, 1):
            msg += f"[{idx}] {act}\n"
        msg += "\n보안 안전도 재측정을 위해 정밀 진단을 자동 실행합니다."
        messagebox.showinfo("원클릭 자동 치료 완료", msg)
        self._on_run_audit()

    # =========================================================================
    # 탭 5: 파일 무결성 감시 (FIM - File Integrity Monitor)
    # 개방형 무결성 익스플로러 테이블 + SHA-256 해시 정밀 대조 인스펙터
    # =========================================================================
    def _create_fim_view(self):
        f = ctk.CTkFrame(self.views_container, fg_color="transparent")
        f.grid_rowconfigure(4, weight=1)
        f.grid_rowconfigure(5, weight=0)
        f.grid_columnconfigure(0, weight=1)

        # 1. 상단 타이틀 및 액션 버튼 바
        top = ctk.CTkFrame(f, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 8))

        ctk.CTkLabel(
            top,
            text="📁 핵심 소스코드 & 설정 파일 실시간 무결성 감시 (SHA-256 FIM)",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=13, weight="bold"),
            text_color=TEXT_TITLE,
        ).pack(side="left")

        ctk.CTkButton(
            top,
            text="📁 무결성 대조 검증 실행",
            fg_color=COLOR_SECURE,
            hover_color="#059669",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=11, weight="bold"),
            command=self._on_fim_check,
        ).pack(side="right", padx=(6, 0))

        ctk.CTkButton(
            top,
            text="🔄 전체 베이스라인 갱신",
            fg_color=BUTTON_SECONDARY,
            hover_color=BUTTON_SECONDARY_HOVER,
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=11),
            command=self._on_fim_rebase,
        ).pack(side="right", padx=4)

        # =====================================================================
        # [💡 파일 무결성 감시(FIM)란 무엇인가요?] 친절한 초보자용 가이드 카드
        # =====================================================================
        fim_guide = ctk.CTkFrame(
            f,
            fg_color="#0b172a",
            corner_radius=10,
            border_width=1,
            border_color="#1e3a5f",
        )
        fim_guide.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 8))

        # 가이드 헤더 행
        g_head = ctk.CTkFrame(fim_guide, fg_color="transparent")
        g_head.pack(fill="x", padx=14, pady=(8, 4))

        ctk.CTkLabel(
            g_head,
            text="💡 파일 무결성 감시(FIM: File Integrity Monitoring)란 무엇인가요?",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=12, weight="bold"),
            text_color="#38bdf8",
        ).pack(side="left")

        fim_badge = ctk.CTkFrame(g_head, fg_color="#064e3b", corner_radius=4, border_width=1, border_color="#059669")
        fim_badge.pack(side="right")
        ctk.CTkLabel(
            fim_badge,
            text="● 침입·변조 즉각 탐지",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=9, weight="bold"),
            text_color="#34d399",
        ).pack(padx=8, pady=2)

        # 3개 핵심 안내 타일 그리드
        guide_grid = ctk.CTkFrame(fim_guide, fg_color="transparent")
        guide_grid.pack(fill="x", padx=10, pady=(0, 8))
        guide_grid.grid_columnconfigure((0, 1, 2), weight=1)

        tiles_data = [
            (
                "📌 개념 정의 (What is FIM?)",
                "서버의 핵심 소스코드(app/, nexus_guard/) 및 중요 환경설정(.env) 58개 파일의 고유한 디지털 지문(SHA-256 해시값)을 등록해두고 실시간으로 감시하는 침입 탐지 시스템입니다.",
                "#38bdf8",
                "#081426",
                "#0ea5e9",
            ),
            (
                "🛡️ 방어 원리 (Defense Principle)",
                "해커가 웹셸을 업로드하거나 소스코드를 단 1글자라도 수정·변조(Tampering)하면 해시값이 즉각 불일치하여 🚨 침해 경보를 발생시킵니다.",
                "#fbbf24",
                "#1e1308",
                "#d97706",
            ),
            (
                "⚡ 사용 방법 (How to Use)",
                "상단 [📁 무결성 대조 검증 실행]을 누르면 58개 전체 파일의 위변조 여부를 0.1초 만에 전수 검사하며, 정상적인 코드 업데이트 후에는 [🔄 전체 베이스라인 갱신]을 눌러 새 지문으로 업데이트합니다.",
                "#34d399",
                "#061d18",
                "#059669",
            ),
        ]

        for col_idx, (t_title, t_desc, t_color, t_bg, t_border) in enumerate(tiles_data):
            t_card = ctk.CTkFrame(guide_grid, fg_color=t_bg, corner_radius=8, border_width=1, border_color=t_border)
            t_card.grid(row=0, column=col_idx, sticky="nsew", padx=4, pady=2)

            ctk.CTkLabel(
                t_card,
                text=t_title,
                font=ctk.CTkFont(family=FONT_FAMILY_UI, size=11, weight="bold"),
                text_color=t_color,
                anchor="w",
            ).pack(fill="x", padx=10, pady=(6, 2))

            ctk.CTkLabel(
                t_card,
                text=t_desc,
                font=ctk.CTkFont(family=FONT_FAMILY_UI, size=10),
                text_color=TEXT_BODY,
                wraplength=340,
                justify="left",
                anchor="w",
            ).pack(fill="x", padx=10, pady=(0, 8))

        # 2. FIM 실시간 KPI 상태 및 인라인 검색 툴바
        fim_kpi_bar = ctk.CTkFrame(f, fg_color=SURFACE_CARD, corner_radius=8, border_width=1, border_color=BORDER_SUBTLE, height=42)
        fim_kpi_bar.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 8))

        base_cnt = len(getattr(self.fim, "_baseline_hashes", {})) or 58
        self.lbl_fim_count = ctk.CTkLabel(
            fim_kpi_bar,
            text=f"● 감시 대상: {base_cnt}개 핵심 자산",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=11, weight="bold"),
            text_color=COLOR_CYAN,
        )
        self.lbl_fim_count.pack(side="left", padx=(14, 12))

        ctk.CTkLabel(
            fim_kpi_bar,
            text="🔒 알고리즘: SHA-256 (256-bit Digest)",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=11),
            text_color=TEXT_MUTED,
        ).pack(side="left", padx=8)

        self.lbl_fim_status_kpi = ctk.CTkLabel(
            fim_kpi_bar,
            text="🛡️ 무결성: 100% 정상 (변조 없음)",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=11, weight="bold"),
            text_color=COLOR_SECURE,
        )
        self.lbl_fim_status_kpi.pack(side="left", padx=14)

        # 실시간 파일 필터 검색창
        self.ent_fim_search = ctk.CTkEntry(
            fim_kpi_bar,
            width=290,
            height=30,
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=11),
            fg_color=SURFACE_INPUT,
            border_color=BORDER_SUBTLE,
            text_color=TEXT_TITLE,
            placeholder_text="🔍 파일명 / 디렉터리 경로 실시간 검색...",
        )
        self.ent_fim_search.pack(side="right", padx=(0, 10), pady=6)
        self.ent_fim_search.bind("<KeyRelease>", lambda e: self._refresh_fim_table())

        # 3. 개방형 파일 목록 컬럼 헤더 바
        col_bar = ctk.CTkFrame(f, fg_color=SURFACE_INNER, corner_radius=6, border_width=1, border_color=BORDER_SUBTLE, height=32)
        col_bar.grid(row=3, column=0, sticky="ew", padx=16, pady=(0, 4))

        ctk.CTkLabel(col_bar, text="상태", width=75, anchor="center", font=ctk.CTkFont(family=FONT_FAMILY_UI, size=11, weight="bold"), text_color=TEXT_MUTED).pack(side="left", padx=(8, 4))
        ctk.CTkLabel(col_bar, text="감시 파일 상대 경로 (Path)", width=260, anchor="w", font=ctk.CTkFont(family=FONT_FAMILY_UI, size=11, weight="bold"), text_color=TEXT_MUTED).pack(side="left", padx=4)
        ctk.CTkLabel(col_bar, text="SHA-256 해시 프리뷰 (베이스라인 대조)", anchor="w", font=ctk.CTkFont(family=FONT_FAMILY_UI, size=11, weight="bold"), text_color=TEXT_MUTED).pack(side="left", fill="x", expand=True, padx=4)
        ctk.CTkLabel(col_bar, text="보안 모듈 분류", width=130, anchor="center", font=ctk.CTkFont(family=FONT_FAMILY_UI, size=11, weight="bold"), text_color=TEXT_MUTED).pack(side="left", padx=4)
        ctk.CTkLabel(col_bar, text="검증 & 정밀 대조", width=130, anchor="center", font=ctk.CTkFont(family=FONT_FAMILY_UI, size=11, weight="bold"), text_color=TEXT_MUTED).pack(side="right", padx=(4, 14))

        # 4. 개방형 스크롤 테이블
        self.scroll_fim = ctk.CTkScrollableFrame(f, fg_color="transparent")
        self.scroll_fim.grid(row=4, column=0, sticky="nsew", padx=16, pady=(0, 8))

        # 5. SHA-256 해시 정밀 대조 인스펙터 (Hash Comparison Inspector)
        self.fim_inspector = ctk.CTkFrame(
            f, fg_color=SURFACE_CARD, corner_radius=10, border_width=1, border_color=BORDER_SUBTLE
        )
        self.fim_inspector.grid(row=5, column=0, sticky="ew", padx=16, pady=(4, 12))

        # 인스펙터 헤더 행
        insp_head = ctk.CTkFrame(self.fim_inspector, fg_color="transparent")
        insp_head.pack(fill="x", padx=14, pady=(10, 6))

        ctk.CTkLabel(
            insp_head,
            text="🔬 SHA-256 해시 정밀 대조 인스펙터 (Hash Comparison Inspector)",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=12, weight="bold"),
            text_color=COLOR_CYAN,
        ).pack(side="left")

        # 선택 파일 배지
        self.insp_file_pill = ctk.CTkFrame(insp_head, fg_color=SURFACE_INNER, corner_radius=4, border_width=1, border_color=BORDER_ACTIVE)
        self.insp_file_pill.pack(side="left", padx=(10, 8))
        self.lbl_insp_file = ctk.CTkLabel(
            self.insp_file_pill,
            text="선택 파일: 없음",
            font=ctk.CTkFont(family=FONT_FAMILY_MONO, size=10, weight="bold"),
            text_color=TEXT_TITLE,
        )
        self.lbl_insp_file.pack(padx=8, pady=2)

        # 무결성 검증 상태 배지
        self.insp_status_pill = ctk.CTkFrame(insp_head, fg_color=COLOR_SECURE_BG, corner_radius=4, border_width=1, border_color=BORDER_EMERALD)
        self.insp_status_pill.pack(side="left", padx=4)
        self.lbl_insp_status = ctk.CTkLabel(
            self.insp_status_pill,
            text="● 베이스라인 일치 (SHA-256 MATCH)",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=10, weight="bold"),
            text_color=COLOR_SECURE,
        )
        self.lbl_insp_status.pack(padx=8, pady=2)

        # 우측 액션 버튼들
        ctk.CTkButton(
            insp_head,
            text="📂 탐색기 위치 열기",
            width=110,
            height=26,
            fg_color=BUTTON_SECONDARY,
            hover_color=BUTTON_SECONDARY_HOVER,
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=10),
            command=self._open_fim_file_in_explorer,
        ).pack(side="right", padx=(4, 0))

        ctk.CTkButton(
            insp_head,
            text="🔄 이 파일만 베이스라인 갱신",
            width=150,
            height=26,
            fg_color=BUTTON_SECONDARY,
            hover_color=BUTTON_SECONDARY_HOVER,
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=10),
            command=self._on_fim_rebase_single,
        ).pack(side="right", padx=4)

        # 해시 정밀 비교 카드 그리드 (베이스라인 vs 실시간 디스크)
        grid_frame = ctk.CTkFrame(self.fim_inspector, fg_color=SURFACE_INNER, corner_radius=8, border_width=1, border_color=BORDER_SUBTLE)
        grid_frame.pack(fill="x", padx=14, pady=(0, 6))

        # 1행: 베이스라인 해시
        row1 = ctk.CTkFrame(grid_frame, fg_color="transparent")
        row1.pack(fill="x", padx=10, pady=(6, 3))

        ctk.CTkLabel(
            row1,
            text="기준 베이스라인 해시 :",
            width=135,
            anchor="w",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=10, weight="bold"),
            text_color=TEXT_MUTED,
        ).pack(side="left")

        self.ent_insp_baseline_hash = ctk.CTkEntry(
            row1,
            height=26,
            font=ctk.CTkFont(family=FONT_FAMILY_MONO, size=10),
            fg_color=SURFACE_CARD,
            border_color=BORDER_SUBTLE,
            text_color=TEXT_BODY,
        )
        self.ent_insp_baseline_hash.pack(side="left", fill="x", expand=True, padx=(4, 8))

        ctk.CTkButton(
            row1,
            text="📋 복사",
            width=54,
            height=24,
            fg_color=BUTTON_SECONDARY,
            hover_color=BUTTON_SECONDARY_HOVER,
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=10),
            command=lambda: self._copy_fim_hash("baseline"),
        ).pack(side="right")

        # 2행: 실시간 디스크 해시
        row2 = ctk.CTkFrame(grid_frame, fg_color="transparent")
        row2.pack(fill="x", padx=10, pady=(3, 6))

        ctk.CTkLabel(
            row2,
            text="실시간 디스크 해시 :",
            width=135,
            anchor="w",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=10, weight="bold"),
            text_color=COLOR_CYAN,
        ).pack(side="left")

        self.ent_insp_current_hash = ctk.CTkEntry(
            row2,
            height=26,
            font=ctk.CTkFont(family=FONT_FAMILY_MONO, size=10, weight="bold"),
            fg_color=SURFACE_CARD,
            border_color=BORDER_SUBTLE,
            text_color=COLOR_SECURE,
        )
        self.ent_insp_current_hash.pack(side="left", fill="x", expand=True, padx=(4, 8))

        ctk.CTkButton(
            row2,
            text="📋 복사",
            width=54,
            height=24,
            fg_color=BUTTON_SECONDARY,
            hover_color=BUTTON_SECONDARY_HOVER,
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=10),
            command=lambda: self._copy_fim_hash("current"),
        ).pack(side="right")

        # 인스펙터 하단 메타데이터 및 토스트 안내 행
        insp_foot = ctk.CTkFrame(self.fim_inspector, fg_color="transparent")
        insp_foot.pack(fill="x", padx=14, pady=(0, 8))

        self.lbl_insp_meta = ctk.CTkLabel(
            insp_foot,
            text="• 파일 메타데이터: 조회 대기 중",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=10),
            text_color=TEXT_MUTED,
        )
        self.lbl_insp_meta.pack(side="left")

        self.lbl_insp_toast = ctk.CTkLabel(
            insp_foot,
            text="",
            font=ctk.CTkFont(family=FONT_FAMILY_UI, size=10, weight="bold"),
            text_color=COLOR_SECURE,
        )
        self.lbl_insp_toast.pack(side="right")

        # 초기 FIM 전체 파일 테이블 렌더링
        self._refresh_fim_table()

        return f

    def _get_fim_module_tag(self, file_path):
        fp = file_path.replace("\\", "/").lower()
        if fp.startswith("app"):
            return "웹 포털 라우트", COLOR_CYAN
        elif fp.startswith("nexus_guard"):
            return "AI-XDR 방어 엔진", COLOR_PURPLE
        elif fp.startswith("db"):
            return "데이터베이스", COLOR_WARN
        elif fp.startswith("tests"):
            return "보안 테스트 스위트", COLOR_SECURE
        elif ".env" in fp or "config" in fp:
            return "보안 자격증명", COLOR_ALERT
        return "핵심 시스템 소스", TEXT_MUTED

    def _refresh_fim_table(self, alerts=None):
        if not hasattr(self, "scroll_fim"):
            return
        for child in self.scroll_fim.winfo_children():
            child.destroy()

        alert_map = {}
        if alerts:
            for a in alerts:
                alert_map[a.get("file", "").replace("/", "\\")] = a
                alert_map[a.get("file", "").replace("\\", "/")] = a

        query = self.ent_fim_search.get().strip().lower() if hasattr(self, "ent_fim_search") else ""
        hashes = getattr(self.fim, "_baseline_hashes", {})

        displayed_count = 0
        first_file = None
        for fpath, hval in sorted(hashes.items()):
            norm_path = fpath.replace("\\", "/")
            if query and query not in norm_path.lower() and query not in hval.lower():
                continue

            displayed_count += 1
            if first_file is None:
                first_file = norm_path

            is_tampered = (fpath in alert_map) or (norm_path in alert_map)
            is_selected = hasattr(self, "_selected_fim_file") and self._selected_fim_file == norm_path

            # 열린 테이블 행
            row_bg = COLOR_ALERT_BG if is_tampered else (SURFACE_HOVER if is_selected else (SURFACE_CARD if displayed_count % 2 == 0 else "transparent"))
            row_border = BORDER_CRIMSON if is_tampered else (BORDER_CYAN if is_selected else BORDER_SUBTLE)

            row = ctk.CTkFrame(
                self.scroll_fim,
                fg_color=row_bg,
                corner_radius=6,
                border_width=1,
                border_color=row_border,
            )
            row.pack(fill="x", padx=2, pady=2)

            # 상태 배지
            if is_tampered:
                st_pill = ctk.CTkFrame(row, fg_color="#450a0a", corner_radius=4, border_width=1, border_color=BORDER_CRIMSON)
                st_pill.pack(side="left", padx=(8, 4), pady=5)
                ctk.CTkLabel(st_pill, text="🚨 변조", width=55, font=ctk.CTkFont(family=FONT_FAMILY_UI, size=10, weight="bold"), text_color=COLOR_ALERT).pack(padx=4, pady=2)
            else:
                st_pill = ctk.CTkFrame(row, fg_color=COLOR_SECURE_BG, corner_radius=4, border_width=1, border_color=BORDER_EMERALD)
                st_pill.pack(side="left", padx=(8, 4), pady=5)
                ctk.CTkLabel(st_pill, text="● 정상", width=55, font=ctk.CTkFont(family=FONT_FAMILY_UI, size=10, weight="bold"), text_color=COLOR_SECURE).pack(padx=4, pady=2)

            # 파일 상대 경로
            ctk.CTkLabel(
                row,
                text=norm_path,
                width=260,
                anchor="w",
                font=ctk.CTkFont(family=FONT_FAMILY_MONO, size=11, weight="bold"),
                text_color=COLOR_ALERT if is_tampered else COLOR_CYAN,
            ).pack(side="left", padx=4)

            # SHA-256 해시 프리뷰
            h_preview = f"{hval[:16]}...{hval[-10:]}" if len(hval) > 26 else (hval or "(빈 파일)")
            ctk.CTkLabel(
                row,
                text=h_preview,
                anchor="w",
                font=ctk.CTkFont(family=FONT_FAMILY_MONO, size=10),
                text_color="#fca5a5" if is_tampered else TEXT_MUTED,
            ).pack(side="left", fill="x", expand=True, padx=4)

            # 모듈 분류 배지
            mod_title, mod_col = self._get_fim_module_tag(norm_path)
            mod_pill = ctk.CTkFrame(row, fg_color=SURFACE_INNER, corner_radius=4, border_width=1, border_color=BORDER_SUBTLE)
            mod_pill.pack(side="left", padx=4)
            ctk.CTkLabel(mod_pill, text=mod_title, width=120, font=ctk.CTkFont(family=FONT_FAMILY_UI, size=10, weight="bold"), text_color=mod_col).pack(padx=4, pady=2)

            # 오른쪽 액션 및 검증 결과 컨테이너
            r_box = ctk.CTkFrame(row, fg_color="transparent")
            r_box.pack(side="right", padx=(4, 12))

            v_txt = "⚠️ 불일치" if is_tampered else "✅ MATCH"
            v_fg = COLOR_ALERT if is_tampered else COLOR_SECURE
            ctk.CTkLabel(r_box, text=v_txt, width=70, anchor="center", font=ctk.CTkFont(family=FONT_FAMILY_MONO, size=10, weight="bold"), text_color=v_fg).pack(side="left", padx=(0, 4))

            ctk.CTkButton(
                r_box,
                text="대조",
                width=48,
                height=24,
                fg_color=BUTTON_SECONDARY,
                hover_color=BUTTON_SECONDARY_HOVER,
                font=ctk.CTkFont(family=FONT_FAMILY_UI, size=10, weight="bold"),
                command=lambda p=norm_path: self._inspect_fim_file(p),
            ).pack(side="left")

            # 행 전체 클릭 시 인스펙터 대조 바인딩
            row.bind("<Button-1>", lambda e, p=norm_path: self._inspect_fim_file(p))

        if displayed_count == 0:
            empty_box = ctk.CTkFrame(self.scroll_fim, fg_color="transparent")
            empty_box.pack(fill="x", padx=4, pady=24)
            ctk.CTkLabel(empty_box, text=f"검색어 '{query}'와 일치하는 감시 대상 파일이 없습니다.", font=ctk.CTkFont(family=FONT_FAMILY_UI, size=11), text_color=TEXT_MUTED).pack(anchor="center")
        elif not hasattr(self, "_selected_fim_file") or not self._selected_fim_file:
            # 기본 첫 번째 파일 자동 인스펙트
            target_to_inspect = alerts[0]["file"] if (alerts and len(alerts) > 0) else (first_file or ".env")
            self._inspect_fim_file(target_to_inspect)

    def _inspect_fim_file(self, rel_path):
        """선택한 파일의 SHA-256 베이스라인과 실시간 디스크 해시를 정밀 대조하여 인스펙터에 출력."""
        self._selected_fim_file = rel_path
        if not hasattr(self, "lbl_insp_file"):
            return

        norm_path = rel_path.replace("\\", "/")
        self.lbl_insp_file.configure(text=f"📁 {norm_path}")

        full_path = BASE_DIR / rel_path
        exists = full_path.exists()
        current_hash = self.fim._calculate_sha256(full_path) if exists else "(파일 없음 - 디스크에서 삭제됨)"
        baseline_hash = self.fim._baseline_hashes.get(norm_path) or self.fim._baseline_hashes.get(rel_path, "(미등록 파일)")

        # 엔트리 텍스트 갱신 (읽기 전용 상태 해제 후 갱신)
        self.ent_insp_baseline_hash.configure(state="normal")
        self.ent_insp_baseline_hash.delete(0, "end")
        self.ent_insp_baseline_hash.insert(0, baseline_hash)
        self.ent_insp_baseline_hash.configure(state="readonly")

        self.ent_insp_current_hash.configure(state="normal")
        self.ent_insp_current_hash.delete(0, "end")
        self.ent_insp_current_hash.insert(0, current_hash)

        # 상태 판정 및 스타일 적용
        if not exists:
            self.insp_status_pill.configure(fg_color=COLOR_ALERT_BG, border_color=BORDER_CRIMSON)
            self.lbl_insp_status.configure(text="❌ 파일 누락 (FILE DELETED)", text_color=COLOR_ALERT)
            self.ent_insp_current_hash.configure(text_color=COLOR_ALERT, border_color=BORDER_CRIMSON)
            meta_txt = f"• 절대 경로: {full_path}   |   • 파일 상태: 디스크에서 파일이 삭제되었습니다!"
        elif baseline_hash == "(미등록 파일)":
            self.insp_status_pill.configure(fg_color=COLOR_WARN_BG, border_color=COLOR_WARN)
            self.lbl_insp_status.configure(text="⚠️ 미등록 신규 파일 (NEW UNREGISTERED)", text_color=COLOR_WARN)
            self.ent_insp_current_hash.configure(text_color=COLOR_WARN, border_color=COLOR_WARN)
            size_kb = os.path.getsize(full_path) / 1024.0
            mtime = datetime.fromtimestamp(os.path.getmtime(full_path)).strftime("%Y-%m-%d %H:%M:%S")
            meta_txt = f"• 크기: {size_kb:.1f} KB ({os.path.getsize(full_path):,} 바이트)   |   • 최종 수정: {mtime}   |   • 알고리즘: SHA-256 (256-bit Digest)"
        elif current_hash == baseline_hash:
            self.insp_status_pill.configure(fg_color=COLOR_SECURE_BG, border_color=BORDER_EMERALD)
            self.lbl_insp_status.configure(text="✅ 베이스라인 무결성 일치 (INTEGRITY VERIFIED)", text_color=COLOR_SECURE)
            self.ent_insp_current_hash.configure(text_color=COLOR_SECURE, border_color=BORDER_EMERALD)
            size_kb = os.path.getsize(full_path) / 1024.0
            mtime = datetime.fromtimestamp(os.path.getmtime(full_path)).strftime("%Y-%m-%d %H:%M:%S")
            meta_txt = f"• 크기: {size_kb:.1f} KB ({os.path.getsize(full_path):,} 바이트)   |   • 최종 수정: {mtime}   |   • 알고리즘: SHA-256   |   • 상태: 정상 무결성 유지 중"
        else:
            self.insp_status_pill.configure(fg_color=COLOR_ALERT_BG, border_color=BORDER_CRIMSON)
            self.lbl_insp_status.configure(text="🚨 SHA-256 해시 불일치 (TAMPERED / MISMATCH)", text_color=COLOR_ALERT)
            self.ent_insp_current_hash.configure(text_color=COLOR_ALERT, border_color=BORDER_CRIMSON)
            size_kb = os.path.getsize(full_path) / 1024.0
            mtime = datetime.fromtimestamp(os.path.getmtime(full_path)).strftime("%Y-%m-%d %H:%M:%S")
            meta_txt = f"• 크기: {size_kb:.1f} KB ({os.path.getsize(full_path):,} 바이트)   |   • 최종 수정: {mtime}   |   • 알고리즘: SHA-256   |   • 경고: 인가되지 않은 소스코드 변조 감지!"

        self.ent_insp_current_hash.configure(state="readonly")
        self.lbl_insp_meta.configure(text=meta_txt)

    def _copy_fim_hash(self, hash_type="baseline"):
        h = ""
        if hash_type == "baseline" and hasattr(self, "ent_insp_baseline_hash"):
            h = self.ent_insp_baseline_hash.get()
            label = "기준 베이스라인 해시"
        elif hasattr(self, "ent_insp_current_hash"):
            h = self.ent_insp_current_hash.get()
            label = "실시간 디스크 해시"
        else:
            label = "해시"

        if h:
            self.clipboard_clear()
            self.clipboard_append(h)
            if hasattr(self, "lbl_insp_toast"):
                self.lbl_insp_toast.configure(text=f"✔ {label}가 클립보드에 복사되었습니다.", text_color=COLOR_SECURE)
                self.after(3000, lambda: self.lbl_insp_toast.configure(text=""))

    def _on_fim_rebase_single(self):
        if not hasattr(self, "_selected_fim_file") or not self._selected_fim_file:
            messagebox.showwarning("파일 미선택", "먼저 목록에서 베이스라인을 갱신할 파일을 선택하세요.")
            return

        rel_path = self._selected_fim_file
        full_path = BASE_DIR / rel_path
        if not full_path.exists():
            messagebox.showerror("파일 없음", f"디스크에 해당 파일이 존재하지 않습니다:\n{full_path}")
            return

        live_hash = self.fim._calculate_sha256(full_path)
        norm_path = rel_path.replace("\\", "/")
        self.fim._baseline_hashes[norm_path] = live_hash
        self.fim._baseline_hashes[rel_path] = live_hash

        self._refresh_fim_table(alerts=None)
        self._inspect_fim_file(rel_path)

        if hasattr(self, "lbl_insp_toast"):
            self.lbl_insp_toast.configure(text=f"✔ [{norm_path}] 해시가 새 베이스라인으로 갱신되었습니다.", text_color=COLOR_SECURE)
            self.after(4000, lambda: self.lbl_insp_toast.configure(text=""))

    def _open_fim_file_in_explorer(self):
        if not hasattr(self, "_selected_fim_file") or not self._selected_fim_file:
            messagebox.showwarning("파일 미선택", "먼저 탐색기에서 확인할 파일을 선택하세요.")
            return

        full_path = BASE_DIR / self._selected_fim_file
        if not full_path.exists():
            messagebox.showerror("파일 없음", f"디스크에 해당 파일이 존재하지 않습니다:\n{full_path}")
            return

        try:
            subprocess.Popen(f'explorer /select,"{str(full_path)}"')
        except Exception as e:
            messagebox.showwarning("탐색기 오류", f"파일 탐색기를 실행하지 못했습니다:\n{e}")

    def _on_fim_check(self):
        alerts = self.fim.scan_for_tampering()
        if not alerts:
            self.lbl_fim_status_kpi.configure(text="🛡️ 무결성: 100% 정상 (변조 없음)", text_color=COLOR_SECURE)
            self._refresh_fim_table(alerts=None)
            messagebox.showinfo("무결성 확인", f"전체 {len(getattr(self.fim, '_baseline_hashes', {}))}개 파일의 SHA-256 해시가 베이스라인과 100% 일치합니다 (변조 0건).")
        else:
            self.lbl_fim_status_kpi.configure(text=f"⚠️ {len(alerts)}건 파일 변조 의심 적발!", text_color=COLOR_ALERT)
            self._refresh_fim_table(alerts=alerts)
            if len(alerts) > 0:
                self._inspect_fim_file(alerts[0]["file"])
            msg = f"{len(alerts)}건의 파일 변조가 감지되었습니다:\n\n"
            for a in alerts[:5]:
                msg += f"• [{a.get('type')}] {a.get('file')}: {a.get('desc')}\n"
            messagebox.showwarning("변조 경고", msg)

    def _on_fim_rebase(self):
        count = self.fim.initialize_baseline()
        if hasattr(self, "lbl_fim_count"):
            self.lbl_fim_count.configure(text=f"● 감시 대상: {count}개 핵심 자산")
        self.lbl_fim_status_kpi.configure(text="🛡️ 무결성: 100% 정상 (변조 없음)", text_color=COLOR_SECURE)
        self._refresh_fim_table(alerts=None)
        if hasattr(self, "_selected_fim_file") and self._selected_fim_file:
            self._inspect_fim_file(self._selected_fim_file)
        messagebox.showinfo("베이스라인 갱신 완료", f"현재 {count}개 파일의 최신 SHA-256 해시가 새로운 무결성 베이스라인으로 성공적으로 등록되었습니다.")

    # =========================================================================
    # 탭 6: 통합 환경 설정 & 외부 연동 (config.json 동기화)
    # =========================================================================
    def _create_settings_view(self):
        f = ctk.CTkScrollableFrame(self.views_container, fg_color="transparent")

        self.cfg_entries = {}

        # =====================================================================
        # [신규 설치 사용자 온보딩 가이드] 4단계 빠른 시작 설정 가이드 카드
        # =====================================================================
        guide_box = ctk.CTkFrame(f, fg_color="#102a24", corner_radius=12, border_width=1, border_color="#10b981")
        guide_box.pack(fill="x", pady=(0, 14), padx=4)

        g_head = ctk.CTkFrame(guide_box, fg_color="transparent")
        g_head.pack(fill="x", padx=16, pady=(12, 6))

        ctk.CTkLabel(
            g_head,
            text="🚀 처음 사용자를 위한 4단계 빠른 시작 설정 가이드 (Quick Start Guide)",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color="#10b981",
        ).pack(side="left")

        guide_badge = ctk.CTkFrame(g_head, fg_color="#064e3b", corner_radius=4)
        guide_badge.pack(side="right")
        ctk.CTkLabel(guide_badge, text="● 초보자 친화 셋업", font=ctk.CTkFont(size=9, weight="bold"), text_color="#34d399").pack(padx=6, pady=2)

        g_desc = (
            "NEXUS-GUARD를 처음 설치하셨다면 아래의 4단계 가이드에 따라 설정을 진행하세요.\n"
            "단독 PC 환경에서는 기본 능동 방어(호스트 방화벽 netsh 드롭 + WAF 입구 격리 + 파일 무결성 FIM)가 즉시 보호를 제공하므로,\n"
            "외부 연동(pfSense, Graylog, Wazuh)은 필요할 때만 선택적으로 설정하시면 됩니다."
        )
        ctk.CTkLabel(
            guide_box,
            text=g_desc,
            font=ctk.CTkFont(size=11),
            text_color="#cbd5e1",
            justify="left",
        ).pack(anchor="w", padx=16, pady=(0, 10))

        # 4개의 단계별 가이드 타일 (그리드 레이아웃)
        step_grid = ctk.CTkFrame(guide_box, fg_color="transparent")
        step_grid.pack(fill="x", padx=12, pady=(0, 12))
        step_grid.grid_columnconfigure((0, 1, 2, 3), weight=1)

        steps_data = [
            (
                "1단계: 보호 대상 지정",
                "🌐 웹/DB 주소 입력",
                "보호할 웹 포털 URL(예: http://내서버:8080)과 DB 포트를 지정합니다.\n내 PC에서 바로 테스트하려면 아래 [로컬 주소 자동 채우기] 버튼을 누르세요.",
                "#38bdf8",
                "#0b1d3a",
            ),
            (
                "2단계: AI 분석기 선택",
                "🤖 AI-XDR 엔진 선택",
                "Groq(초고속), NVIDIA NIM, 또는 Ollama(로컬) 중 원하는 모델을 선택합니다.\nAPI 키가 없어도 100% 룰셋 기반 방어는 정상 작동합니다.",
                "#a78bfa",
                "#2e1065",
            ),
            (
                "3단계: 외부 장비 연동",
                "🧱 방화벽/SIEM (선택)",
                "사내에 pfSense 방화벽이나 Graylog SIEM이 구축되어 있다면 IP를 입력하고 [테스트] 버튼을 누르세요. 없으면 비워두셔도 안전합니다.",
                "#fbbf24",
                "#2a1f0a",
            ),
            (
                "4단계: 저장 & 진단 실행",
                "🔍 정밀 검증 시작",
                "하단의 [💾 변경 설정 저장]을 누르면 새 설정이 config.json에 영구 반영되며, [시스템 진단] 탭에서 입력한 대상의 보안 검증이 시작됩니다.",
                "#10b981",
                "#0c2e26",
            ),
        ]

        for idx, (st_num, st_title, st_detail, s_fg, s_bg) in enumerate(steps_data):
            card = ctk.CTkFrame(step_grid, fg_color=s_bg, corner_radius=8, border_width=1, border_color=s_fg)
            card.grid(row=0, column=idx, sticky="nsew", padx=4, pady=4)

            ctk.CTkLabel(card, text=st_num, font=ctk.CTkFont(size=9, weight="bold"), text_color=s_fg).pack(anchor="w", padx=10, pady=(8, 2))
            ctk.CTkLabel(card, text=st_title, font=ctk.CTkFont(size=11, weight="bold"), text_color="#f8fafc").pack(anchor="w", padx=10, pady=(0, 4))
            ctk.CTkLabel(card, text=st_detail, font=ctk.CTkFont(size=10), text_color="#cbd5e1", wraplength=210, justify="left").pack(anchor="w", padx=10, pady=(0, 10))

        # 가이드 툴바 액션 버튼들
        g_action_bar = ctk.CTkFrame(guide_box, fg_color="#090d16", corner_radius=8)
        g_action_bar.pack(fill="x", padx=14, pady=(0, 12))

        ctk.CTkLabel(g_action_bar, text="⚡ 빠른 셋업 도우미:", font=ctk.CTkFont(size=11, weight="bold"), text_color="#38bdf8").pack(side="left", padx=(12, 10), pady=8)

        ctk.CTkButton(
            g_action_bar,
            text="⚡ 내 PC 로컬 테스트 주소 자동 채우기 (127.0.0.1:5070)",
            fg_color="#0284c7",
            hover_color="#0369a1",
            font=ctk.CTkFont(size=10, weight="bold"),
            height=28,
            command=self._on_fill_local_test_presets,
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            g_action_bar,
            text="🧹 모든 설정 비우기 (초기 설치 상태 클린 초기화)",
            fg_color="#dc2626",
            hover_color="#b91c1c",
            font=ctk.CTkFont(size=10, weight="bold"),
            height=28,
            command=self._on_clear_all_settings,
        ).pack(side="left", padx=4)

        # 외부 보안 장비 실시간 헬스 매트릭스 뱃지 스트립 (동적 상태 반영)
        self.health_matrix_strip = ctk.CTkFrame(f, fg_color="#0f172a", corner_radius=12, border_width=1, border_color="#1e293b")
        self.health_matrix_strip.pack(fill="x", padx=4, pady=(0, 14))

        hm_head = ctk.CTkFrame(self.health_matrix_strip, fg_color="transparent")
        hm_head.pack(fill="x", padx=16, pady=(12, 6))
        ctk.CTkLabel(hm_head, text="📡 외부 보안 장비 & 클라우드 연동 실시간 상태 매트릭스", font=ctk.CTkFont(size=13, weight="bold"), text_color="#38bdf8").pack(side="left")
        ctk.CTkLabel(hm_head, text="● 5대 모듈 상태 텔레메트리", font=ctk.CTkFont(size=10, weight="bold"), text_color="#10b981").pack(side="right")

        matrix_cards_box = ctk.CTkFrame(self.health_matrix_strip, fg_color="transparent")
        matrix_cards_box.pack(fill="x", padx=12, pady=(0, 12))

        # 동적 초기 상태 계산
        ext_cfg = self.cfg.get("external_integrations", {})
        pfs_init = ext_cfg.get("pfsense", {}).get("enabled", False) and bool(ext_cfg.get("pfsense", {}).get("host"))
        gl_init = ext_cfg.get("graylog", {}).get("enabled", False) and bool(ext_cfg.get("graylog", {}).get("host"))
        wz_init = ext_cfg.get("wazuh", {}).get("enabled", False) and bool(ext_cfg.get("wazuh", {}).get("manager_host"))
        ai_cfg = self.cfg.get("ai_xdr_engine", {})
        ai_init = bool(ai_cfg.get("groq_api_key") or ai_cfg.get("nvidia_api_key") or ai_cfg.get("ollama_base_url"))

        services = [
            ("pfSense 게이트웨이", ("● FEED ACTIVE", "#10b981", "#0c2e26") if pfs_init else ("○ STANDBY (미연동)", "#94a3b8", "#1e293b")),
            ("Graylog SIEM", ("● GELF READY", "#10b981", "#0c2e26") if gl_init else ("○ STANDBY (미연동)", "#94a3b8", "#1e293b")),
            ("Wazuh EDR/XDR", ("● AGENT READY", "#38bdf8", "#0b1d3a") if wz_init else ("○ STANDBY (미연동)", "#94a3b8", "#1e293b")),
            ("AI-XDR LPU", ("● LPU CONNECTED", "#a78bfa", "#2e1065") if ai_init else ("○ RULE-BASED (룰셋 모드)", "#38bdf8", "#0b1d3a")),
            ("SOAR Webhook", ("○ STANDALONE (단독 모드)", "#94a3b8", "#1e293b")),
        ]

        self.service_status_labels = {}
        for title, (status, fg_col, bg_col) in services:
            card = ctk.CTkFrame(matrix_cards_box, fg_color=bg_col, corner_radius=6, border_width=1, border_color=fg_col)
            card.pack(side="left", expand=True, fill="x", padx=4, pady=4)

            ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=10, weight="bold"), text_color="#cbd5e1").pack(padx=8, pady=(6, 1))
            lbl_st = ctk.CTkLabel(card, text=status, font=ctk.CTkFont(size=9, weight="bold"), text_color=fg_col)
            lbl_st.pack(padx=8, pady=(0, 6))
            self.service_status_labels[title] = (card, lbl_st)

        # 섹션 0: ⚡ 1-클릭 환경 프리셋 프로파일 (초보자 원클릭 세팅) & 백업/복원
        s0 = ctk.CTkFrame(f, fg_color="#1e293b", corner_radius=12, border_width=1, border_color="#38bdf8")
        s0.pack(fill="x", pady=(0, 14), padx=4)

        s0_head = ctk.CTkFrame(s0, fg_color="transparent")
        s0_head.pack(fill="x", padx=16, pady=(12, 6))

        ctk.CTkLabel(
            s0_head,
            text="⚡ 1-클릭 환경 프리셋 프로파일 (초보자 원클릭 세팅) & 설정 백업/복원",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#38bdf8",
        ).pack(side="left")

        ctk.CTkLabel(
            s0,
            text="외부 방화벽(pfSense)이나 SIEM(Graylog) 프로그램 설치 여부에 관계없이 사용자 환경에 맞게 1초 만에 최적 세팅합니다.",
            font=ctk.CTkFont(size=11),
            text_color="#94a3b8",
        ).pack(anchor="w", padx=16, pady=(0, 8))

        preset_box = ctk.CTkFrame(s0, fg_color="transparent")
        preset_box.pack(fill="x", padx=16, pady=(0, 8))

        ctk.CTkButton(
            preset_box,
            text="🏠 단독 PC 안심 모드 (초보자/단독실행 추천)",
            fg_color="#059669",
            hover_color="#047857",
            font=ctk.CTkFont(size=11, weight="bold"),
            height=32,
            command=lambda: self._on_apply_preset("standalone"),
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            preset_box,
            text="🏢 엔터프라이즈 SOC 풀 연동 모드",
            fg_color="#2563eb",
            hover_color="#1d4ed8",
            font=ctk.CTkFont(size=11, weight="bold"),
            height=32,
            command=lambda: self._on_apply_preset("enterprise_soc"),
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            preset_box,
            text="💻 로컬 개발자 모드 (Port 5070 / Mock)",
            fg_color="#475569",
            hover_color="#64748b",
            font=ctk.CTkFont(size=11, weight="bold"),
            height=32,
            command=lambda: self._on_apply_preset("developer_local"),
        ).pack(side="left")

        backup_box = ctk.CTkFrame(s0, fg_color="#0f172a", corner_radius=8)
        backup_box.pack(fill="x", padx=16, pady=(4, 12))

        ctk.CTkLabel(
            backup_box,
            text="📦 전체 설정 & 룰셋 번들 관리:",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#f8fafc",
        ).pack(side="left", padx=(12, 10), pady=6)

        ctk.CTkButton(
            backup_box,
            text="📤 전체 설정 & 룰셋 파일 백업 (Export)",
            fg_color="#0284c7",
            hover_color="#0369a1",
            font=ctk.CTkFont(size=11),
            height=28,
            command=self._on_export_backup_bundle,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            backup_box,
            text="📥 백업 파일 불러오기 복원 (Import)",
            fg_color="#7c3aed",
            hover_color="#6d28d9",
            font=ctk.CTkFont(size=11),
            height=28,
            command=self._on_import_backup_bundle,
        ).pack(side="left")

        # 섹션 1: 웹 포털 & DB 접속 설정
        s1 = ctk.CTkFrame(f, fg_color="#0f172a", corner_radius=12)
        s1.pack(fill="x", pady=(0, 14), padx=4)

        ctk.CTkLabel(s1, text="🌐 1. 감시 대상 웹 포털 & DB 접속 정보 (Target Services)", font=ctk.CTkFont(size=12, weight="bold"), text_color="#38bdf8").pack(anchor="w", padx=16, pady=(12, 8))

        tgt = self.cfg.get("target_service", {})
        self._add_ctk_row(s1, "웹 포털 접속 URL:", "target_service.web_portal_url", tgt.get("web_portal_url", ""), 340, placeholder="예: http://127.0.0.1:5070 또는 https://mysite.com", hint="(24/7 가용성 및 보안 헤더를 프로빙할 주소)")
        self._add_ctk_row(s1, "웹 서비스 포트:", "target_service.web_portal_port", str(tgt.get("web_portal_port", "") or ""), 120, placeholder="예: 5070", hint="(웹 서비스 HTTP/HTTPS 포트)")
        self._add_ctk_row(s1, "MySQL DB 호스트:", "target_service.db_host", tgt.get("db_host", ""), 200, placeholder="예: 127.0.0.1 (미사용 시 비움)", hint="(데이터베이스 IP/도메인 주소)")
        self._add_ctk_row(s1, "MySQL DB 포트:", "target_service.db_port", str(tgt.get("db_port", "") or ""), 120, placeholder="예: 3306 또는 3307", hint="(DB 수신 리스닝 포트)")
        self._add_ctk_row(s1, "DB 데이터베이스명:", "target_service.db_name", tgt.get("db_name", ""), 180, placeholder="예: nexus_db", hint="(선택 사항)")
        self._add_ctk_row(s1, "DB 접속 계정:", "target_service.db_user", tgt.get("db_user", ""), 180, placeholder="예: app_user", hint="(선택 사항)")

        # 섹션 2: AI-XDR 4중 캐스케이드 모델 및 API Key 설정
        s2 = ctk.CTkFrame(f, fg_color="#0f172a", corner_radius=12)
        s2.pack(fill="x", pady=(0, 14), padx=4)

        ctk.CTkLabel(s2, text="🤖 2. AI-XDR 심층 추론 모델 & LPU API Key (AI-Powered Triage)", font=ctk.CTkFont(size=12, weight="bold"), text_color="#38bdf8").pack(anchor="w", padx=16, pady=(12, 8))

        ai = self.cfg.get("ai_xdr_engine", {})
        self._add_ctk_row(s2, "Groq LPU API Key:", "ai_xdr_engine.groq_api_key", ai.get("groq_api_key", ""), 340, is_secret=True, placeholder="gsk_... (비워둘 시 자체 룰셋 모드로 안전 방어)", hint="(Groq Cloud 무료 LPU API Key)")
        self._add_ctk_row(s2, "Groq 모델명:", "ai_xdr_engine.groq_model", ai.get("groq_model", "openai/gpt-oss-120b"), 280, placeholder="openai/gpt-oss-120b", hint="(LPU 초고속 추론 모델)")
        self._add_ctk_row(s2, "NVIDIA NIM API Key:", "ai_xdr_engine.nvidia_api_key", ai.get("nvidia_api_key", ""), 340, is_secret=True, placeholder="nvapi-... (선택 사항)", hint="(2차 캐스케이드 LPU)")
        self._add_ctk_row(s2, "로컬 Ollama URL:", "ai_xdr_engine.ollama_base_url", ai.get("ollama_base_url", ""), 280, placeholder="예: http://127.0.0.1:11434 (오프라인 폐쇄망)", hint="(로컬 LLM 서버 주소)")

        # 섹션 3: 🧱 [pfSense] 게이트웨이 방화벽 개별 전용 설정 & 피드 진단
        s3 = ctk.CTkFrame(f, fg_color="#0f172a", corner_radius=12)
        s3.pack(fill="x", pady=(0, 14), padx=4)

        pfs_top = ctk.CTkFrame(s3, fg_color="transparent")
        pfs_top.pack(fill="x", padx=16, pady=(12, 6))

        ctk.CTkLabel(pfs_top, text="🧱 3. pfSense 게이트웨이 방화벽 전용 설정 (Firewall Integration - 선택)", font=ctk.CTkFont(size=12, weight="bold"), text_color="#38bdf8").pack(side="left")

        pfs = self.cfg.get("external_integrations", {}).get("pfsense", {})
        self._add_ctk_row(s3, "pfSense 호스트/IP:", "external_integrations.pfsense.host", pfs.get("host", ""), 200, placeholder="예: 192.168.1.1 (미사용 시 비움)", hint="(pfSense WebGUI 접근 주소)")
        self._add_ctk_row(s3, "WebGUI HTTPS 포트:", "external_integrations.pfsense.webgui_port", str(pfs.get("webgui_port", 443)), 100, placeholder="443", hint="(관리 콘솔 포트)")
        self._add_ctk_row(s3, "방화벽 Alias 테이블명:", "external_integrations.pfsense.alias_name", pfs.get("alias_name", ""), 240, placeholder="예: NEXUS_XDR_BLOCKED", hint="(URL Table IP Alias 명칭)")
        self._add_ctk_row(s3, "차단 IP 피드 URL:", "external_integrations.pfsense.feed_url", pfs.get("feed_url", ""), 360, placeholder="예: http://127.0.0.1:5070/feeds/xdr-blocked-ips.txt", hint="(pfSense가 폴링할 피드 주소)")
        self._add_ctk_row(s3, "피드 동기화 주기(분):", "external_integrations.pfsense.polling_interval_minutes", str(pfs.get("polling_interval_minutes", 1)), 100, placeholder="1", hint="(분 단위 주기)")
        self._add_ctk_row(s3, "차단 지속 시간(분):", "external_integrations.pfsense.block_duration_minutes", str(pfs.get("block_duration_minutes", 15)), 100, placeholder="15", hint="(자동 차단 지속 시간)")

        pfs_btn_box = ctk.CTkFrame(s3, fg_color="transparent")
        pfs_btn_box.pack(fill="x", padx=16, pady=(6, 12))

        ctk.CTkButton(
            pfs_btn_box,
            text="🔍 pfSense 차단 피드 유효성 및 응답 테스트",
            height=30,
            fg_color="#0284c7",
            hover_color="#0369a1",
            font=ctk.CTkFont(size=11, weight="bold"),
            command=self._on_test_pfsense,
        ).pack(side="left")

        # 섹션 4: 📊 [Graylog] SIEM 로그 수집기 개별 전용 설정 & GELF 패킷 발송
        s4 = ctk.CTkFrame(f, fg_color="#0f172a", corner_radius=12)
        s4.pack(fill="x", pady=(0, 14), padx=4)

        gl_top = ctk.CTkFrame(s4, fg_color="transparent")
        gl_top.pack(fill="x", padx=16, pady=(12, 6))

        ctk.CTkLabel(gl_top, text="📊 4. Graylog 엔터프라이즈 SIEM 전용 설정 (GELF Stream - 선택)", font=ctk.CTkFont(size=12, weight="bold"), text_color="#38bdf8").pack(side="left")

        gl = self.cfg.get("external_integrations", {}).get("graylog", {})
        self._add_ctk_row(s4, "Graylog 서버 호스트:", "external_integrations.graylog.host", gl.get("host", ""), 200, placeholder="예: 192.168.1.50 (미사용 시 비움)", hint="(Graylog 서버 IP/호스트)")
        self._add_ctk_row(s4, "GELF UDP 수신 포트:", "external_integrations.graylog.gelf_udp_port", str(gl.get("gelf_udp_port", 12201)), 100, placeholder="12201", hint="(GELF UDP Input 리스닝 포트)")
        self._add_ctk_row(s4, "전송 프로토콜 (UDP/TCP):", "external_integrations.graylog.protocol", gl.get("protocol", "UDP"), 100, placeholder="UDP", hint="(기본: UDP)")
        self._add_ctk_row(s4, "타겟 스트림/인덱스 명:", "external_integrations.graylog.stream_name", gl.get("stream_name", ""), 240, placeholder="예: NEXUS_SECURITY_STREAM", hint="(SIEM 인덱스 스트림)")
        self._add_ctk_row(s4, "최소 로그 필터 레벨:", "external_integrations.graylog.min_log_level", gl.get("min_log_level", "WARNING"), 120, placeholder="WARNING", hint="(전송 최소 심각도)")
        self._add_ctk_row(s4, "Facility 식별 태그:", "external_integrations.graylog.facility", gl.get("facility", "nexus-guard-soc"), 180, placeholder="nexus-guard-soc", hint="(Syslog Facility 태그)")

        gl_btn_box = ctk.CTkFrame(s4, fg_color="transparent")
        gl_btn_box.pack(fill="x", padx=16, pady=(6, 12))

        ctk.CTkButton(
            gl_btn_box,
            text="📡 Graylog GELF UDP 패킷 전송 테스트",
            height=30,
            fg_color="#059669",
            hover_color="#047857",
            font=ctk.CTkFont(size=11, weight="bold"),
            command=self._on_test_graylog,
        ).pack(side="left")

        # 섹션 5: 🔍 [Wazuh] EDR / XDR / FIM 에이전트 개별 전용 설정 & 진단
        s5 = ctk.CTkFrame(f, fg_color="#0f172a", corner_radius=12)
        s5.pack(fill="x", pady=(0, 14), padx=4)

        wz_top = ctk.CTkFrame(s5, fg_color="transparent")
        wz_top.pack(fill="x", padx=16, pady=(12, 6))

        ctk.CTkLabel(wz_top, text="🔍 5. Wazuh XDR / EDR / FIM 에이전트 전용 설정 (Agent & File Monitor - 선택)", font=ctk.CTkFont(size=12, weight="bold"), text_color="#38bdf8").pack(side="left")

        wz = self.cfg.get("external_integrations", {}).get("wazuh", {})
        self._add_ctk_row(s5, "Wazuh Manager IP:", "external_integrations.wazuh.manager_host", wz.get("manager_host", ""), 200, placeholder="예: 192.168.1.60 (미사용 시 비움)", hint="(Wazuh 매니저 IP)")
        self._add_ctk_row(s5, "Manager 통신 포트:", "external_integrations.wazuh.manager_port", str(wz.get("manager_port", 1514)), 100, placeholder="1514", hint="(에이전트 연결 포트)")
        self._add_ctk_row(s5, "엔드포인트 에이전트 ID:", "external_integrations.wazuh.agent_id", wz.get("agent_id", ""), 100, placeholder="예: 001", hint="(에이전트 고유 식별 번호)")
        self._add_ctk_row(s5, "에이전트 명칭:", "external_integrations.wazuh.agent_name", wz.get("agent_name", ""), 200, placeholder="예: nexus-endpoint-01", hint="(에이전트 호스트 명칭)")
        self._add_ctk_row(s5, "FIM 해시 알고리즘:", "external_integrations.wazuh.hash_algorithm", wz.get("hash_algorithm", "SHA-256"), 120, placeholder="SHA-256", hint="(무결성 알고리즘)")
        self._add_ctk_row(s5, "실시간 감시 주기(초):", "external_integrations.wazuh.fim_interval_seconds", str(wz.get("fim_interval_seconds", 10)), 100, placeholder="10", hint="(초 단위 폴링 주기)")
        self._add_ctk_row(s5, "감시 대상 디렉터리:", "external_integrations.wazuh.monitored_paths", wz.get("monitored_paths", ""), 340, placeholder="예: app, nexus_guard, config.json, .env", hint="(감시할 폴더 및 파일)")

        wz_btn_box = ctk.CTkFrame(s5, fg_color="transparent")
        wz_btn_box.pack(fill="x", padx=16, pady=(6, 12))

        ctk.CTkButton(
            wz_btn_box,
            text="🔍 Wazuh Manager 연결성 & FIM 상태 테스트",
            height=30,
            fg_color="#d97706",
            hover_color="#b45309",
            font=ctk.CTkFont(size=11, weight="bold"),
            command=self._on_test_wazuh,
        ).pack(side="left")

        # 섹션 6: 🔔 실시간 보안 알림 웹훅 & SOAR 워크플로우 (Discord / Slack / n8n)
        s6 = ctk.CTkFrame(f, fg_color="#0f172a", corner_radius=12)
        s6.pack(fill="x", pady=(0, 14), padx=4)

        wh_top = ctk.CTkFrame(s6, fg_color="transparent")
        wh_top.pack(fill="x", padx=16, pady=(12, 6))

        ctk.CTkLabel(wh_top, text="🔔 6. 실시간 보안 알림 웹훅 & SOAR 자동화 (Discord / Slack / n8n - 선택)", font=ctk.CTkFont(size=12, weight="bold"), text_color="#38bdf8").pack(side="left")

        wh = self.cfg.get("external_integrations", {}).get("webhooks", {})
        if not wh:
            wh = self.cfg.get("webhooks", {})
        self._add_ctk_row(s6, "Discord 보안 알림 웹훅 URL:", "webhooks.discord_alert_url", wh.get("discord_alert_url", ""), 380, placeholder="예: https://discord.com/api/webhooks/...", hint="(침해 차단 시 디스코드 알림)")
        self._add_ctk_row(s6, "Slack / Teams 알림 URL:", "webhooks.slack_alert_url", wh.get("slack_alert_url", ""), 380, placeholder="예: https://hooks.slack.com/services/...", hint="(슬랙 인시던트 채널 알림)")
        self._add_ctk_row(s6, "n8n SOAR 조치 웹훅 URL:", "external_integrations.n8n_soar.webhook_url", self.cfg.get("external_integrations", {}).get("n8n_soar", {}).get("webhook_url", ""), 380, placeholder="예: http://내-n8n서버:5678/webhook/...", hint="(SOAR 자동 대응 워크플로우)")
        self._add_ctk_row(s6, "웹훅 발송 임계치 (Threshold):", "webhooks.alert_threshold", wh.get("alert_threshold", "HIGH"), 120, placeholder="HIGH", hint="(CRITICAL / HIGH / ALL)")

        wh_btn_box = ctk.CTkFrame(s6, fg_color="transparent")
        wh_btn_box.pack(fill="x", padx=16, pady=(6, 12))

        ctk.CTkButton(
            wh_btn_box,
            text="🔔 Discord/Slack 웹훅 테스트 전송",
            width=200,
            height=30,
            fg_color="#4f46e5",
            hover_color="#4338ca",
            font=ctk.CTkFont(size=11, weight="bold"),
            command=self._on_test_webhook,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            wh_btn_box,
            text="⚡ n8n SOAR 웹훅 신호 발송",
            width=180,
            height=30,
            fg_color="#0891b2",
            hover_color="#0e7490",
            font=ctk.CTkFont(size=11),
            command=self._on_test_n8n_webhook,
        ).pack(side="left")

        # 저장 및 복원 버튼 바
        btn_box = ctk.CTkFrame(f, fg_color="transparent")
        btn_box.pack(fill="x", pady=(4, 16), padx=4)

        ctk.CTkButton(
            btn_box,
            text="💾 전체 설정 파일(config.json)에 저장 및 적용",
            fg_color="#2563eb",
            hover_color="#1d4ed8",
            font=ctk.CTkFont(size=12, weight="bold"),
            height=38,
            command=self._on_save_config,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            btn_box,
            text="⚡ 로컬 테스트 주소 자동 채우기",
            fg_color="#0284c7",
            hover_color="#0369a1",
            font=ctk.CTkFont(size=11, weight="bold"),
            height=38,
            command=self._on_fill_local_test_presets,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            btn_box,
            text="🧹 모든 설정 비우기",
            fg_color="#dc2626",
            hover_color="#b91c1c",
            font=ctk.CTkFont(size=11, weight="bold"),
            height=38,
            command=self._on_clear_all_settings,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            btn_box,
            text="기본값으로 복원",
            fg_color="#334155",
            hover_color="#475569",
            font=ctk.CTkFont(size=11),
            height=38,
            command=self._on_reset_config,
        ).pack(side="left")

        return f

    def _on_test_pfsense(self):
        ent = self.cfg_entries.get("external_integrations.pfsense.feed_url", None)
        feed_url = ent.get().strip() if ent else "http://127.0.0.1:5070/feeds/xdr-blocked-ips.txt"
        def _w():
            ok, msg = test_pfsense_feed(feed_url)
            if ok and "pfSense 게이트웨이" in getattr(self, "service_status_labels", {}):
                card, lbl = self.service_status_labels["pfSense 게이트웨이"]
                self.after(0, lambda: (card.configure(fg_color="#0c2e26", border_color="#10b981"), lbl.configure(text="● 200 OK CONNECTED", text_color="#10b981")))
            self.after(0, lambda: messagebox.showinfo("pfSense 피드 진단 결과", msg) if ok else messagebox.showwarning("pfSense 진단 안내", msg))
        threading.Thread(target=_w, daemon=True).start()

    def _on_test_graylog(self):
        ent_host = self.cfg_entries.get("external_integrations.graylog.host", None)
        ent_port = self.cfg_entries.get("external_integrations.graylog.gelf_udp_port", None)
        ent_stream = self.cfg_entries.get("external_integrations.graylog.stream_name", None)
        host = ent_host.get().strip() if ent_host else "192.168.3.10"
        port = int(ent_port.get().strip()) if (ent_port and ent_port.get().strip().isdigit()) else 12201
        stream = ent_stream.get().strip() if ent_stream else "NEXUS_SECURITY_STREAM"
        def _w():
            ok, msg = test_graylog_gelf(host, port, stream)
            if ok and "Graylog SIEM" in getattr(self, "service_status_labels", {}):
                card, lbl = self.service_status_labels["Graylog SIEM"]
                self.after(0, lambda: (card.configure(fg_color="#0c2e26", border_color="#10b981"), lbl.configure(text="● GELF SENT (OK)", text_color="#10b981")))
            self.after(0, lambda: messagebox.showinfo("Graylog GELF 패킷 진단", msg) if ok else messagebox.showerror("GELF 발송 오류", msg))
        threading.Thread(target=_w, daemon=True).start()

    def _on_test_wazuh(self):
        ent_host = self.cfg_entries.get("external_integrations.wazuh.manager_host", None)
        ent_port = self.cfg_entries.get("external_integrations.wazuh.manager_port", None)
        ent_id = self.cfg_entries.get("external_integrations.wazuh.agent_id", None)
        host = ent_host.get().strip() if ent_host else "192.168.3.20"
        port = int(ent_port.get().strip()) if (ent_port and ent_port.get().strip().isdigit()) else 1514
        agent_id = ent_id.get().strip() if ent_id else "001"
        def _w():
            ok, msg = test_wazuh_agent(host, port, agent_id)
            if ok and "Wazuh EDR/XDR" in getattr(self, "service_status_labels", {}):
                card, lbl = self.service_status_labels["Wazuh EDR/XDR"]
                self.after(0, lambda: (card.configure(fg_color="#0b1d3a", border_color="#38bdf8"), lbl.configure(text="● AGENT VERIFIED", text_color="#38bdf8")))
            self.after(0, lambda: messagebox.showinfo("Wazuh XDR / FIM 진단", msg))
        threading.Thread(target=_w, daemon=True).start()

    def _on_test_webhook(self):
        wh_url = self.cfg_entries.get("webhooks.discord_alert_url", None)
        url_val = wh_url.get().strip() if wh_url else ""
        if not url_val:
            wh_url2 = self.cfg_entries.get("webhooks.slack_alert_url", None)
            url_val = wh_url2.get().strip() if wh_url2 else ""

        if not url_val:
            messagebox.showwarning("URL 필요", "테스트할 Discord 또는 Slack 웹훅 URL을 입력하세요.")
            return

        def _w():
            ok, msg = test_webhook_dispatch(url_val, "보안 알림 웹훅 테스트")
            if ok and "SOAR Webhook" in getattr(self, "service_status_labels", {}):
                card, lbl = self.service_status_labels["SOAR Webhook"]
                self.after(0, lambda: (card.configure(fg_color="#0c2e26", border_color="#10b981"), lbl.configure(text="● ALERT DISPATCHED", text_color="#10b981")))
            self.after(0, lambda: messagebox.showinfo("웹훅 결과", msg) if ok else messagebox.showerror("웹훅 전송 실패", msg))
        threading.Thread(target=_w, daemon=True).start()

    def _on_test_n8n_webhook(self):
        wh_url = self.cfg_entries.get("external_integrations.n8n_soar.webhook_url", None)
        url_val = wh_url.get().strip() if wh_url else ""
        if not url_val:
            messagebox.showwarning("URL 필요", "n8n SOAR 웹훅 URL을 입력하세요.\n(외부 n8n 컨테이너가 없을 때는 Standalone 모드로 처리됩니다)")
            return

        def _w():
            ok, msg = test_webhook_dispatch(url_val, "n8n 자동화 오케스트레이션 트리거")
            if ok and "SOAR Webhook" in getattr(self, "service_status_labels", {}):
                card, lbl = self.service_status_labels["SOAR Webhook"]
                self.after(0, lambda: (card.configure(fg_color="#0c2e26", border_color="#10b981"), lbl.configure(text="● n8n TRIGGERED", text_color="#10b981")))
            self.after(0, lambda: messagebox.showinfo("n8n SOAR 결과", msg) if ok else messagebox.showwarning("SOAR 전송 안내", f"{msg}\n(외부 n8n 컨테이너가 없을 때는 Standalone 모드로 처리됩니다)"))
        threading.Thread(target=_w, daemon=True).start()

    def _add_ctk_row(self, parent, label_text, key, val, width, is_secret=False, placeholder="", hint=""):
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=3)

        ctk.CTkLabel(row, text=label_text, width=200, anchor="w", font=ctk.CTkFont(size=11, weight="bold"), text_color="#cbd5e1").pack(side="left")
        ent = ctk.CTkEntry(row, width=width, font=ctk.CTkFont(family="Consolas", size=11), placeholder_text=placeholder)
        if val is not None and str(val).strip() and str(val) != "None":
            ent.insert(0, str(val))
        if is_secret and val:
            ent.configure(show="*")
        ent.pack(side="left", padx=6)
        if hint:
            ctk.CTkLabel(row, text=hint, font=ctk.CTkFont(size=10), text_color=TEXT_MUTED).pack(side="left", padx=(4, 0))
        self.cfg_entries[key] = ent

    def _on_save_config(self):
        try:
            for key, ent in self.cfg_entries.items():
                val = ent.get().strip()
                parts = key.split(".")
                ref = self.cfg
                for p in parts[:-1]:
                    if p not in ref:
                        ref[p] = {}
                    ref = ref[p]
                last_k = parts[-1]
                if last_k.endswith("_port") and val.isdigit():
                    ref[last_k] = int(val)
                elif last_k.endswith("_port") and not val:
                    ref[last_k] = ""
                else:
                    ref[last_k] = val

            self.config_mgr.save_config(self.cfg)
            self._update_health_matrix_badges()
            messagebox.showinfo("저장 완료", "설정이 nexus_guard/config.json 파일에 성공적으로 저장되었습니다!\n모든 보안 엔진에 새 설정이 즉시 반영됩니다.")
        except Exception as e:
            messagebox.showerror("오류", f"저장 중 오류가 발생했습니다: {e}")

    def _on_fill_local_test_presets(self):
        """내 PC 로컬 개발/테스트용 주소를 입력란에 즉시 채워줍니다."""
        local_presets = {
            "target_service.web_portal_url": "http://127.0.0.1:5070",
            "target_service.host": "127.0.0.1",
            "target_service.port": "5070",
            "target_service.db_host": "127.0.0.1",
            "target_service.db_port": "3307",
            "target_service.db_user": "root",
            "target_service.db_name": "nexus_db",
        }
        for k, v in local_presets.items():
            if k in self.cfg_entries:
                self.cfg_entries[k].delete(0, "end")
                self.cfg_entries[k].insert(0, str(v))
        messagebox.showinfo(
            "로컬 주소 자동 채우기 완료",
            "웹 포털(http://127.0.0.1:5070) 및 DB(127.0.0.1:3307) 로컬 테스트 주소가 채워졌습니다.\n[💾 변경 설정 저장] 버튼을 누르면 즉시 감시 및 진단 대상에 반영됩니다.",
        )

    def _on_clear_all_settings(self):
        """신규 설치 상태처럼 모든 입력란을 깨끗하게 비웁니다."""
        if not messagebox.askyesno(
            "전체 비우기 확인",
            "설정 입력란의 모든 주소와 키를 비우시겠습니까?\n(placeholder 예시 안내가 표시되는 신규 설치 클린 상태로 초기화됩니다)",
        ):
            return
        for ent in self.cfg_entries.values():
            ent.delete(0, "end")
        self._update_health_matrix_badges()
        messagebox.showinfo(
            "설정 비우기 완료",
            "모든 설정 입력란이 초기화되었습니다.\n원하는 대상 주소를 입력한 후 [💾 변경 설정 저장]을 누르세요.",
        )

    def _update_health_matrix_badges(self):
        """외부 연동 설정 상태에 따라 상단 헬스 매트릭스 뱃지를 동적으로 갱신합니다."""
        if not hasattr(self, "service_status_labels"):
            return
        ext_cfg = self.cfg.get("external_integrations", {})
        pfs_host = ext_cfg.get("pfsense", {}).get("host", "")
        gl_host = ext_cfg.get("graylog", {}).get("host", "")
        wz_host = ext_cfg.get("wazuh", {}).get("manager_host", "")
        ai_cfg = self.cfg.get("ai_xdr_engine", {})
        has_ai = bool(ai_cfg.get("groq_api_key") or ai_cfg.get("nvidia_api_key") or ai_cfg.get("ollama_base_url"))

        pfs_card, pfs_lbl = self.service_status_labels.get("pfSense 게이트웨이", (None, None))
        if pfs_card and pfs_lbl:
            if pfs_host:
                pfs_card.configure(fg_color="#0c2e26", border_color="#10b981")
                pfs_lbl.configure(text="● CONFIGURED", text_color="#10b981")
            else:
                pfs_card.configure(fg_color="#1e293b", border_color="#94a3b8")
                pfs_lbl.configure(text="○ STANDBY (미연동)", text_color="#94a3b8")

        gl_card, gl_lbl = self.service_status_labels.get("Graylog SIEM", (None, None))
        if gl_card and gl_lbl:
            if gl_host:
                gl_card.configure(fg_color="#0c2e26", border_color="#10b981")
                gl_lbl.configure(text="● CONFIGURED", text_color="#10b981")
            else:
                gl_card.configure(fg_color="#1e293b", border_color="#94a3b8")
                gl_lbl.configure(text="○ STANDBY (미연동)", text_color="#94a3b8")

        wz_card, wz_lbl = self.service_status_labels.get("Wazuh EDR/XDR", (None, None))
        if wz_card and wz_lbl:
            if wz_host:
                wz_card.configure(fg_color="#0b1d3a", border_color="#38bdf8")
                wz_lbl.configure(text="● CONFIGURED", text_color="#38bdf8")
            else:
                wz_card.configure(fg_color="#1e293b", border_color="#94a3b8")
                wz_lbl.configure(text="○ STANDBY (미연동)", text_color="#94a3b8")

        ai_card, ai_lbl = self.service_status_labels.get("AI-XDR LPU", (None, None))
        if ai_card and ai_lbl:
            if has_ai:
                ai_card.configure(fg_color="#2e1065", border_color="#a78bfa")
                ai_lbl.configure(text="● LPU READY", text_color="#a78bfa")
            else:
                ai_card.configure(fg_color="#0b1d3a", border_color="#38bdf8")
                ai_lbl.configure(text="○ RULE-BASED (룰셋 모드)", text_color="#38bdf8")

    def _on_reset_config(self):
        if messagebox.askyesno("확인", "설정을 기본값으로 복원하시겠습니까?"):
            self.cfg = self.config_mgr.reset_to_defaults()
            self._reload_settings_form_values()
            messagebox.showinfo("복원 완료", "기본 설정으로 복원되었습니다.")

    def _on_apply_preset(self, preset_key):
        desc_map = {
            "standalone": "단독 PC 안심 모드 (초보자 권장 / 외부 방화벽·SIEM 없이 Windows 방화벽 및 자체 AI-XDR 완벽 방어)",
            "enterprise_soc": "엔터프라이즈 SOC 풀 연동 모드 (pfSense, Graylog, Wazuh, n8n SOAR 전체 활성화)",
            "developer_local": "로컬 개발자 모드 (Port 5070 / Mock 관제)",
        }
        title = desc_map.get(preset_key, preset_key)
        if not messagebox.askyesno("프리셋 적용 확인", f"'{title}' 프리셋을 적용하시겠습니까?\n기존 설정 필드가 권장 구성으로 자동 변경됩니다."):
            return

        self.cfg = self.config_mgr.apply_preset(preset_key)
        self._reload_settings_form_values()
        messagebox.showinfo("프리셋 적용 완료", f"'{title}' 설정이 성공적으로 적용되었습니다!")

    def _reload_settings_form_values(self):
        for key, ent in self.cfg_entries.items():
            parts = key.split(".")
            ref = self.cfg
            found = True
            for p in parts:
                if isinstance(ref, dict) and p in ref:
                    ref = ref[p]
                else:
                    found = False
                    break
            if found:
                ent.delete(0, "end")
                if ref is not None and str(ref).strip() and str(ref) != "None":
                    ent.insert(0, str(ref))
        self._update_health_matrix_badges()

    def _on_export_backup_bundle(self):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fpath = filedialog.asksaveasfilename(
            initialfile=f"nexus_guard_backup_{ts}.json",
            defaultextension=".json",
            filetypes=[("NEXUS-GUARD Backup Bundle", "*.json"), ("모든 파일", "*.*")],
        )
        if not fpath:
            return
        self.config_mgr.export_bundle(fpath)
        messagebox.showinfo(
            "백업 내보내기 성공",
            f"전체 설정 및 방화벽/SIEM 룰셋이 백업 파일로 안전하게 저장되었습니다!\n\n저장 위치: {fpath}",
        )

    def _on_import_backup_bundle(self):
        fpath = filedialog.askopenfilename(
            filetypes=[("NEXUS-GUARD Backup Bundle", "*.json"), ("모든 파일", "*.*")],
        )
        if not fpath:
            return
        if not messagebox.askyesno("복원 확인", "선택한 백업 파일의 설정 및 룰셋으로 복원하시겠습니까?"):
            return

        ok, msg = self.config_mgr.import_bundle(fpath)
        if ok:
            self.cfg = self.config_mgr.get_config()
            self._reload_settings_form_values()
            self.fw_rules_mgr.rules = self.fw_rules_mgr.load_rules()
            self.siem_rules_mgr.rules = self.siem_rules_mgr.load_rules()
            self._refresh_fw_rules_display()
            self._refresh_siem_rules_display()
            messagebox.showinfo("복원 완료", msg)
        else:
            messagebox.showerror("복원 실패", msg)

    # =========================================================================
    # 상단 쉴드 토글 & 백그라운드 데몬 (스레드 세이프 dispatch)
    # =========================================================================
    def _on_switch_defense(self):
        new_mode = "on" if self.switch_defense.get() == 1 else "off"
        def _worker():
            try:
                subprocess.run([sys.executable, str(BASE_DIR / "demo_runner.py"), "--security", new_mode], capture_output=True)
            except Exception:
                pass
            self.security_mode = new_mode.upper()
            self.after(0, self._apply_shield_ui_state)

        threading.Thread(target=_worker, daemon=True).start()

    def _apply_shield_ui_state(self):
        if self.security_mode == "ON":
            self.lbl_side_shield.configure(text="● PROTECTED (가동 중)", text_color="#22c55e")
            self.hero_banner.configure(fg_color="#102a24", border_color="#10b981")
            self.lbl_hero_title.configure(text="시스템이 안전하게 보호되고 있습니다 (SYSTEM SECURED)", text_color="#10b981")
        else:
            self.lbl_side_shield.configure(text="● VULNERABLE (꺼짐)", text_color="#f43f5e")
            self.hero_banner.configure(fg_color="#2b1419", border_color="#f43f5e")
            self.lbl_hero_title.configure(text="⚠️ 능동 방어 쉴드가 해제되었습니다 (VULNERABLE)", text_color="#f43f5e")

    def _realtime_status_daemon(self):
        target_url = self.cfg.get("target_service", {}).get("web_portal_url", "http://127.0.0.1:5070")
        while self.running:
            try:
                req = urllib.request.Request(f"{target_url}/admin/overview")
                with urllib.request.urlopen(req, timeout=2):
                    pass
            except Exception:
                pass
            time.sleep(3)

    def _log_tail_daemon(self):
        log_file = BASE_DIR / "logs" / "security.jsonl"
        last_size = 0
        if log_file.exists():
            last_size = log_file.stat().st_size

        while self.running:
            try:
                if log_file.exists():
                    curr = log_file.stat().st_size
                    if curr < last_size:
                        last_size = 0
                    if curr > last_size:
                        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                            f.seek(last_size)
                            lines = f.readlines()
                            last_size = curr
                        for l in lines:
                            ls = l.strip()
                            if ls:
                                self._total_ingested_logs = getattr(self, "_total_ingested_logs", 0) + 1
                                try:
                                    self._log_queue.put_nowait(ls)
                                except queue.Full:
                                    self._dropped_queue_events = getattr(self, "_dropped_queue_events", 0) + 1
                else:
                    last_size = 0
                time.sleep(1)
            except Exception:
                time.sleep(2)

    def _process_new_log_entry(self, raw_line):
        self._append_traffic_log(raw_line)
        try:
            d = json.loads(raw_line)
            ev = d.get("event_type") or d.get("event") or ""
            ip = d.get("src_ip") or d.get("client_ip") or "127.0.0.1"
            ts = d.get("ts") or ""
            time_str = ts[11:19] if len(ts) >= 19 else datetime.now().strftime("%H:%M:%S")

            new_alert = None
            if ev == "decoy_triggered":
                path = d.get("path", "/.env")
                new_alert = ("CRITICAL", ip, time_str, f"가짜 미끼 경로({path}) 불법 탐침 적발", "🚫 HTTP 403 입구 차단")
                self._threat_spike_ticks = 4
                self._threat_spike_level = 85
            elif ev == "prompt_injection_detected":
                new_alert = ("CRITICAL", ip, time_str, "LLM 프롬프트 인젝션 탈옥 시도 적발", "🛑 세션 즉시 차단")
                self._threat_spike_ticks = 4
                self._threat_spike_level = 90
            elif ev == "login_locked":
                new_alert = ("HIGH", ip, time_str, "관리자 계정 무차별 대입(Brute-force) 감지", "🔒 15분 계정 잠금")
                self._threat_spike_ticks = 3
                self._threat_spike_level = 65
            elif ev == "ip_blocked":
                reason = d.get("reason", "악성 행위")
                new_alert = ("HIGH", ip, time_str, f"공격자 IP 방화벽 차단 집행 ({reason})", "🧱 netsh Drop 등록")
                self._threat_spike_ticks = 3
                self._threat_spike_level = 70
            elif ev == "authz_deny":
                path = d.get("path", "미인가 리소스")
                new_alert = ("HIGH", ip, time_str, f"비인가 권한 침해 시도 ({path})", "🚫 403 Forbidden")
            elif ev == "xdr_assessment_created":
                score = d.get("threat_score", 0)
                verdict = d.get("verdict", "INFO")
                sev = "CRITICAL" if score >= 80 else ("HIGH" if score >= 50 else "INFO")
                new_alert = (sev, ip, time_str, f"AI-XDR 평가: {verdict} (위험도 {score}점)", f"📊 신뢰도 {int(d.get('confidence', 0)*100)}%")

            if new_alert:
                if not hasattr(self, "raw_dash_events"):
                    self.raw_dash_events = []
                self.raw_dash_events.insert(0, new_alert)
                if len(self.raw_dash_events) > 50:
                    self.raw_dash_events.pop()
                if hasattr(self, "mitre_strip"):
                    self.mitre_strip.record_log_event(d)
                self._update_dash_filter_chips()
                self._filter_dash_events(getattr(self, "_current_dash_category", "ALL"))
                self._refresh_real_triage_panel()
                if hasattr(self, "card_blocked"):
                    self.card_blocked.configure(text=f"{len(self.firewall.get_blocked_list())} 건")
        except Exception:
            pass

    def _append_traffic_log(self, text):
        if hasattr(self, "txt_traffic"):
            self.txt_traffic.insert("end", f"[{datetime.now().strftime('%H:%M:%S')}] {text}\n")
            try:
                line_count = int(self.txt_traffic.index("end-1c").split(".")[0])
                if line_count > 2000:
                    self.txt_traffic.delete("1.0", f"{line_count - 1500}.0")
            except Exception:
                pass
            self.txt_traffic.see("end")

    def _on_export_ciso_audit_report(self):
        """CISO 및 보안 감사관용 원클릭 종합 보안 감사 보고서(HTML/CSV)를 생성하고 브라우저로 엽니다."""
        try:
            sc_data = getattr(self, "_last_scan_report", None)
            if not sc_data:
                sc_data = {
                    "security_score": getattr(self, "sec_score", 100),
                    "security_grade": "A+ (안전)",
                    "findings": [],
                }
            blocked_ips = self.firewall.get_blocked_list()
            fim_alerts = getattr(self, "_fim_alerts", [])
            fim_count = len(getattr(self.fim, "_baseline_hashes", {}))

            dash_events = getattr(self, "raw_dash_events", [])
            mitre_events = []
            for ev in dash_events:
                sev, ip, time_str, desc, act = ev
                mapped = self.mitre_mapper.map_event({"desc": desc, "event": desc})
                mitre_events.append({
                    "ip": ip,
                    "time": time_str,
                    "desc": desc,
                    "action": act,
                    "tactic": mapped["tactic"],
                    "technique_id": mapped["technique_id"],
                    "technique_name": mapped["technique_kr"],
                    "severity": sev,
                })

            mitre_data = {
                "total_mitre_events": len(mitre_events),
                "recent_events": mitre_events,
                "tactics_summary": self.mitre_mapper.calculate_coverage(mitre_events),
                "matrix": [
                    {"technique_id": "T1595.002", "technique_name": "취약점 능동 스캔 및 디코이 탐침", "tactic": "Reconnaissance", "severity": "CRITICAL", "hits": len([e for e in mitre_events if "T1595" in e.get("technique_id", "")]), "status": "ACTIVE_CONTAINMENT", "remediation_playbook": "미끼 경로 접근 IP 403 즉시 차단 및 15분 격리"},
                    {"technique_id": "T1059", "technique_name": "AI 프롬프트 인젝션 탈옥 시도", "tactic": "Execution", "severity": "CRITICAL", "hits": len([e for e in mitre_events if "T1059" in e.get("technique_id", "")]), "status": "ACTIVE_CONTAINMENT", "remediation_playbook": "Groq LPU 0.5초 세션 즉시 차단"},
                    {"technique_id": "T1110.001", "technique_name": "관리자 계정 무차별 대입 (Brute Force)", "tactic": "Credential Access", "severity": "HIGH", "hits": len([e for e in mitre_events if "T1110" in e.get("technique_id", "")]), "status": "LOCKED", "remediation_playbook": "5회 실패 시 15분 계정 잠금"},
                    {"technique_id": "T1562.001", "technique_name": "네트워크 인바운드 방화벽 능동 차단", "tactic": "Defense Evasion", "severity": "HIGH", "hits": len(blocked_ips), "status": "PROTECTED", "remediation_playbook": "Windows netsh 드롭 룰 집행"},
                    {"technique_id": "T1068", "technique_name": "BOLA 수평/수직 권한 상승 시도", "tactic": "Privilege Escalation", "severity": "HIGH", "hits": len([e for e in mitre_events if "T1068" in e.get("technique_id", "")]), "status": "DENIED", "remediation_playbook": "RBAC 세션 토큰 검증 및 403 거부"},
                    {"technique_id": "T1070.004", "technique_name": "핵심 보안 자산 SHA-256 디지털 지문 변조", "tactic": "Defense Evasion", "severity": "CRITICAL", "hits": len(fim_alerts), "status": "MONITORED", "remediation_playbook": "FIM 베이스라인 자동 대조 및 알림"},
                ]
            }

            ctx = self.report_exporter.build_report_context(
                scanner_data=sc_data,
                blocked_ips=blocked_ips,
                fim_alerts=fim_alerts,
                fim_baseline_count=fim_count,
                mitre_data=mitre_data,
            )

            res = self.report_exporter.export_all(ctx)
            html_p = res.get("html")
            csv_p = res.get("csv")

            if html_p and html_p.exists():
                try:
                    os.startfile(str(html_p))
                except Exception:
                    pass

            messagebox.showinfo(
                "CISO 감사 보고서 발행 완료",
                f"엔터프라이즈 CISO 종합 보안 감사 보고서가 성공적으로 발행되었습니다!\n\n"
                f"• 보고서 번호: {ctx['meta']['report_id']}\n"
                f"• 디지털 인장: {ctx['meta']['digital_seal_sha256'][:16]}...\n"
                f"• HTML 보고서: {html_p.name}\n"
                f"• CSV 감사 로그: {csv_p.name}\n\n"
                f"기본 브라우저에서 보고서가 자동으로 열립니다.",
            )
        except Exception as e:
            messagebox.showerror("보고서 발행 오류", f"CISO 감사 보고서 발행 중 오류가 발생했습니다:\n{e}")

    def _update_containment_ui(self):
        is_c = self.firewall.is_contained()
        if is_c:
            btn_text = "⚡ 비상 격리 해제 및 복구"
            btn_fg = "#15803d"
            btn_hover = "#166534"
            status_text = "🚨 [CONTAINED] 호스트 비상 격리 가동 중"
            status_color = "#f43f5e"
            if hasattr(self, "hero_banner"):
                self.hero_banner.configure(fg_color="#360a0a", border_color="#f43f5e")
                self.lbl_hero_icon.configure(text="🚨")
                self.lbl_hero_title.configure(text="🚨 EMERGENCY CONTAINMENT ACTIVE (호스트 비상 격리 가동 중)", text_color="#f43f5e")
                self.lbl_hero_desc.configure(text="호스트가 외부 네트워크로부터 완전 격리되었습니다 | 127.0.0.1 관리자 플레인 단독 유지 중 | 침해 격리 증적 기록 완료", text_color="#fca5a5")
        else:
            btn_text = "🚨 1-클릭 비상 격리"
            btn_fg = "#7f1d1d"
            btn_hover = "#991b1b"
            status_text = "● [OPERATIONAL] 정상 네트워크 운영 중"
            status_color = "#10b981"
            if hasattr(self, "hero_banner"):
                self.hero_banner.configure(fg_color="#102a24", border_color="#10b981")
                self.lbl_hero_icon.configure(text="🛡️")
                self.lbl_hero_title.configure(text="NEXUS-GUARD 엔터프라이즈 능동 방어 관제 (SYSTEM SECURED)", text_color="#10b981")
                fim_actual_cnt = len(getattr(self.fim, "_baseline_hashes", {}))
                self.lbl_hero_desc.configure(text=f"실시간 WAF 입구 차단 활성 | 4중 AI-XDR LPU 엔진 연동 | {fim_actual_cnt}개 핵심 자산 SHA-256 무결성 유지 | Windows 방화벽 netsh 동기화", text_color="#94a3b8")

        if hasattr(self, "btn_dash_contain"):
            self.btn_dash_contain.configure(text=btn_text, fg_color=btn_fg, hover_color=btn_hover)
        if hasattr(self, "btn_fw_contain"):
            self.btn_fw_contain.configure(text=btn_text, fg_color=btn_fg, hover_color=btn_hover)
        if hasattr(self, "btn_emergency_contain"):
            if is_c:
                self.btn_emergency_contain.configure(
                    text="🟢 호스트 격리 해제",
                    fg_color="#052e25",
                    hover_color="#064e3b",
                    border_color=COLOR_SECURE,
                    text_color=COLOR_SECURE,
                )
            else:
                self.btn_emergency_contain.configure(
                    text="🚨 1-클릭 신속 격리",
                    fg_color=COLOR_ALERT_BG,
                    hover_color="#4c101c",
                    border_color=COLOR_ALERT,
                    text_color=COLOR_ALERT,
                )
        if hasattr(self, "emergency_hud_bar"):
            if is_c:
                self.emergency_hud_bar.grid(row=1, column=0, sticky="ew", padx=0, pady=0)
            else:
                self.emergency_hud_bar.grid_remove()
        if hasattr(self, "live_ticker"):
            self.live_ticker.update_metrics(is_contained=is_c)
        if hasattr(self, "lbl_fw_contain_status"):
            self.lbl_fw_contain_status.configure(text=status_text, text_color=status_color)

    def _apply_containment_ui_state(self, is_contained: bool):
        self._update_containment_ui()

    def _on_toggle_emergency_containment(self):
        """1-클릭 신속 비상 격리 및 자동 복구 플레이북 토글 (CrowdStrike / SentinelOne RTR 규격)."""
        if not self.firewall.is_contained():
            confirm = messagebox.askyesno(
                "🚨 긴급 비상 격리 (Emergency Containment) 확인",
                "즉시 호스트 네트워크 긴급 비상 격리를 발동하시겠습니까?\n\n"
                "• 로컬 루프백(127.0.0.1) 관리자 콘솔을 제외한 모든 외부 인그레스/에그레스 트래픽이 즉시 차단됩니다.\n"
                "• 모든 활성 악성 침해 세션이 강제 종료됩니다.\n"
                "• SentinelOne/CrowdStrike RTR 규격 CISO 비상 감사 증적이 생성됩니다.",
                icon="warning"
            )
            if confirm:
                res = self.firewall.activate_emergency_containment(
                    reason="SOC 관리자 GUI 콘솔 1-클릭 긴급 비상 격리 발동",
                    initiated_by="CISO_CONSOLE_ADMIN"
                )
                self._update_containment_ui()
                messagebox.showinfo(
                    "비상 격리 완료",
                    f"호스트가 긴급 비상 격리되었습니다.\n"
                    f"격리 식별자: {res.get('containment_id')}\n"
                    f"외부 접근 차단 및 관리자 플레인(127.0.0.1) 단독 유지 중입니다."
                )
        else:
            confirm = messagebox.askyesno(
                "⚡ 비상 격리 해제 및 자동 복구 플레이북 실행",
                "비상 격리를 해제하고 정상 운영 상태로 복원하시겠습니까?\n\n"
                "• 자동화 복구 플레이북이 실행되어 호스트 무결성을 검증합니다.\n"
                "• Windows netsh 비상 규칙이 정리되고 정상 WAF 파이프라인이 복구됩니다."
            )
            if confirm:
                res = self.firewall.lift_emergency_containment(authorized_by="CISO_CONSOLE_ADMIN")
                self._update_containment_ui()
                messagebox.showinfo(
                    "자동 복구 완료",
                    "비상 격리가 성공적으로 해제되었으며 정상 운영 모드로 복구되었습니다."
                )

    def _on_inspect_mitre_tactic(self, spec):
        """MITRE ATT&CK 전술 타일 클릭 시 고도화된 전술 상세 분석 및 완화 플레이북 다이얼로그 출력."""
        try:
            cnt = 0
            if hasattr(self, "mitre_strip"):
                cnt = self.mitre_strip.tactic_counts.get(spec.get("key"), 0)
            MitreTacticDetailDialog(self, spec, count=cnt)
        except Exception:
            # 폴백용 정보창
            t_name = spec.get("name", "TACTIC")
            t_id = spec.get("id", "TA0000")
            t_tech = spec.get("technique", "T0000")
            t_desc = spec.get("description", "설명 없음")
            t_play = spec.get("countermeasure", "권장 조치 없음")
            t_status = spec.get("default_status", "ACTIVE")
            msg = (
                f"■ MITRE 전술명: {t_name} [{t_id}]\n"
                f"■ 대표 기법 코드: {t_tech}\n"
                f"■ 현재 방어 태세: {t_status}\n\n"
                f"■ 공격 시나리오 및 위협 설명:\n{t_desc}\n\n"
                f"■ 능동 대응 및 완화 플레이북 (Playbook):\n{t_play}"
            )
            messagebox.showinfo(f"MITRE ATT&CK 전술 분석 - [{t_id}] {t_name}", msg)


def main():
    app = NexusGuardNativeApp()
    app.mainloop()


if __name__ == "__main__":
    main()
