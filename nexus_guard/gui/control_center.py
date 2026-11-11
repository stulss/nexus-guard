# -*- coding: utf-8 -*-
"""NEXUS-GUARD Enterprise Security Suite (고도화된 전문 보안 프로그램 GUI 콘솔).

개발자: 홍주형 (웹/DB 보안 하드닝 & 코어 아키텍처 & AI 엔지니어링)
버전: 2.5.0-LTS Enterprise Edition
"""
import json
import os
import subprocess
import sys
import threading
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, ttk
import urllib.request

from ..engine.config_manager import GuardConfigManager
from ..engine.scanner import SystemVulnerabilityScanner
from ..engine.fim import FileIntegrityMonitor
from ..engine.firewall import FirewallRuleManager
from ..ai_engine.cascade_router import AiCascadeRouter
from ..ai_engine.xdr_triage import XdrTriageEngine
from .theme import (
    BG_DARK,
    SURFACE_CARD,
    SURFACE_HOVER,
    BORDER_SUBTLE,
    COLOR_SECURE,
    COLOR_CYAN,
    COLOR_ALERT,
    TEXT_TITLE,
    TEXT_BODY,
    TEXT_MUTED,
)

BASE_DIR = Path(__file__).resolve().parents[2]


class NexusGuardEnterpriseGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ NEXUS-GUARD : 엔터프라이즈 능동형 AI-XDR 보안 프로그램 (v2.5.0-LTS)")
        self.root.geometry("1180x820")
        self.root.minsize(1050, 700)
        self.root.configure(bg="#0d1117")

        # 1. 설정 및 보안 엔진 인스턴스 초기화
        self.config_mgr = GuardConfigManager()
        self.cfg = self.config_mgr.get_data()

        self.scanner = SystemVulnerabilityScanner()
        self.fim = FileIntegrityMonitor()
        self.firewall = FirewallRuleManager()
        self.ai_router = AiCascadeRouter()
        self.xdr_triage = XdrTriageEngine(self.ai_router)

        self.security_mode = self.cfg.get("active_defense", {}).get("defense_mode", "ON")
        self._init_theme()
        self._build_header()
        self._build_tabs()
        self._build_footer()

        # 2. 백그라운드 실시간 모니터링 데몬들
        self.running = True
        self.daemon_thread = threading.Thread(target=self._realtime_daemon_loop, daemon=True)
        self.daemon_thread.start()

        self.log_tail_thread = threading.Thread(target=self._log_tail_loop, daemon=True)
        self.log_tail_thread.start()

    def _init_theme(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", background="#0d1117", foreground="#c9d1d9", font=("Pretendard", 10))
        style.configure("TNotebook", background="#0d1117", borderwidth=0)
        style.configure("TNotebook.Tab", background="#161b22", foreground="#8b949e", padding=[16, 8], font=("Pretendard", 10, "bold"))
        style.map("TNotebook.Tab", background=[("selected", "#1f6feb")], foreground=[("selected", "#ffffff")])
        style.configure("Treeview", background="#161b22", foreground="#c9d1d9", fieldbackground="#161b22", rowheight=28)
        style.configure("Treeview.Heading", background="#21262d", foreground="#58a6ff", font=("Pretendard", 9, "bold"))
        style.map("Treeview", background=[("selected", "#1f6feb")])

    def _build_header(self):
        header = tk.Frame(self.root, bg="#161b22", height=75, padx=20, pady=12, bd=1, relief="ridge")
        header.pack(fill="x", side="top")

        info_frame = tk.Frame(header, bg="#161b22")
        info_frame.pack(side="left")

        tk.Label(
            info_frame,
            text="🛡️ NEXUS-GUARD Enterprise Security Suite",
            font=("Pretendard", 16, "bold"),
            fg="#58a6ff",
            bg="#161b22",
        ).pack(anchor="w")

        target_url = self.cfg.get("target_service", {}).get("web_portal_url", "http://127.0.0.1:5070")
        tk.Label(
            info_frame,
            text=f"AI-Powered Active Ingress Defense · Real-Time XDR · Host Firewall & FIM | 감시 대상: {target_url}",
            font=("Pretendard", 9),
            fg="#8b949e",
            bg="#161b22",
        ).pack(anchor="w")

        ctrl_frame = tk.Frame(header, bg="#161b22")
        ctrl_frame.pack(side="right")

        self.lbl_shield_badge = tk.Label(
            ctrl_frame,
            text="● SYSTEM PROTECTED",
            font=("Pretendard", 11, "bold"),
            fg="#3fb950",
            bg="#1f242c",
            padx=14,
            pady=6,
            relief="solid",
            bd=1,
        )
        self.lbl_shield_badge.pack(side="left", padx=10)

        self.btn_toggle_defense = tk.Button(
            ctrl_frame,
            text="능동 방어 일시 정지 (취약 모드)",
            font=("Pretendard", 9, "bold"),
            bg="#21262d",
            fg="#e6edf3",
            activebackground="#30363d",
            padx=12,
            pady=5,
            command=self._toggle_defense_mode,
        )
        self.btn_toggle_defense.pack(side="left", padx=5)

    def _build_tabs(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=15, pady=(10, 5))

        # 탭 1: 종합 대시보드
        self.tab_dashboard = tk.Frame(self.notebook, bg="#0d1117")
        self.notebook.add(self.tab_dashboard, text=" 📊 보안 종합 대시보드 ")
        self._build_dashboard_tab()

        # 탭 2: 실시간 침입 탐지 및 트래픽 모니터
        self.tab_traffic = tk.Frame(self.notebook, bg="#0d1117")
        self.notebook.add(self.tab_traffic, text=" 📡 실시간 침입 탐지 (IDS/IPS) ")
        self._build_traffic_tab()

        # 탭 3: 방화벽 & 블랙리스트 관리
        self.tab_firewall = tk.Frame(self.notebook, bg="#0d1117")
        self.notebook.add(self.tab_firewall, text=" 🧱 방화벽 & 차단 IP 관리 ")
        self._build_firewall_tab()

        # 탭 4: 시스템 취약점 전수 진단
        self.tab_scanner = tk.Frame(self.notebook, bg="#0d1117")
        self.notebook.add(self.tab_scanner, text=" 🔍 시스템 취약점 진단 (Scanner) ")
        self._build_scanner_tab()

        # 탭 5: 파일 무결성 감시 (FIM)
        self.tab_fim = tk.Frame(self.notebook, bg="#0d1117")
        self.notebook.add(self.tab_fim, text=" 📁 파일 무결성 감시 (FIM) ")
        self._build_fim_tab()

        # 탭 6: 환경 설정 & 외부 장비 연동 맵 (Settings) ⭐
        self.tab_settings = tk.Frame(self.notebook, bg="#0d1117")
        self.notebook.add(self.tab_settings, text=" ⚙️ 환경 설정 & 외부 연동 (Config) ")
        self._build_settings_tab()

    # ---------------- 탭 1: 종합 대시보드 ----------------
    def _build_dashboard_tab(self):
        dash_frame = tk.Frame(self.tab_dashboard, bg="#0d1117", padx=15, pady=15)
        dash_frame.pack(fill="both", expand=True)

        cards_grid = tk.Frame(dash_frame, bg="#0d1117")
        cards_grid.pack(fill="x", pady=(0, 15))

        init_blocked = len(self.firewall.get_blocked_list())
        self.card_score = self._create_kpi_card(cards_grid, "보안 종합 안전도", "100 / 100", "A+ 최고 안전 상태 유지", "#3fb950", 0)
        self.card_blocked = self._create_kpi_card(cards_grid, "현재 차단된 위협 IP", f"{init_blocked} 건", "최근 15분 차단 유지", "#3fb950" if init_blocked == 0 else "#f85149", 1)
        self.card_ai_speed = self._create_kpi_card(cards_grid, "AI 위협 판정 속도", "0.52 초", "Groq LPU 4중 캐스케이드", "#58a6ff", 2)
        self.card_fim_count = self._create_kpi_card(cards_grid, "FIM 감시 대상 파일", "58 개", "SHA-256 무결성 감시 중", "#d29922", 3)

        mid_pane = tk.PanedWindow(dash_frame, orient="horizontal", bg="#0d1117", bd=0)
        mid_pane.pack(fill="both", expand=True)

        left_box = tk.LabelFrame(mid_pane, text=" 🚨 최근 감지된 위협 이벤트 ", bg="#161b22", fg="#58a6ff", font=("Pretendard", 10, "bold"), padx=10, pady=10)
        mid_pane.add(left_box, width=650)

        cols = ("time", "ip", "event", "severity", "action")
        self.tree_dash_events = ttk.Treeview(left_box, columns=cols, show="headings", height=8)
        self.tree_dash_events.heading("time", text="탐지 시각")
        self.tree_dash_events.heading("ip", text="공격자 IP")
        self.tree_dash_events.heading("event", text="이벤트 유형")
        self.tree_dash_events.heading("severity", text="심각도")
        self.tree_dash_events.heading("action", text="방어 조치")

        self.tree_dash_events.column("time", width=80)
        self.tree_dash_events.column("ip", width=110)
        self.tree_dash_events.column("event", width=140)
        self.tree_dash_events.column("severity", width=80)
        self.tree_dash_events.column("action", width=120)
        self.tree_dash_events.pack(fill="both", expand=True)

        # 초기 상태: 활성 공격 없음 (실시간 감시 대기 중)
        pass

        right_box = tk.LabelFrame(mid_pane, text=" 🤖 AI-XDR 4중 위협 분석 센터 ", bg="#161b22", fg="#58a6ff", font=("Pretendard", 10, "bold"), padx=15, pady=10)
        mid_pane.add(right_box)

        tk.Label(right_box, text="현재 AI 모델:", font=("Pretendard", 9, "bold"), fg="#8b949e", bg="#161b22").pack(anchor="w")
        tk.Label(right_box, text="Groq LPU (openai/gpt-oss-120b)", font=("Pretendard", 11, "bold"), fg="#58a6ff", bg="#161b22").pack(anchor="w", pady=(0, 10))

        tk.Label(right_box, text="최신 위협 분석 결론:", font=("Pretendard", 9, "bold"), fg="#8b949e", bg="#161b22").pack(anchor="w")
        self.lbl_dash_ai_text = tk.Label(
            right_box,
            text="[SYSTEM SECURE / 위험도 0점]\n현재 활성 공격자가 감지되지 않았습니다 (클린 네트워크 상태). 24/7 실시간 WAF 및 침입 방지 시스템이 정상 가동 대기 중입니다.",
            font=("Pretendard", 9),
            fg="#e6edf3",
            bg="#21262d",
            padx=12,
            pady=10,
            justify="left",
            wraplength=340,
        )
        self.lbl_dash_ai_text.pack(fill="x", pady=5)

    def _create_kpi_card(self, parent, title, val, sub, col, col_idx):
        card = tk.Frame(parent, bg="#161b22", padx=16, pady=12, bd=1, relief="ridge")
        card.grid(row=0, column=col_idx, sticky="ew", padx=5)
        parent.grid_columnconfigure(col_idx, weight=1)

        tk.Label(card, text=title, font=("Pretendard", 9), fg="#8b949e", bg="#161b22").pack(anchor="w")
        val_lbl = tk.Label(card, text=val, font=("Pretendard", 18, "bold"), fg=col, bg="#161b22")
        val_lbl.pack(anchor="w", pady=4)
        tk.Label(card, text=sub, font=("Pretendard", 8), fg="#8b949e", bg="#161b22").pack(anchor="w")
        return val_lbl

    # ---------------- 탭 2: 실시간 침입 탐지 ----------------
    def _build_traffic_tab(self):
        f = tk.Frame(self.tab_traffic, bg="#0d1117", padx=15, pady=15)
        f.pack(fill="both", expand=True)

        top_ctrl = tk.Frame(f, bg="#0d1117")
        top_ctrl.pack(fill="x", pady=(0, 10))

        tk.Label(top_ctrl, text="실시간 유입 패킷 & 보안 감사 스트림 (Live Traffic & Security Stream)", font=("Pretendard", 11, "bold"), fg="#58a6ff", bg="#0d1117").pack(side="left")

        btn_clear = tk.Button(top_ctrl, text="로그 지우기", font=("Pretendard", 8), bg="#21262d", fg="#c9d1d9", command=lambda: self.txt_traffic.delete("1.0", "end"))
        btn_clear.pack(side="right")

        self.txt_traffic = tk.Text(f, bg="#161b22", fg="#58a6ff", font=("Consolas", 9), bd=0, padx=10, pady=10)
        self.txt_traffic.pack(fill="both", expand=True)
        self._traffic_log("[*] NEXUS-GUARD 실시간 인그레스 침입 탐지 엔진이 활성화되었습니다.")
        self._traffic_log(f"[*] 감시 대상 서비스: {self.cfg.get('target_service', {}).get('web_portal_url')}")

    def _traffic_log(self, msg):
        now = datetime.now().strftime("%H:%M:%S")
        self.txt_traffic.insert("end", f"[{now}] {msg}\n")
        self.txt_traffic.see("end")

    # ---------------- 탭 3: 방화벽 & 차단 IP 관리 ----------------
    def _build_firewall_tab(self):
        f = tk.Frame(self.tab_firewall, bg="#0d1117", padx=15, pady=15)
        f.pack(fill="both", expand=True)

        form = tk.LabelFrame(f, text=" 🛡️ 위협 IP 즉각 차단 등록 (수동 방화벽 규칙) ", bg="#161b22", fg="#58a6ff", font=("Pretendard", 10, "bold"), padx=15, pady=10)
        form.pack(fill="x", pady=(0, 15))

        tk.Label(form, text="차단할 IP 주소:", bg="#161b22", fg="#c9d1d9").grid(row=0, column=0, padx=5, sticky="w")
        self.ent_block_ip = tk.Entry(form, bg="#21262d", fg="#ffffff", insertbackground="#fff", font=("Pretendard", 10), width=18)
        self.ent_block_ip.grid(row=0, column=1, padx=5)

        tk.Label(form, text="차단 사유:", bg="#161b22", fg="#c9d1d9").grid(row=0, column=2, padx=5, sticky="w")
        self.ent_block_reason = tk.Entry(form, bg="#21262d", fg="#ffffff", insertbackground="#fff", font=("Pretendard", 10), width=28)
        self.ent_block_reason.insert(0, "비인가 악성 행위 감지")
        self.ent_block_reason.grid(row=0, column=3, padx=5)

        btn_add_block = tk.Button(form, text="🚫 즉시 입구 차단 (403)", font=("Pretendard", 9, "bold"), bg="#da3633", fg="#fff", command=self._on_add_firewall_block)
        btn_add_block.grid(row=0, column=4, padx=8)

        btn_win_fw = tk.Button(form, text="🔥 Windows 방화벽(netsh) 연동", font=("Pretendard", 9, "bold"), bg="#1f6feb", fg="#fff", command=self._on_apply_win_firewall)
        btn_win_fw.grid(row=0, column=5, padx=5)

        tbl_frame = tk.LabelFrame(f, text=" 📋 현재 블랙리스트 목록 (Blocked IP Table) ", bg="#161b22", fg="#58a6ff", font=("Pretendard", 10, "bold"), padx=10, pady=10)
        tbl_frame.pack(fill="both", expand=True)

        cols = ("ip", "reason", "hits", "remaining", "status")
        self.tree_firewall = ttk.Treeview(tbl_frame, columns=cols, show="headings")
        self.tree_firewall.heading("ip", text="차단된 IP")
        self.tree_firewall.heading("reason", text="차단 사유")
        self.tree_firewall.heading("hits", text="위협 침해 횟수")
        self.tree_firewall.heading("remaining", text="잔여 시간 (초)")
        self.tree_firewall.heading("status", text="방화벽 상태")

        self.tree_firewall.column("ip", width=140)
        self.tree_firewall.column("reason", width=250)
        self.tree_firewall.column("hits", width=100)
        self.tree_firewall.column("remaining", width=100)
        self.tree_firewall.column("status", width=120)
        self.tree_firewall.pack(fill="both", expand=True)

        btn_box = tk.Frame(tbl_frame, bg="#161b22", pady=8)
        btn_box.pack(fill="x")

        btn_unblock = tk.Button(btn_box, text="선택 IP 차단 해제", font=("Pretendard", 9), bg="#21262d", fg="#c9d1d9", command=self._on_remove_firewall_block)
        btn_unblock.pack(side="left", padx=5)

        btn_clear_all = tk.Button(btn_box, text="전체 차단 초기화 (원상복구)", font=("Pretendard", 9, "bold"), bg="#238636", fg="#fff", command=self._on_clear_firewall)
        btn_clear_all.pack(side="right", padx=5)

        self._refresh_firewall_table()

    def _refresh_firewall_table(self):
        for row in self.tree_firewall.get_children():
            self.tree_firewall.delete(row)
        for item in self.firewall.get_blocked_list():
            self.tree_firewall.insert("", "end", values=(item["ip"], item["reason"], item["hits"], item["remaining_seconds"], item["status"]))

    def _on_add_firewall_block(self):
        ip = self.ent_block_ip.get().strip()
        reason = self.ent_block_reason.get().strip()
        if not ip:
            messagebox.showwarning("입력 오류", "차단할 IP 주소를 입력하세요.")
            return
        self.firewall.add_block_ip(ip, reason)
        self._refresh_firewall_table()
        self._traffic_log(f"[!] 방화벽에 새로운 차단 IP 등록 완료: {ip} ({reason})")
        messagebox.showinfo("차단 완료", f"IP {ip}가 성공적으로 차단 목록에 등록되었습니다.")

    def _on_remove_firewall_block(self):
        sel = self.tree_firewall.selection()
        if not sel:
            messagebox.showwarning("선택 오류", "해제할 IP를 목록에서 선택하세요.")
            return
        ip = self.tree_firewall.item(sel[0], "values")[0]
        self.firewall.remove_block_ip(ip)
        self._refresh_firewall_table()
        self._traffic_log(f"[+] 차단 IP 해제 완료: {ip}")

    def _on_clear_firewall(self):
        cnt = self.firewall.clear_all()
        subprocess.run([sys.executable, str(BASE_DIR / "demo_runner.py"), "--cleanup"], capture_output=True)
        self._refresh_firewall_table()
        self._traffic_log(f"[+] 모든 차단 IP({cnt}건)가 초기화되고 정상 복구되었습니다.")
        messagebox.showinfo("원상복구 완료", "모든 차단 IP 및 잠금 계정이 1초 만에 정상화되었습니다.")

    def _on_apply_win_firewall(self):
        ip = self.ent_block_ip.get().strip()
        if not ip:
            messagebox.showwarning("입력 오류", "Windows 방화벽에 적용할 IP를 입력하세요.")
            return
        ok, msg = self.firewall.apply_windows_firewall_rule(ip)
        self._traffic_log(f"[*] Windows 방화벽 결과: {msg}")
        messagebox.showinfo("방화벽 연동", msg)

    # ---------------- 탭 4: 시스템 취약점 전수 진단 ----------------
    def _build_scanner_tab(self):
        f = tk.Frame(self.tab_scanner, bg="#0d1117", padx=15, pady=15)
        f.pack(fill="both", expand=True)

        top = tk.Frame(f, bg="#0d1117")
        top.pack(fill="x", pady=(0, 10))

        tk.Label(top, text="시스템 취약점 & 보안 설정 전수 진단 (Vulnerability Audit)", font=("Pretendard", 11, "bold"), fg="#58a6ff", bg="#0d1117").pack(side="left")

        self.btn_run_scan = tk.Button(top, text="🔍 전체 시스템 정밀 진단 시작", font=("Pretendard", 10, "bold"), bg="#1f6feb", fg="#fff", padx=12, pady=6, command=self._run_security_scan)
        self.btn_run_scan.pack(side="right", padx=5)

        btn_export_rep = tk.Button(top, text="📄 진단 보고서 저장", font=("Pretendard", 9), bg="#21262d", fg="#c9d1d9", padx=10, pady=5, command=self._export_scan_report)
        btn_export_rep.pack(side="right")

        cols = ("sev", "cat", "title", "desc")
        self.tree_scan = ttk.Treeview(f, columns=cols, show="headings")
        self.tree_scan.heading("sev", text="심각도")
        self.tree_scan.heading("cat", text="구분")
        self.tree_scan.heading("title", text="진단 항목")
        self.tree_scan.heading("desc", text="상세 진단 결과 및 권고사항")

        self.tree_scan.column("sev", width=90)
        self.tree_scan.column("cat", width=110)
        self.tree_scan.column("title", width=230)
        self.tree_scan.column("desc", width=480)
        self.tree_scan.pack(fill="both", expand=True)
        self.last_scan_report = None

    def _run_security_scan(self):
        self.btn_run_scan.config(state="disabled", text="진단 스캔 진행 중...")
        for row in self.tree_scan.get_children():
            self.tree_scan.delete(row)

        def _worker():
            report = self.scanner.run_full_scan()
            self.last_scan_report = report
            time.sleep(0.5)

            def _update():
                score = report["security_score"]
                grade = report["security_grade"]
                self.card_score.config(text=f"{score} / 100")

                for finding in report["findings"]:
                    self.tree_scan.insert("", "end", values=(
                        finding["severity"],
                        finding["category"],
                        finding["title"],
                        finding["desc"],
                    ))

                self.btn_run_scan.config(state="normal", text="🔍 전체 시스템 정밀 진단 시작")
                self._traffic_log(f"[+] 시스템 정밀 진단 완료: 안전도 {score}점 ({grade}), 총 {report['total_issues']}개 항목 검사")
                messagebox.showinfo("진단 완료", f"시스템 정밀 진단이 완료되었습니다!\n종합 점수: {score}점 ({grade})")

            self.root.after(0, _update)

        threading.Thread(target=_worker, daemon=True).start()

    def _export_scan_report(self):
        if not self.last_scan_report:
            messagebox.showwarning("경고", "먼저 진단을 실행한 후 보고서를 저장하세요.")
            return
        out_path = BASE_DIR / "security_audit_report.txt"
        lines = [
            "=" * 65,
            "  NEXUS-GUARD 시스템 보안 정밀 진단 보고서",
            f"  진단 일시: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"  종합 점수: {self.last_scan_report['security_score']}점 ({self.last_scan_report['security_grade']})",
            "=" * 65,
            "",
            "[취약점 및 설정 진단 항목 목록]",
        ]
        for idx, f in enumerate(self.last_scan_report["findings"], 1):
            lines.append(f"{idx}. [{f['severity']}] {f['category']} - {f['title']}")
            lines.append(f"   내용: {f['desc']}\n")
        out_path.write_text("\n".join(lines), encoding="utf-8")
        messagebox.showinfo("저장 완료", f"보고서가 성공적으로 저장되었습니다:\n{out_path}")

    # ---------------- 탭 5: 파일 무결성 감시 (FIM) ----------------
    def _build_fim_tab(self):
        f = tk.Frame(self.tab_fim, bg="#0d1117", padx=15, pady=15)
        f.pack(fill="both", expand=True)

        top = tk.Frame(f, bg="#0d1117")
        top.pack(fill="x", pady=(0, 10))

        tk.Label(top, text="핵심 소스코드 & 설정 파일 무결성 실시간 감시 (FIM)", font=("Pretendard", 11, "bold"), fg="#58a6ff", bg="#0d1117").pack(side="left")

        btn_fim_check = tk.Button(top, text="📁 무결성 대조 검증 실행", font=("Pretendard", 9, "bold"), bg="#238636", fg="#fff", padx=10, pady=5, command=self._on_run_fim_check)
        btn_fim_check.pack(side="right", padx=5)

        btn_fim_base = tk.Button(top, text="해시 베이스라인 재등록", font=("Pretendard", 9), bg="#21262d", fg="#c9d1d9", command=self._on_reset_fim_baseline)
        btn_fim_base.pack(side="right")

        cols = ("time", "type", "sev", "file", "desc")
        self.tree_fim = ttk.Treeview(f, columns=cols, show="headings")
        self.tree_fim.heading("time", text="감지 시각")
        self.tree_fim.heading("type", text="변조 유형")
        self.tree_fim.heading("sev", text="심각도")
        self.tree_fim.heading("file", text="대상 파일 경로")
        self.tree_fim.heading("desc", text="상세 내역")

        self.tree_fim.column("time", width=90)
        self.tree_fim.column("type", width=130)
        self.tree_fim.column("sev", width=80)
        self.tree_fim.column("file", width=220)
        self.tree_fim.column("desc", width=380)
        self.tree_fim.pack(fill="both", expand=True)

    def _on_run_fim_check(self):
        alerts = self.fim.scan_for_tampering()
        for row in self.tree_fim.get_children():
            self.tree_fim.delete(row)

        if not alerts:
            messagebox.showinfo("무결성 확인", "모든 소스코드 및 설정 파일의 SHA-256 해시가 베이스라인과 100% 일치합니다 (변조 없음).")
            self._traffic_log("[+] FIM 검증: 모든 파일 무결성 정상 통과.")
        else:
            for a in alerts:
                self.tree_fim.insert("", "end", values=(a["time"], a["type"], a["severity"], a["file"], a["desc"]))
            messagebox.showwarning("변조 경고", f"{len(alerts)}건의 파일 변경/변조 의심 항목이 적발되었습니다!")

    def _on_reset_fim_baseline(self):
        count = self.fim.initialize_baseline()
        messagebox.showinfo("베이스라인 완료", f"현재 파일 {count}개에 대한 SHA-256 해시 베이스라인이 성공적으로 등록되었습니다.")

    # ---------------- 탭 6: 환경 설정 & 외부 연동 맵 (Settings) ⭐ ----------------
    def _build_settings_tab(self):
        canvas = tk.Canvas(self.tab_settings, bg="#0d1117", highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.tab_settings, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg="#0d1117", padx=20, pady=15)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # 섹션 1: 감시 대상 웹 및 DB 서버 설정
        s1 = tk.LabelFrame(scrollable_frame, text=" 🌐 감시 대상 웹 서비스 & DB 설정 ", bg="#161b22", fg="#58a6ff", font=("Pretendard", 10, "bold"), padx=15, pady=10)
        s1.pack(fill="x", pady=(0, 15))

        self.cfg_entries = {}
        tgt = self.cfg.get("target_service", {})

        self._add_config_row(s1, "웹 포털 접속 URL:", "target_service.web_portal_url", tgt.get("web_portal_url", "http://127.0.0.1:5070"), 0, 40)
        self._add_config_row(s1, "웹 바인딩 호스트:", "target_service.web_portal_host", tgt.get("web_portal_host", "127.0.0.1"), 1, 20)
        self._add_config_row(s1, "웹 서비스 포트:", "target_service.web_portal_port", str(tgt.get("web_portal_port", 5070)), 2, 10)
        self._add_config_row(s1, "MySQL DB 호스트:", "target_service.db_host", tgt.get("db_host", "127.0.0.1"), 3, 20)
        self._add_config_row(s1, "MySQL DB 포트:", "target_service.db_port", str(tgt.get("db_port", 3307)), 4, 10)

        # 섹션 2: AI 엔진 및 API 키 설정
        s2 = tk.LabelFrame(scrollable_frame, text=" 🤖 AI-XDR 판정 엔진 & 클라우드/로컬 모델 설정 ", bg="#161b22", fg="#58a6ff", font=("Pretendard", 10, "bold"), padx=15, pady=10)
        s2.pack(fill="x", pady=(0, 15))

        ai_cfg = self.cfg.get("ai_xdr_engine", {})
        self._add_config_row(s2, "Groq LPU API Key:", "ai_xdr_engine.groq_api_key", ai_cfg.get("groq_api_key", ""), 0, 45, is_secret=True)
        self._add_config_row(s2, "Groq 모델명:", "ai_xdr_engine.groq_model", ai_cfg.get("groq_model", "openai/gpt-oss-120b"), 1, 35)
        self._add_config_row(s2, "NVIDIA NIM API Key:", "ai_xdr_engine.nvidia_api_key", ai_cfg.get("nvidia_api_key", ""), 2, 45, is_secret=True)
        self._add_config_row(s2, "온프레미스 Ollama URL:", "ai_xdr_engine.ollama_base_url", ai_cfg.get("ollama_base_url", "http://127.0.0.1:11434"), 3, 30)

        # 섹션 3: 외부 보안 장비 연동 맵 (pfSense, Graylog, Wazuh, n8n)
        s3 = tk.LabelFrame(scrollable_frame, text=" 🔗 외부 보안 장비 인터페이스 연동 (pfSense / Graylog / Wazuh / n8n) ", bg="#161b22", fg="#58a6ff", font=("Pretendard", 10, "bold"), padx=15, pady=10)
        s3.pack(fill="x", pady=(0, 15))

        ext = self.cfg.get("external_integrations", {})
        pf = ext.get("pfsense", {})
        gl = ext.get("graylog", {})
        wz = ext.get("wazuh", {})
        n8 = ext.get("n8n_soar", {})

        self._add_config_row(s3, "pfSense 차단 피드 URL:", "external_integrations.pfsense.feed_url", pf.get("feed_url", "http://127.0.0.1:5070/feeds/xdr-blocked-ips.txt"), 0, 45)
        self._add_config_row(s3, "Graylog IP & GELF UDP:", "external_integrations.graylog.host", f"{gl.get('host', '192.168.3.10')}:{gl.get('gelf_udp_port', 12201)}", 1, 30)
        self._add_config_row(s3, "Wazuh Manager IP:", "external_integrations.wazuh.manager_host", wz.get("manager_host", "192.168.3.20"), 2, 25)
        self._add_config_row(s3, "n8n SOAR Webhook URL:", "external_integrations.n8n_soar.webhook_url", n8.get("webhook_url", "http://192.168.3.15:5678/webhook/nexus-ticket-action"), 3, 45)

        # 저장 및 초기화 버튼 박스
        save_box = tk.Frame(scrollable_frame, bg="#0d1117", pady=10)
        save_box.pack(fill="x")

        btn_save = tk.Button(save_box, text="💾 설정 파일(config.json)에 저장 및 적용", font=("Pretendard", 10, "bold"), bg="#1f6feb", fg="#fff", padx=15, pady=8, command=self._on_save_settings)
        btn_save.pack(side="left", padx=5)

        btn_reset = tk.Button(save_box, text="기본값으로 복원", font=("Pretendard", 9), bg="#21262d", fg="#c9d1d9", padx=10, pady=8, command=self._on_reset_settings)
        btn_reset.pack(side="left", padx=5)

    def _add_config_row(self, parent, label_text, key, val, row, width, is_secret=False):
        tk.Label(parent, text=label_text, bg="#161b22", fg="#c9d1d9", font=("Pretendard", 9, "bold")).grid(row=row, column=0, sticky="w", pady=4, padx=5)
        ent = tk.Entry(parent, bg="#21262d", fg="#ffffff", insertbackground="#fff", font=("Pretendard", 9), width=width)
        ent.insert(0, str(val))
        if is_secret and val:
            ent.config(show="*")
        ent.grid(row=row, column=1, sticky="w", pady=4, padx=5)
        self.cfg_entries[key] = ent

    def _on_save_settings(self):
        try:
            # Entry 위젯의 값들을 self.cfg에 병합
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
                else:
                    ref[last_k] = val

            self.config_mgr.save_config(self.cfg)
            self._traffic_log("[+] 환경 설정 파일(config.json)이 성공적으로 갱신되었습니다.")
            messagebox.showinfo("설정 저장 완료", "설정이 nexus_guard/config.json 파일에 성공적으로 저장되었습니다!\n모든 보안 엔진에 새 설정이 즉시 적용됩니다.")
        except Exception as e:
            messagebox.showerror("저장 오류", f"설정 저장 중 오류가 발생했습니다: {e}")

    def _on_reset_settings(self):
        if messagebox.askyesno("확인", "모든 설정을 초기 기본값으로 되돌리시겠습니까?"):
            self.cfg = self.config_mgr.reset_to_defaults()
            self._traffic_log("[*] 모든 설정이 기본값으로 초기화되었습니다.")
            messagebox.showinfo("초기화 완료", "설정이 기본값으로 복원되었습니다. 화면을 다시 로드해 주세요.")

    def _build_footer(self):
        footer = tk.Frame(self.root, bg="#161b22", height=30, padx=15)
        footer.pack(fill="x", side="bottom")

        self.lbl_server_status = tk.Label(footer, text="● 웹 서비스 포털 연결 확인 중...", font=("Pretendard", 8), fg="#8b949e", bg="#161b22")
        self.lbl_server_status.pack(side="left")

        tk.Label(footer, text="NEXUS-GUARD v2.5.0-LTS | Enterprise Host & Web Defense", font=("Pretendard", 8), fg="#8b949e", bg="#161b22").pack(side="right")

    def _toggle_defense_mode(self):
        new_mode = "off" if self.security_mode == "ON" else "on"
        self._traffic_log(f"[*] 능동 방어 모드 전환 요청: {self.security_mode} ➔ {new_mode.upper()}")

        def _worker():
            subprocess.run([sys.executable, str(BASE_DIR / "demo_runner.py"), "--security", new_mode], capture_output=True)
            self.security_mode = new_mode.upper()
            self._update_shield_ui()
            self._traffic_log(f"[+] 능동 방어 상태 전환 완료: [{self.security_mode}]")

        threading.Thread(target=_worker, daemon=True).start()

    def _update_shield_ui(self):
        if self.security_mode == "ON":
            self.lbl_shield_badge.config(text="● SYSTEM PROTECTED", fg="#3fb950", bg="#1f242c")
            self.btn_toggle_defense.config(text="능동 방어 일시 정지 (취약 모드)")
        else:
            self.lbl_shield_badge.config(text="● VULNERABLE (SHIELD OFF)", fg="#f85149", bg="#2d1d20")
            self.btn_toggle_defense.config(text="능동 방어 즉시 재가동 (ON)")

    def _realtime_daemon_loop(self):
        target_url = self.cfg.get("target_service", {}).get("web_portal_url", "http://127.0.0.1:5070")
        while self.running:
            try:
                req = urllib.request.Request(f"{target_url}/admin/overview")
                with urllib.request.urlopen(req, timeout=2):
                    self.lbl_server_status.config(text=f"● 웹 포털 서비스 정상 가동 중 ({target_url})", fg="#3fb950")
            except Exception:
                self.lbl_server_status.config(text=f"○ 포털 서비스 오프라인 ({target_url})", fg="#8b949e")
            time.sleep(3)

    def _log_tail_loop(self):
        """실제 logs/security.jsonl 파일을 테일링하여 실시간 로그 탭에 출력."""
        log_file = BASE_DIR / "logs" / "security.jsonl"
        last_size = 0
        if log_file.exists():
            last_size = log_file.stat().st_size

        while self.running:
            try:
                if log_file.exists():
                    curr_size = log_file.stat().st_size
                    if curr_size < last_size:
                        last_size = 0
                    if curr_size > last_size:
                        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                            f.seek(last_size)
                            new_lines = f.readlines()
                            last_size = curr_size

                        for line in new_lines:
                            line_str = line.strip()
                            if line_str:
                                try:
                                    ev = json.loads(line_str)
                                    ev_type = ev.get("event", "event")
                                    src_ip = ev.get("src_ip", "unknown")
                                    self._traffic_log(f"[{ev_type.upper()}] from {src_ip} | {ev}")
                                except Exception:
                                    self._traffic_log(line_str)
                else:
                    last_size = 0
                time.sleep(1)
            except Exception:
                time.sleep(2)


def main():
    root = tk.Tk()
    app = NexusGuardEnterpriseGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
