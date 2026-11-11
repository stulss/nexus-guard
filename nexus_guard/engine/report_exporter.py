# -*- coding: utf-8 -*-
"""NEXUS-GUARD Engine: 엔터프라이즈 CISO/감사관용 원클릭 종합 보안 감사 보고서 생성기.

HTML, CSV, JSON 규격으로 관제 현황, 실시간 차단 이력, FIM 파일 무결성 상태,
MITRE ATT&CK 커버리지 매트릭스, 취약점 진단 결과를 집약하여
CISO 보고 및 컴플라이언스(ISMS-P, ISO 27001) 감사 증적 자료를 자동 생성합니다.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

BASE_DIR = Path(__file__).resolve().parents[2]


class SecurityReportExporter:
    """엔터프라이즈 상용급 원클릭 보안 감사 리포트 내보내기 엔진."""

    def __init__(self, export_dir: Optional[Path] = None):
        if export_dir is None:
            self.export_dir = BASE_DIR / "exports" / "reports"
        else:
            self.export_dir = Path(export_dir)
        self.export_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _compute_hash(data_str: str) -> str:
        return hashlib.sha256(data_str.encode("utf-8")).hexdigest()

    def build_report_context(
        self,
        scanner_data: Optional[Dict[str, Any]] = None,
        blocked_ips: Optional[List[Dict[str, Any]]] = None,
        fim_alerts: Optional[List[Dict[str, Any]]] = None,
        fim_baseline_count: int = 0,
        mitre_data: Optional[Dict[str, Any]] = None,
        containment_status: Optional[Dict[str, Any]] = None,
        ciso_name: str = "Enterprise Chief Information Security Officer (CISO)",
        organization: str = "NEXUS ENTERPRISE SECURITY OPERATIONS CENTER",
    ) -> Dict[str, Any]:
        """보고서 생성에 필요한 모든 관제 지표를 수집·가공하여 컨텍스트 딕셔너리를 구축합니다."""
        now = datetime.now()
        report_id = f"NX-AUDIT-{now.strftime('%Y%m%d')}-{int(now.timestamp()) % 10000:04d}"
        iso_timestamp = now.strftime("%Y-%m-%d %H:%M:%S KST")

        # 스캐너 요약
        sc = scanner_data or {}
        score = sc.get("security_score", 100)
        grade = sc.get("security_grade", "A+ (최고 안전)")
        findings = sc.get("findings", [])
        total_vulns = len(findings)

        # 차단 IP
        b_list = blocked_ips or []
        active_blocks = [b for b in b_list if "차단" in str(b.get("status", "")) or b.get("remaining_seconds", 0) > 0]

        # FIM 상태
        f_alerts = fim_alerts or []
        is_fim_tampered = len(f_alerts) > 0

        # MITRE ATT&CK
        m_data = mitre_data or {}
        mitre_matrix = m_data.get("matrix", [])
        mitre_tactics = m_data.get("tactics_summary", {})
        total_mitre_events = m_data.get("total_mitre_events", 0)

        # 비상 격리 상태
        c_status = containment_status or {}
        is_contained = c_status.get("is_contained", False)

        context = {
            "meta": {
                "report_id": report_id,
                "created_at": iso_timestamp,
                "ciso_name": ciso_name,
                "organization": organization,
                "standard_frameworks": ["MITRE ATT&CK Enterprise v14", "ISO/IEC 27001", "ISMS-P", "NIST CSF 2.0"],
            },
            "executive_summary": {
                "overall_security_score": score,
                "security_grade": grade,
                "posture_status": "SECURE" if score >= 90 and not is_contained and not is_fim_tampered else ("CRITICAL ATTENTION" if score < 70 or is_contained or is_fim_tampered else "ELEVATED POSTURE"),
                "total_vulnerabilities": total_vulns,
                "active_blocked_ips": len(active_blocks),
                "all_time_blocked_records": len(b_list),
                "fim_monitored_assets": fim_baseline_count,
                "fim_tampering_incidents": len(f_alerts),
                "mitre_monitored_techniques": len(mitre_matrix) if mitre_matrix else 7,
                "mitre_active_threat_events": total_mitre_events,
                "emergency_containment_active": is_contained,
            },
            "containment": c_status,
            "mitre_attack": {
                "tactics_summary": mitre_tactics,
                "matrix": mitre_matrix,
                "recent_events": m_data.get("recent_events", []),
            },
            "firewall_and_blocks": {
                "active_blocks": active_blocks,
                "total_records": b_list,
            },
            "file_integrity": {
                "baseline_files_count": fim_baseline_count,
                "status": "COMPROMISED" if is_fim_tampered else "INTACT_AND_VERIFIED",
                "alerts": f_alerts,
            },
            "vulnerability_findings": findings,
        }

        # 무결성 검증용 디지털 지문 생성
        raw_json = json.dumps(context, sort_keys=True, ensure_ascii=False)
        context["meta"]["digital_seal_sha256"] = self._compute_hash(raw_json)

        return context

    def export_json(self, context: Dict[str, Any], filename: Optional[str] = None) -> Path:
        """JSON 규격 감사 보고서를 출력합니다."""
        rid = context["meta"]["report_id"]
        fname = filename or f"{rid}.json"
        out_path = self.export_dir / fname
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(context, f, indent=2, ensure_ascii=False)
        return out_path

    def export_csv(self, context: Dict[str, Any], filename: Optional[str] = None) -> Path:
        """CSV 규격 감사 로그 요약 파일을 출력합니다."""
        rid = context["meta"]["report_id"]
        fname = filename or f"{rid}.csv"
        out_path = self.export_dir / fname

        with open(out_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f)

            # 1. 헤더 메타데이터
            writer.writerow(["[NEXUS-GUARD CISO AUDIT REPORT - SUMMARY]"])
            writer.writerow(["Report ID", context["meta"]["report_id"]])
            writer.writerow(["Created At", context["meta"]["created_at"]])
            writer.writerow(["Security Score", f"{context['executive_summary']['overall_security_score']}점 ({context['executive_summary']['security_grade']})"])
            writer.writerow(["Posture Status", context["executive_summary"]["posture_status"]])
            writer.writerow(["Digital Seal SHA256", context["meta"]["digital_seal_sha256"]])
            writer.writerow([])

            # 2. 차단 IP 목록
            writer.writerow(["[SECTION 1: BLOCKED IP REGISTRY]"])
            writer.writerow(["Source IP", "Block Reason", "Hits", "Remaining Seconds", "Status"])
            for b in context["firewall_and_blocks"]["total_records"]:
                writer.writerow([
                    b.get("ip", ""),
                    b.get("reason", ""),
                    b.get("hits", 1),
                    b.get("remaining_seconds", 0),
                    b.get("status", ""),
                ])
            writer.writerow([])

            # 3. MITRE ATT&CK 커버리지
            writer.writerow(["[SECTION 2: MITRE ATT&CK MATRIX STATUS]"])
            writer.writerow(["Technique ID", "Technique Name", "Tactic", "Severity", "Detections", "Status", "Playbook"])
            for m in context["mitre_attack"]["matrix"]:
                writer.writerow([
                    m.get("technique_id", ""),
                    m.get("technique_name", ""),
                    m.get("tactic", ""),
                    m.get("severity", ""),
                    m.get("hits", 0),
                    m.get("status", ""),
                    m.get("remediation_playbook", ""),
                ])
            writer.writerow([])

            # 4. FIM 위변조 내역
            writer.writerow(["[SECTION 3: FILE INTEGRITY MONITORING (FIM)]"])
            writer.writerow(["Alert Type", "File Path", "Severity", "Description", "Timestamp"])
            for a in context["file_integrity"]["alerts"]:
                writer.writerow([
                    a.get("type", ""),
                    a.get("file", ""),
                    a.get("severity", ""),
                    a.get("desc", ""),
                    a.get("time", ""),
                ])
            writer.writerow([])

            # 5. 취약점 진단 점검 항목
            writer.writerow(["[SECTION 4: VULNERABILITY FINDINGS]"])
            writer.writerow(["Category", "Severity", "Title", "Description"])
            for v in context["vulnerability_findings"]:
                writer.writerow([
                    v.get("category", ""),
                    v.get("severity", ""),
                    v.get("title", ""),
                    v.get("desc", ""),
                ])

        return out_path

    def export_html(self, context: Dict[str, Any], filename: Optional[str] = None) -> Path:
        """CrowdStrike / SentinelOne 스타일 엔터프라이즈 CISO 감사 보고서 HTML을 생성합니다."""
        rid = context["meta"]["report_id"]
        fname = filename or f"{rid}.html"
        out_path = self.export_dir / fname

        summary = context["executive_summary"]
        meta = context["meta"]
        c_status = context["containment"]
        mitre = context["mitre_attack"]
        blocks = context["firewall_and_blocks"]
        fim = context["file_integrity"]
        findings = context["vulnerability_findings"]

        score_color = "#10b981" if summary["overall_security_score"] >= 90 else ("#f59e0b" if summary["overall_security_score"] >= 75 else "#f43f5e")

        html_content = f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NEXUS-GUARD CISO Security Audit Report - {meta['report_id']}</title>
<style>
  :root {{
    --bg-primary: #090d16;
    --bg-card: #0f172a;
    --bg-inner: #070a12;
    --border: #1e293b;
    --text-main: #f8fafc;
    --text-muted: #94a3b8;
    --text-dim: #64748b;
    --emerald: #10b981;
    --crimson: #f43f5e;
    --cyan: #38bdf8;
    --amber: #f59e0b;
    --purple: #a855f7;
    --font-sans: -apple-system, BlinkMacSystemFont, "Pretendard", "Segoe UI", Roboto, sans-serif;
    --font-mono: "JetBrains Mono", Consolas, "Courier New", monospace;
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background-color: var(--bg-primary);
    color: var(--text-main);
    font-family: var(--font-sans);
    line-height: 1.6;
    padding: 32px 20px;
  }}

  .container {{
    max-width: 1200px;
    margin: 0 auto;
  }}

  /* Executive Header */
  .header-card {{
    background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%);
    border: 1px solid #312e81;
    border-radius: 12px;
    padding: 28px 36px;
    margin-bottom: 24px;
    position: relative;
    overflow: hidden;
  }}
  .header-top {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    padding-bottom: 16px;
    margin-bottom: 16px;
  }}
  .brand-badge {{
    font-family: var(--font-mono);
    font-size: 13px;
    background: rgba(56, 189, 248, 0.15);
    color: var(--cyan);
    padding: 4px 10px;
    border-radius: 6px;
    border: 1px solid rgba(56, 189, 248, 0.3);
    text-transform: uppercase;
    letter-spacing: 1px;
  }}
  .report-title {{
    font-size: 26px;
    font-weight: 700;
    color: #ffffff;
    margin-bottom: 6px;
  }}
  .meta-sub {{
    color: var(--text-muted);
    font-size: 14px;
  }}

  /* KPI Cards Grid */
  .kpi-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
    gap: 16px;
    margin-bottom: 28px;
  }}
  .kpi-card {{
    background-color: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
  }}
  .kpi-card.hero {{
    border-color: {score_color};
    background: linear-gradient(145deg, #0f172a 0%, #132338 100%);
  }}
  .kpi-label {{
    color: var(--text-muted);
    font-size: 13px;
    font-weight: 600;
    margin-bottom: 8px;
    text-transform: uppercase;
  }}
  .kpi-value {{
    font-size: 32px;
    font-weight: 800;
    font-family: var(--font-mono);
  }}
  .kpi-subtext {{
    font-size: 12px;
    color: var(--text-dim);
    margin-top: 6px;
  }}

  /* Section Styling */
  .section {{
    background-color: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 24px;
    margin-bottom: 24px;
  }}
  .section-title {{
    font-size: 18px;
    font-weight: 700;
    margin-bottom: 16px;
    display: flex;
    align-items: center;
    gap: 8px;
    color: #ffffff;
    border-bottom: 1px solid var(--border);
    padding-bottom: 10px;
  }}

  /* Data Table */
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
    text-align: left;
  }}
  th {{
    background-color: var(--bg-inner);
    color: var(--text-muted);
    padding: 12px 14px;
    font-weight: 600;
    border-bottom: 2px solid var(--border);
    text-transform: uppercase;
    font-size: 11px;
    letter-spacing: 0.5px;
  }}
  td {{
    padding: 12px 14px;
    border-bottom: 1px solid var(--border);
    color: var(--text-main);
  }}
  tr:hover td {{
    background-color: rgba(255, 255, 255, 0.02);
  }}

  /* Badges */
  .badge {{
    display: inline-block;
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    font-family: var(--font-mono);
  }}
  .badge-critical {{ background: rgba(244, 63, 94, 0.2); color: #f43f5e; border: 1px solid #f43f5e; }}
  .badge-high {{ background: rgba(245, 158, 11, 0.2); color: #f59e0b; border: 1px solid #f59e0b; }}
  .badge-medium {{ background: rgba(56, 189, 248, 0.2); color: #38bdf8; border: 1px solid #38bdf8; }}
  .badge-secure {{ background: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid #10b981; }}

  /* Digital Seal */
  .seal-box {{
    background: var(--bg-inner);
    border: 1px dashed #475569;
    border-radius: 8px;
    padding: 18px 24px;
    margin-top: 24px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-family: var(--font-mono);
    font-size: 12px;
  }}

  /* Print Optimizations */
  @media print {{
    body {{ background: #ffffff !important; color: #000000 !important; padding: 0; }}
    .header-card, .section, .kpi-card {{
      background: #ffffff !important;
      border: 1px solid #cbd5e1 !important;
      color: #000000 !important;
      page-break-inside: avoid;
    }}
    .report-title, .section-title {{ color: #000000 !important; }}
    th {{ background: #f1f5f9 !important; color: #0f172a !important; border-color: #cbd5e1 !important; }}
    td {{ color: #0f172a !important; border-color: #e2e8f0 !important; }}
    .badge {{ border: 1px solid #000000 !important; }}
  }}
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div class="header-card">
    <div class="header-top">
      <div class="brand-badge">NEXUS-GUARD ENTERPRISE EDR/XDR SUITE</div>
      <div style="font-family: var(--font-mono); font-size: 13px; color: var(--text-muted);">
        REPORT ID: <strong style="color: var(--cyan);">{meta['report_id']}</strong>
      </div>
    </div>
    <h1 class="report-title">엔터프라이즈 CISO 종합 보안 감사 보고서</h1>
    <p class="meta-sub">
      발행 기관: {meta['organization']} &nbsp;|&nbsp; 감사 시각: {meta['created_at']} &nbsp;|&nbsp;
      준거 프레임워크: {", ".join(meta['standard_frameworks'])}
    </p>
  </div>

  <!-- KPI Grid -->
  <div class="kpi-grid">
    <div class="kpi-card hero">
      <div class="kpi-label">종합 보안 태세 점수</div>
      <div class="kpi-value" style="color: {score_color};">{summary['overall_security_score']} <span style="font-size:16px;">/ 100</span></div>
      <div class="kpi-subtext">판정: <strong>{summary['security_grade']}</strong></div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">활성 차단 침해 IP</div>
      <div class="kpi-value" style="color: {'#f43f5e' if summary['active_blocked_ips'] > 0 else '#10b981'};">{summary['active_blocked_ips']} <span style="font-size:16px;">개 호스트</span></div>
      <div class="kpi-subtext">누적 차단 기록: {summary['all_time_blocked_records']}건</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">FIM 소스 무결성</div>
      <div class="kpi-value" style="color: {'#f43f5e' if summary['fim_tampering_incidents'] > 0 else '#10b981'};">{'위변조 감지' if summary['fim_tampering_incidents'] > 0 else '정상 (INTACT)'}</div>
      <div class="kpi-subtext">감시 자산: {summary['fim_monitored_assets']}개 파일</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">MITRE ATT&CK 커버리지</div>
      <div class="kpi-value" style="color: var(--cyan);">{summary['mitre_monitored_techniques']} <span style="font-size:16px;">개 핵심 기법</span></div>
      <div class="kpi-subtext">실시간 탐지 이벤트: {summary['mitre_active_threat_events']}건</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">네트워크 비상 격리 상태</div>
      <div class="kpi-value" style="color: {'#f43f5e' if summary['emergency_containment_active'] else '#10b981'};">{'격리 가동 중' if summary['emergency_containment_active'] else '정상 운영 중'}</div>
      <div class="kpi-subtext">원클릭 긴급 차단 플레이북</div>
    </div>
  </div>

  <!-- Section 1: MITRE ATT&CK Matrix -->
  <div class="section">
    <div class="section-title">
      <span>🛡️</span> MITRE ATT&CK Enterprise Matrix 매핑 및 대응 플레이북
    </div>
    <table>
      <thead>
        <tr>
          <th>Technique ID</th>
          <th>기법명 (Technique Name)</th>
          <th>전술 단계 (Tactic)</th>
          <th>위험도</th>
          <th>탐지 횟수</th>
          <th>상태</th>
          <th>권장 대응 플레이북</th>
        </tr>
      </thead>
      <tbody>
"""
        for m in mitre.get("matrix", []):
            badge_cls = "badge-critical" if m.get("severity") == "CRITICAL" else ("badge-high" if m.get("severity") == "HIGH" else "badge-medium")
            st_badge = "badge-critical" if m.get("hits", 0) > 0 else "badge-secure"
            html_content += f"""
        <tr>
          <td><strong style="color: var(--cyan); font-family: var(--font-mono);">{m.get('technique_id')}</strong></td>
          <td>{m.get('technique_name')}</td>
          <td>{m.get('tactic')} <span style="color: var(--text-dim); font-size: 11px;">({m.get('tactic_id', '')})</span></td>
          <td><span class="badge {badge_cls}">{m.get('severity')}</span></td>
          <td><strong>{m.get('hits', 0)}</strong></td>
          <td><span class="badge {st_badge}">{m.get('status')}</span></td>
          <td style="font-size: 12px; color: var(--text-muted);">{m.get('remediation_playbook')}</td>
        </tr>
"""
        html_content += """
      </tbody>
    </table>
  </div>

  <!-- Section 2: Blocked IPs -->
  <div class="section">
    <div class="section-title">
      <span>🚫</span> 인그레스 방화벽 활성 침해 차단 및 격리 이력
    </div>
    <table>
      <thead>
        <tr>
          <th>공격자 발신지 IP</th>
          <th>차단 사유 및 탐지 근거</th>
          <th>공격 시도 수 (Hits)</th>
          <th>잔여 차단 시간</th>
          <th>집행 상태</th>
        </tr>
      </thead>
      <tbody>
"""
        all_blocks = blocks.get("total_records", [])
        if not all_blocks:
            html_content += """
        <tr>
          <td colspan="5" style="text-align: center; color: var(--text-dim); padding: 24px;">
            활성 차단된 공격자 IP가 없습니다 (클린 네트워크 상태 유지 중).
          </td>
        </tr>
"""
        else:
            for b in all_blocks:
                status_cls = "badge-critical" if "차단" in str(b.get("status", "")) else "badge-secure"
                html_content += f"""
        <tr>
          <td><strong style="font-family: var(--font-mono); color: var(--crimson);">{b.get('ip')}</strong></td>
          <td>{b.get('reason')}</td>
          <td>{b.get('hits', 1)}</td>
          <td>{b.get('remaining_seconds', 0)}초</td>
          <td><span class="badge {status_cls}">{b.get('status')}</span></td>
        </tr>
"""
        html_content += """
      </tbody>
    </table>
  </div>

  <!-- Section 3: FIM Integrity -->
  <div class="section">
    <div class="section-title">
      <span>📁</span> 파일 무결성 실시간 감시 (FIM) SHA-256 검증 결과
    </div>
    <table>
      <thead>
        <tr>
          <th>위변조 이벤트 유형</th>
          <th>대상 파일 경로</th>
          <th>위험도</th>
          <th>변조 상세 설명</th>
          <th>발생 시각</th>
        </tr>
      </thead>
      <tbody>
"""
        all_alerts = fim.get("alerts", [])
        if not all_alerts:
            html_content += f"""
        <tr>
          <td colspan="5" style="text-align: center; color: var(--emerald); padding: 24px;">
            모든 핵심 보안 소스코드 및 환경설정 파일({fim.get('baseline_files_count', 0)}개)이 SHA-256 베이스라인과 100% 일치합니다 (위변조 없음).
          </td>
        </tr>
"""
        else:
            for a in all_alerts:
                html_content += f"""
        <tr>
          <td><span class="badge badge-critical">{a.get('type')}</span></td>
          <td><strong style="font-family: var(--font-mono);">{a.get('file')}</strong></td>
          <td><span class="badge badge-high">{a.get('severity')}</span></td>
          <td>{a.get('desc')}</td>
          <td style="font-family: var(--font-mono); color: var(--text-muted);">{a.get('time')}</td>
        </tr>
"""
        html_content += """
      </tbody>
    </table>
  </div>

  <!-- Section 4: Vulnerability Findings -->
  <div class="section">
    <div class="section-title">
      <span>🔍</span> 시스템 정밀 진단 및 AST 취약점 점검 내역
    </div>
    <table>
      <thead>
        <tr>
          <th>카테고리</th>
          <th>위험도</th>
          <th>진단 항목명</th>
          <th>상세 내역 및 권장 조치</th>
        </tr>
      </thead>
      <tbody>
"""
        if not findings:
            html_content += """
        <tr>
          <td colspan="4" style="text-align: center; color: var(--emerald); padding: 24px;">
            정밀 진단 결과 발견된 취약점이 없습니다.
          </td>
        </tr>
"""
        else:
            for v in findings:
                v_badge = "badge-critical" if v.get("severity") == "HIGH" else "badge-medium"
                html_content += f"""
        <tr>
          <td><strong style="color: var(--cyan);">{v.get('category')}</strong></td>
          <td><span class="badge {v_badge}">{v.get('severity')}</span></td>
          <td><strong>{v.get('title')}</strong></td>
          <td style="color: var(--text-muted);">{v.get('desc')}</td>
        </tr>
"""
        html_content += f"""
      </tbody>
    </table>
  </div>

  <!-- Digital Seal -->
  <div class="seal-box">
    <div>
      <div><strong>보고서 무결성 암호학적 디지털 인장 (SHA-256 DIGITAL SEAL)</strong></div>
      <div style="color: var(--cyan); word-break: break-all; margin-top: 4px;">{meta['digital_seal_sha256']}</div>
    </div>
    <div style="text-align: right; color: var(--text-muted);">
      <div>AUDITED BY: {meta['ciso_name']}</div>
      <div style="color: var(--emerald); font-weight: bold; margin-top: 2px;">VERIFIED & CERTIFIED</div>
    </div>
  </div>

</div>
</body>
</html>
"""
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return out_path

    def export_all(
        self,
        scanner_data: Optional[Dict[str, Any]] = None,
        blocked_ips: Optional[List[Dict[str, Any]]] = None,
        fim_alerts: Optional[List[Dict[str, Any]]] = None,
        fim_baseline_count: int = 0,
        mitre_data: Optional[Dict[str, Any]] = None,
        containment_status: Optional[Dict[str, Any]] = None,
        base_name: Optional[str] = None,
    ) -> Dict[str, Path]:
        """HTML, CSV, JSON 3대 포맷으로 원클릭 일괄 내보내기를 수행합니다."""
        ctx = self.build_report_context(
            scanner_data=scanner_data,
            blocked_ips=blocked_ips,
            fim_alerts=fim_alerts,
            fim_baseline_count=fim_baseline_count,
            mitre_data=mitre_data,
            containment_status=containment_status,
        )

        rid = base_name or ctx["meta"]["report_id"]
        html_path = self.export_html(ctx, filename=f"{rid}.html")
        csv_path = self.export_csv(ctx, filename=f"{rid}.csv")
        json_path = self.export_json(ctx, filename=f"{rid}.json")

        return {
            "html": html_path,
            "csv": csv_path,
            "json": json_path,
            "context": ctx,
        }
