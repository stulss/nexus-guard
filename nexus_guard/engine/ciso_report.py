# -*- coding: utf-8 -*-
"""NEXUS-GUARD Engine: CISO Audit Report Generator Facade.

SecurityReportExporter에 대한 표준 CISO 엔터프라이즈 인터페이스 파사드(Facade).
"""
from pathlib import Path
from typing import Any, Dict, List, Optional
from .report_exporter import SecurityReportExporter


class CisoAuditReportGenerator(SecurityReportExporter):
    """CISO 및 감사관용 원클릭 종합 보고서 생성기 표준 클래스."""

    def export_html_report(self, filepath: str, scanner_data=None, blocked_ips=None, fim_alerts=None) -> bool:
        """지정된 파일 경로로 HTML 보고서를 생성합니다."""
        try:
            ctx = self.build_report_context(
                scanner_data=scanner_data,
                blocked_ips=blocked_ips,
                fim_alerts=fim_alerts,
            )
            out_p = Path(filepath)
            self.export_html(ctx, filename=out_p.name)
            if out_p.parent != self.export_dir and out_p.exists():
                pass
            elif out_p.parent != self.export_dir and (self.export_dir / out_p.name).exists():
                import shutil
                shutil.copy2(self.export_dir / out_p.name, out_p)
            return out_p.exists()
        except Exception:
            return False

    def export_csv_report(self, filepath: str, scanner_data=None, blocked_ips=None, fim_alerts=None) -> bool:
        """지정된 파일 경로로 CSV 보고서를 생성합니다."""
        try:
            ctx = self.build_report_context(
                scanner_data=scanner_data,
                blocked_ips=blocked_ips,
                fim_alerts=fim_alerts,
            )
            out_p = Path(filepath)
            self.export_csv(ctx, filename=out_p.name)
            if out_p.parent != self.export_dir and (self.export_dir / out_p.name).exists():
                import shutil
                shutil.copy2(self.export_dir / out_p.name, out_p)
            return out_p.exists()
        except Exception:
            return False
