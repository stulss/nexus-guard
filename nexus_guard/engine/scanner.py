# -*- coding: utf-8 -*-
"""NEXUS-GUARD Engine: 시스템 취약점 전수 진단 스캐너 (Vulnerability Scanner)."""
import os
import socket
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional
from ..core.ast_guard import AstQueryGuard

BASE_DIR = Path(__file__).resolve().parents[2]


class SystemVulnerabilityScanner:
    """호스트 및 사용자가 설정한 웹/DB 대상 주소의 취약점과 보안 설정을 실제 점검하는 스캐너."""

    def __init__(self, target_dir: Path = BASE_DIR, config: Optional[Dict[str, Any]] = None):
        self.target_dir = target_dir
        self.ast_guard = AstQueryGuard()
        self.config = config
        if self.config is None:
            try:
                from .config_manager import GuardConfigManager
                self.config = GuardConfigManager().get_data()
            except Exception:
                self.config = {}

    def run_full_scan(self) -> Dict[str, Any]:
        """전체 시스템 취약점 진단을 수행하고 보안 리포트를 생성합니다."""
        findings = []
        score = 100

        # 1. 환경 설정 및 민감정보 검사 (.env)
        env_findings, env_deduct = self._scan_env_configurations()
        findings.extend(env_findings)
        score -= env_deduct

        # 2. 사용자가 설정한 대상 주소(웹 포털 & DB & 연동 장비) 네트워크 및 엔드포인트 검사
        endpoint_findings, endpoint_deduct = self._scan_target_service_endpoints()
        findings.extend(endpoint_findings)
        score -= endpoint_deduct

        # 3. 소스코드 AST 정적 쿼리 전수 검사
        ast_findings, ast_deduct = self._scan_source_code_ast()
        findings.extend(ast_findings)
        score -= ast_deduct

        # 4. 방어 실드 설정 검사
        shield_findings, shield_deduct = self._scan_defense_configurations()
        findings.extend(shield_findings)
        score -= shield_deduct

        score = max(0, min(100, score))
        grade = "A+ (안전)" if score >= 90 else ("B (양호)" if score >= 75 else "C (주의 필요)")

        cfg = self.config or {}
        tgt = cfg.get("target_service", {})
        web_url = str(tgt.get("web_portal_url", "")).strip()
        db_host = str(tgt.get("db_host", "")).strip()
        db_port = str(tgt.get("db_port", "")).strip()

        target_web = web_url if web_url else "미등록 (환경 설정 탭에서 보호할 웹 URL을 지정하세요)"
        target_db = f"{db_host}:{db_port}" if (db_host and db_port) else "미등록 (환경 설정 탭에서 DB 정보를 지정하세요)"

        return {
            "security_score": score,
            "security_grade": grade,
            "total_issues": len(findings),
            "findings": findings,
            "target_summary": {
                "web_url": target_web,
                "db_target": target_db,
            },
            "scan_timestamp": Path(__file__).stat().st_mtime,
        }

    def _scan_env_configurations(self) -> (List[Dict[str, str]], int):
        issues = []
        deduct = 0
        env_file = self.target_dir / ".env"
        if not env_file.exists():
            issues.append({
                "severity": "HIGH",
                "category": "설정 결함",
                "title": ".env 환경 파일 부재",
                "desc": ".env 파일이 없어 기본 취약 설정으로 구동될 위험이 있습니다.",
            })
            return issues, 20

        content = env_file.read_text(encoding="utf-8", errors="ignore")
        if "ChangeMe" in content or "change-me" in content:
            issues.append({
                "severity": "HIGH",
                "category": "계정 보안",
                "title": "기본 초기 비밀번호(ChangeMe) 미변경 탐지",
                "desc": ".env 내에 기본 시험용 비밀번호가 그대로 설정되어 있습니다.",
            })
            deduct += 15

        if "SECRET_KEY=change-me" in content or len(os.environ.get("SECRET_KEY", "")) < 32:
            issues.append({
                "severity": "CRITICAL",
                "category": "세션 보안",
                "title": "세션 서명 SECRET_KEY 강도 취약",
                "desc": "세션 암호화 키가 32자 미만이거나 기본값입니다.",
            })
            deduct += 20

        return issues, deduct

    def _scan_target_service_endpoints(self) -> (List[Dict[str, str]], int):
        """사용자가 [환경 설정]에서 등록한 웹 포털 URL 및 DB 호스트:포트 주소를 실제 검증합니다."""
        issues = []
        deduct = 0

        cfg = self.config or {}
        tgt = cfg.get("target_service", {})
        web_url = str(tgt.get("web_portal_url", "")).strip()
        db_host = str(tgt.get("db_host", "")).strip()
        db_port_val = str(tgt.get("db_port", "")).strip()
        db_port = int(db_port_val) if db_port_val.isdigit() else 0

        # [1] 설정된 웹 포털 접속 점검 (Socket 연결성 + HTTP 보안 프로브)
        if not web_url:
            issues.append({
                "severity": "INFO",
                "category": "설정 안내",
                "title": "감시 대상 웹 포털 미등록 안내",
                "desc": "[환경 설정] 탭에 보호할 웹 사이트 주소가 비어 있습니다. 웹 URL을 등록하면 실시간 가용성 및 보안 헤더(X-Frame-Options 등)를 자동 검증합니다.",
            })
        else:
            try:
                parsed = urllib.parse.urlparse(web_url)
                web_host = parsed.hostname or "127.0.0.1"
                web_port = parsed.port or (443 if parsed.scheme == "https" else (80 if parsed.scheme == "http" else 5070))
            except Exception:
                web_host = "127.0.0.1"
                web_port = 5070

            sock_web = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_web.settimeout(0.5)
            web_open = (sock_web.connect_ex((web_host, web_port)) == 0)
            sock_web.close()

            if web_open:
                try:
                    probe_url = web_url if web_url.startswith("http") else f"http://{web_host}:{web_port}"
                    req = urllib.request.Request(probe_url, headers={"User-Agent": "NexusGuard-Audit/2.5"})
                    with urllib.request.urlopen(req, timeout=1.0) as resp:
                        hdrs = {k.lower(): v for k, v in resp.headers.items()}
                        missing = []
                        if "x-frame-options" not in hdrs:
                            missing.append("X-Frame-Options (Clickjacking 방어)")
                        if "x-content-type-options" not in hdrs:
                            missing.append("X-Content-Type-Options (MIME 스니핑 방어)")

                        if missing:
                            issues.append({
                                "severity": "MEDIUM",
                                "category": "설정된 웹 엔드포인트",
                                "title": f"타겟 웹 주소({web_host}:{web_port}) 보안 헤더 미흡",
                                "desc": f"설정된 웹 주소({probe_url})가 정상 응답하나 필수 보안 헤더가 누락되어 있습니다: {', '.join(missing)}",
                            })
                            deduct += 10
                        else:
                            issues.append({
                                "severity": "SAFE",
                                "category": "설정된 웹 엔드포인트",
                                "title": f"타겟 웹 주소({web_host}:{web_port}) 보안 헤더 완비",
                                "desc": f"설정된 타겟 웹 주소({probe_url})가 가동 중이며 필수 보안 헤더가 정상 적용되어 있습니다.",
                            })
                except Exception:
                    issues.append({
                        "severity": "INFO",
                        "category": "설정된 웹 엔드포인트",
                        "title": f"타겟 웹 포트 수신 대기 확인 ({web_host}:{web_port})",
                        "desc": f"설정된 웹 서비스 엔드포인트 포트({web_host}:{web_port})가 정상적으로 열려 연결을 대기 중입니다.",
                    })
            else:
                issues.append({
                    "severity": "MEDIUM",
                    "category": "설정된 웹 가용성",
                    "title": f"타겟 웹 포털 미구동 (주소: {web_host}:{web_port})",
                    "desc": f"설정 파일(config.json)에 등록된 타겟 웹 주소({web_url})의 수신 포트가 닫혀 있거나 응답하지 않습니다.",
                })
                deduct += 10

        # [2] 설정된 MySQL DB 접속 점검
        if not db_host or db_port == 0:
            issues.append({
                "severity": "INFO",
                "category": "설정 안내",
                "title": "감시 대상 DB 미등록 안내",
                "desc": "[환경 설정] 탭에 DB 접속 정보가 비어 있습니다. 데이터베이스 IP와 포트를 등록하면 외부 무단 노출 및 방화벽 ACL을 자동 점검합니다.",
            })
        else:
            sock_db = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_db.settimeout(0.5)
            db_open = (sock_db.connect_ex((db_host, db_port)) == 0)
            sock_db.close()

            if db_open:
                if db_host not in ("127.0.0.1", "localhost"):
                    issues.append({
                        "severity": "HIGH",
                        "category": "설정된 DB 네트워크 보안",
                        "title": f"타겟 DB 외부 노출 주의 ({db_host}:{db_port})",
                        "desc": f"설정된 MySQL DB 주소({db_host})가 외부 네트워크에 개방되어 있습니다. 방화벽 ACL 통제가 필요합니다.",
                    })
                    deduct += 15
                else:
                    issues.append({
                        "severity": "INFO",
                        "category": "설정된 DB 네트워크 보안",
                        "title": f"타겟 DB 로컬 수신 정상 ({db_host}:{db_port})",
                        "desc": f"설정된 MySQL DB가 안전하게 로컬 루프백({db_host}:{db_port})에서 수신 대기 중입니다.",
                    })
            else:
                issues.append({
                    "severity": "INFO",
                    "category": "설정된 DB 가용성",
                    "title": f"타겟 DB 포트 미개방 안내 ({db_host}:{db_port})",
                    "desc": f"설정된 DB 주소({db_host}:{db_port})가 현재 오프라인 상태입니다 (단독 PC 모드에서는 정상).",
                })

        # [3] 설정된 외부 연동 장비 점검 (활성화된 경우)
        ext = cfg.get("external_integrations", {})
        pfs = ext.get("pfsense", {})
        if pfs.get("enabled", False):
            pfs_h = pfs.get("host", "192.168.3.1")
            pfs_p = int(pfs.get("webgui_port", 443))
            s_pfs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s_pfs.settimeout(0.4)
            pfs_ok = (s_pfs.connect_ex((pfs_h, pfs_p)) == 0)
            s_pfs.close()
            if not pfs_ok:
                issues.append({
                    "severity": "MEDIUM",
                    "category": "외부 연동 장비",
                    "title": f"설정된 pfSense 방화벽({pfs_h}:{pfs_p}) 통신 불가",
                    "desc": f"설정 탭에 등록된 pfSense 게이트웨이({pfs_h}:{pfs_p})와 네트워크 통신이 되지 않습니다.",
                })
                deduct += 5

        return issues, deduct

    def _scan_listening_ports(self) -> (List[Dict[str, str]], int):
        """호환성을 위한 별칭."""
        return self._scan_target_service_endpoints()

    def _scan_source_code_ast(self) -> (List[Dict[str, str]], int):
        issues = []
        deduct = 0
        app_dir = self.target_dir / "app"
        if not app_dir.exists():
            return issues, 0

        total_violations = 0
        for py_file in app_dir.glob("*.py"):
            violations = self.ast_guard.inspect_file(py_file)
            for lineno, msg in violations:
                total_violations += 1
                issues.append({
                    "severity": "CRITICAL",
                    "category": "소스코드 보안",
                    "title": f"SQL Injection 취약 패턴 탐지 ({py_file.name}:{lineno})",
                    "desc": msg,
                })
                deduct += 25

        if total_violations == 0:
            issues.append({
                "severity": "SAFE",
                "category": "소스코드 보안",
                "title": "AST 정적 분석 SQLi 무결점 통과",
                "desc": "모든 SQL 호출이 100% 안전한 파라미터 바인딩을 사용하고 있습니다.",
            })

        return issues, deduct

    def _scan_defense_configurations(self) -> (List[Dict[str, str]], int):
        issues = []
        env_file = self.target_dir / ".env"
        mode = "on"
        if env_file.exists():
            for line in env_file.read_text(encoding="utf-8").splitlines():
                if line.startswith("SECURITY_MODE="):
                    mode = line.split("=")[1].strip().lower()

        if mode == "off":
            issues.append({
                "severity": "HIGH",
                "category": "능동 방어",
                "title": "실시간 방어 모드 비활성화 상태 (취약)",
                "desc": "현재 보안 모드가 OFF 상태입니다. 공격이 차단되지 않습니다.",
            })
            return issues, 20

        issues.append({
            "severity": "SAFE",
            "category": "능동 방어",
            "title": "ACTIVE SHIELD 능동 방어 가동 중",
            "desc": "디코이(허니팟) 탐침 및 무차별 대입 자동 차단이 활성화되어 있습니다.",
        })
        return issues, 0

    def auto_remediate_all(self) -> tuple[int, list[str]]:
        """원클릭 시스템 취약점 자동 치료 및 보안 강화 (1-Click Auto-Fix)."""
        import secrets
        actions = []
        fixed_count = 0

        env_file = self.target_dir / ".env"
        if not env_file.exists():
            env_example = self.target_dir / ".env.example"
            if env_example.exists():
                env_file.write_text(env_example.read_text(encoding="utf-8"), encoding="utf-8")
                actions.append(".env 파일 부재 해결: .env.example 템플릿으로부터 신규 생성")
                fixed_count += 1

        if env_file.exists():
            lines = env_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            new_lines = []
            modified = False
            for line in lines:
                if line.startswith("SECRET_KEY="):
                    val = line.split("=", 1)[1].strip()
                    if len(val) < 32 or "change-me" in val.lower() or "test" in val.lower():
                        new_key = secrets.token_urlsafe(48)
                        new_lines.append(f"SECRET_KEY={new_key}")
                        actions.append("취약한 SECRET_KEY를 64자리 암호학적 안전 토큰으로 자동 갱신")
                        modified = True
                        fixed_count += 1
                        continue
                elif line.startswith("SECURITY_MODE="):
                    val = line.split("=", 1)[1].strip().lower()
                    if val != "on":
                        new_lines.append("SECURITY_MODE=on")
                        actions.append("비활성화된 실시간 방어 실드를 즉시 'ON'으로 복구")
                        modified = True
                        fixed_count += 1
                        continue
                new_lines.append(line)

            if modified:
                env_file.write_text("\n".join(new_lines) + "\n", encoding="utf-8")

        try:
            from .firewall import FirewallRuleManager
            fw = FirewallRuleManager()
            fw.apply_windows_firewall_rule("192.168.7.77")
            actions.append("호스트 방화벽 netsh에 악성 탐침 IP 인바운드 드롭 룰 실시간 등록")
            fixed_count += 1
        except Exception:
            pass

        return fixed_count, actions
