# -*- coding: utf-8 -*-
"""NEXUS-GUARD Core: MITRE ATT&CK Enterprise Matrix v14 실시간 매핑 및 분석 엔진.

글로벌 EDR/XDR 표준(CrowdStrike Falcon, SentinelOne Singularity)에 준하는
보안 이벤트-MITRE ATT&CK 프레임워크 실시간 기법 매핑, 전술 분류 및 매트릭스 레이어 산출.
"""
from dataclasses import dataclass, field
import json
import re
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class MitreTechnique:
    """MITRE ATT&CK 기법 메타데이터."""
    technique_id: str
    technique_name: str
    tactic: str
    tactic_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    description: str
    mitigation: str
    subtechnique_of: Optional[str] = None


@dataclass
class MitreMappingResult:
    """이벤트 매핑 결과."""
    primary_technique: MitreTechnique
    all_techniques: List[MitreTechnique] = field(default_factory=list)
    tactic: str = ""
    tactic_id: str = ""
    severity: str = "LOW"
    confidence: float = 1.0  # 0.0 ~ 1.0
    recommended_action: str = ""
    matched_patterns: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.primary_technique.technique_id,
            "technique_name": self.primary_technique.technique_name,
            "tactic": self.tactic or self.primary_technique.tactic,
            "tactic_id": self.tactic_id or self.primary_technique.tactic_id,
            "severity": self.severity,
            "confidence": round(self.confidence, 2),
            "recommended_action": self.recommended_action,
            "all_techniques": [t.technique_id for t in self.all_techniques],
            "matched_patterns": self.matched_patterns,
        }


# =========================================================================
# MITRE ATT&CK Enterprise Knowledge Base (v14)
# =========================================================================
TECHNIQUE_CATALOG: Dict[str, MitreTechnique] = {
    "T1190": MitreTechnique(
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        tactic="Initial Access",
        tactic_id="TA0001",
        severity="CRITICAL",
        description="공개 웹 애플리케이션의 취약점(SQL Injection, RCE 등)을 악용하여 내부 시스템에 초기 침투합니다.",
        mitigation="인그레스 AST 쿼리 정적 검증, WAF 실시간 403 차단, 입력 파라미터 유효성 전수 검사.",
    ),
    "T1083": MitreTechnique(
        technique_id="T1083",
        technique_name="File and Directory Discovery",
        tactic="Discovery",
        tactic_id="TA0007",
        severity="HIGH",
        description="시스템 내 민감 설정 파일(.env), 관리자 디렉터리, 백업 파일을 식별하기 위해 비인가 스캔을 시도합니다.",
        mitigation="능동형 가상 디코이(Honeypot) 경로 배치 및 첫 탐침 즉시 공격 IP 영구 격리.",
    ),
    "T1110": MitreTechnique(
        technique_id="T1110",
        technique_name="Brute Force",
        tactic="Credential Access",
        tactic_id="TA0006",
        severity="HIGH",
        description="인증 자격 증명을 획득하기 위해 반복적인 비밀번호 대입이나 사전 공격을 감행합니다.",
        mitigation="IP/계정 단위 동적 지수 백오프 잠금 및 인메모리 블랙리스트 자동 차단 집행.",
    ),
    "T1110.001": MitreTechnique(
        technique_id="T1110.001",
        technique_name="Password Guessing",
        tactic="Credential Access",
        tactic_id="TA0006",
        severity="HIGH",
        description="특정 관리자 또는 사용자 계정에 대해 사전 기반의 비밀번호 추측 공격을 수행합니다.",
        mitigation="5회 연속 실패 시 계정 임시 동결 및 다단계 인증(MFA) 강제.",
        subtechnique_of="T1110",
    ),
    "T1110.003": MitreTechnique(
        technique_id="T1110.003",
        technique_name="Password Spraying",
        tactic="Credential Access",
        tactic_id="TA0006",
        severity="HIGH",
        description="계정 잠금을 회피하기 위해 다수의 계정을 대상으로 공통 비밀번호를 1~2회씩 분산 시도합니다.",
        mitigation="단일 발신지 IP 기반 크로스 어카운트 로그인 실패 집계 및 전역 IP 차단.",
        subtechnique_of="T1110",
    ),
    "T1059": MitreTechnique(
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        tactic="Execution",
        tactic_id="TA0002",
        severity="CRITICAL",
        description="운영체제 명령어(Shell/PowerShell/Bash) 또는 스크립트 인터프리터를 호출하여 악의적 명령을 실행합니다.",
        mitigation="셸 명령어 직간접 실행 API 원천 차단(shell=False 엄격화) 및 AST 정적 검사.",
    ),
    "T1059.006": MitreTechnique(
        technique_id="T1059.006",
        technique_name="Python",
        tactic="Execution",
        tactic_id="TA0002",
        severity="CRITICAL",
        description="Python 인터프리터(eval, exec, __import__)를 비인가 호출하여 임의 코드를 실행합니다.",
        mitigation="동적 파이썬 실행 함수 비활성화 및 AST 구문 분석기를 통한 금지 노드 차단.",
        subtechnique_of="T1059",
    ),
    "T1562.001": MitreTechnique(
        technique_id="T1562.001",
        technique_name="Impair Defenses: Disable or Modify Tools",
        tactic="Defense Evasion",
        tactic_id="TA0005",
        severity="CRITICAL",
        description="보안 관제 엔진을 무력화하거나 소스코드/설정 파일의 무결성을 훼손하여 탐지를 우회합니다.",
        mitigation="SHA-256 파일 무결성 감시(FIM) 실시간 대조 및 변조 탐지 즉시 호스트 격리.",
        subtechnique_of="T1562",
    ),
    "T1071.001": MitreTechnique(
        technique_id="T1071.001",
        technique_name="Application Layer Protocol: Web Protocols",
        tactic="Command and Control",
        tactic_id="TA0011",
        severity="MEDIUM",
        description="웹 프로토콜(HTTP/HTTPS)을 악용하여 C2 서버와 비정상적인 통신 또는 데이터 유출 채널을 구축합니다.",
        mitigation="아웃바운드 Egress 네트워크 필터링 및 비정상 요청 헤더 심층 감시.",
        subtechnique_of="T1071",
    ),
    "T1005": MitreTechnique(
        technique_id="T1005",
        technique_name="Data from Local System",
        tactic="Collection",
        tactic_id="TA0009",
        severity="HIGH",
        description="BOLA/IDOR 취약점이나 결재 권한 우회를 통해 사내 주요 데이터베이스나 문서 파일을 불법 탈취합니다.",
        mitigation="5단계 결재 트랜잭션 소유권 BOLA 실시간 차단 쉴드 및 DB 권한 최소화.",
    ),
    "T1548": MitreTechnique(
        technique_id="T1548",
        technique_name="Abuse Elevation Control Mechanism",
        tactic="Privilege Escalation",
        tactic_id="TA0004",
        severity="HIGH",
        description="일반 사용자 권한에서 관리자 권한으로 승격하기 위해 시스템 메커니즘을 오용합니다.",
        mitigation="권한 변경 엔드포인트 세션 검증 및 롤 기반 접근 제어(RBAC) 감사.",
    ),
    "T1595.002": MitreTechnique(
        technique_id="T1595.002",
        technique_name="Active Scanning: Vulnerability Scanning",
        tactic="Reconnaissance",
        tactic_id="TA0043",
        severity="MEDIUM",
        description="타깃 호스트의 개방 포트 및 소프트웨어 취약점을 식별하기 위해 능동형 스캐너를 구동합니다.",
        mitigation="경계 방화벽 포트 스캔 탐지 및 비정상 트래픽 속도 제한(Rate Limiting).",
        subtechnique_of="T1595",
    ),
    "T1078": MitreTechnique(
        technique_id="T1078",
        technique_name="Valid Accounts",
        tactic="Persistence",
        tactic_id="TA0003",
        severity="MEDIUM",
        description="도용된 정상 계정을 이용하여 시스템에 잠복하거나 인가된 영역에 접근합니다.",
        mitigation="위험 기반 이상 로그인 탐지 및 동시 세션 제한 정책 적용.",
    ),
    "T1498": MitreTechnique(
        technique_id="T1498",
        technique_name="Network Denial of Service",
        tactic="Impact",
        tactic_id="TA0040",
        severity="HIGH",
        description="대량의 비정상 트래픽을 주입하여 가용성을 저해하는 DoS/DDoS 공격을 시도합니다.",
        mitigation="인메모리 트래픽 카운터 및 비정상 스파이크 자동 임계치 차단.",
    ),
}

DEFAULT_TECHNIQUE = MitreTechnique(
    technique_id="T1071.001",
    technique_name="Application Layer Protocol: Web Protocols",
    tactic="Initial Access",
    tactic_id="TA0001",
    severity="LOW",
    description="일반적인 웹 프로토콜 기반의 통신 트래픽입니다.",
    mitigation="지속적인 실시간 트래픽 관제 및 시그니처 대조.",
)


class MitreAttackMapper:
    """보안 이벤트 로그를 MITRE ATT&CK 기법과 실시간 매핑하는 엔터프라이즈 분석기."""

    def __init__(self, catalog: Optional[Dict[str, MitreTechnique]] = None):
        self.catalog = catalog or TECHNIQUE_CATALOG

        # 시그니처 매핑 테이블
        self._event_type_rules: Dict[str, str] = {
            "decoy_probe": "T1083",
            "decoy_hit": "T1083",
            "honeypot_hit": "T1083",
            "sqli_blocked": "T1190",
            "sqli_attempt": "T1190",
            "sql_injection": "T1190",
            "ast_blocked": "T1190",
            "xss_blocked": "T1190",
            "rce_attempt": "T1059",
            "command_injection": "T1059",
            "eval_injection": "T1059.006",
            "python_code_injection": "T1059.006",
            "login_failed_burst": "T1110",
            "brute_force": "T1110",
            "password_spray": "T1110.003",
            "credential_stuffing": "T1110.001",
            "bola_blocked": "T1005",
            "idor_attempt": "T1005",
            "unauthorized_download": "T1005",
            "privilege_escalation": "T1548",
            "role_tamper": "T1548",
            "fim_tamper": "T1562.001",
            "file_tampered": "T1562.001",
            "integrity_violation": "T1562.001",
            "port_scan": "T1595.002",
            "vuln_scan": "T1595.002",
            "dos_flood": "T1498",
            "c2_heartbeat": "T1071.001",
        }

        # 텍스트 정규식 패턴 기반 매핑
        self._pattern_rules: List[Tuple[re.Pattern, str, str]] = [
            (re.compile(r"(\.env|backup\.sql|\.git|wp-admin|phpinfo|web\.config)", re.IGNORECASE), "T1083", "민감 설정 파일 및 디렉터리 탐색 패턴 식별"),
            (re.compile(r"(union\s+select|information_schema|waitfor\s+delay|sleep\(\d+\)|or\s+1=1)", re.IGNORECASE), "T1190", "SQL Injection 문법 및 서브쿼리 패턴 식별"),
            (re.compile(r"(<script|alert\(|javascript:|onerror=)", re.IGNORECASE), "T1190", "Cross-Site Scripting (XSS) 스크립트 태그 삽입"),
            (re.compile(r"(/bin/sh|/bin/bash|cmd\.exe|powershell|whoami|curl\s+http)", re.IGNORECASE), "T1059", "운영체제 명령어 실행 및 셸 호출 시도"),
            (re.compile(r"(__import__|eval\(|exec\(|getattr\(|subprocess\.Popen)", re.IGNORECASE), "T1059.006", "파이썬 동적 코드 실행 인터프리터 오용"),
            (re.compile(r"(sha256.*불일치|변조.*탐지|fim.*tamper|baseline.*diff)", re.IGNORECASE), "T1562.001", "시스템 무결성 파일 해시 불일치 및 변조 감지"),
            (re.compile(r"(결재.*새치기|타인.*결재|bola.*blocked|소유권.*위반)", re.IGNORECASE), "T1005", "비인가 결재선 조작 및 BOLA 데이터 침해 시도"),
            (re.compile(r"(연속.*비밀번호.*실패|brute.*force|login.*fail.*burst)", re.IGNORECASE), "T1110", "비밀번호 무차별 대입 및 자격 증명 공격"),
        ]

    def map_event(self, event: Dict[str, Any]) -> MitreMappingResult:
        """단일 보안 이벤트를 정밀 분석하여 MITRE ATT&CK 기법으로 매핑합니다."""
        if not isinstance(event, dict):
            event = {}

        matched_tech_ids: List[str] = []
        matched_notes: List[str] = []
        confidence = 0.85

        # 1. 명시적 technique 필드 확인 (기존에 부여된 경우)
        explicit_id = str(event.get("mitre_technique") or event.get("technique_id") or "").strip().upper()
        if explicit_id in self.catalog:
            matched_tech_ids.append(explicit_id)
            matched_notes.append(f"명시적 기법 태그: {explicit_id}")
            confidence = 1.0

        # 2. event_type 필드 규칙 매핑
        event_type = str(event.get("event") or event.get("event_type") or "").strip().lower()
        if event_type in self._event_type_rules:
            tid = self._event_type_rules[event_type]
            if tid not in matched_tech_ids and tid in self.catalog:
                matched_tech_ids.append(tid)
                matched_notes.append(f"이벤트 타입 [{event_type}] 기반 규칙 매핑")
                confidence = max(confidence, 0.95)

        # 3. 텍스트 필드(path, reason, detail, payload, query) 종합 정규식 검사
        combined_text = " ".join([
            str(event.get("path", "")),
            str(event.get("reason", "")),
            str(event.get("detail", "")),
            str(event.get("payload", "")),
            str(event.get("query", "")),
            str(event.get("analysis", "")),
        ])

        for pattern, tid, desc in self._pattern_rules:
            if pattern.search(combined_text):
                if tid not in matched_tech_ids and tid in self.catalog:
                    matched_tech_ids.append(tid)
                    matched_notes.append(desc)
                    confidence = max(confidence, 0.90)

        # 4. 매핑 결과 도출
        if not matched_tech_ids:
            primary = DEFAULT_TECHNIQUE
            confidence = 0.50
            matched_notes.append("일반 웹 프로토콜 기본 매핑")
        else:
            primary_id = matched_tech_ids[0]
            primary = self.catalog.get(primary_id, DEFAULT_TECHNIQUE)

        all_techniques = [self.catalog[tid] for tid in matched_tech_ids if tid in self.catalog]
        if not all_techniques:
            all_techniques = [primary]

        return MitreMappingResult(
            primary_technique=primary,
            all_techniques=all_techniques,
            tactic=primary.tactic,
            tactic_id=primary.tactic_id,
            severity=primary.severity,
            confidence=confidence,
            recommended_action=primary.mitigation,
            matched_patterns=matched_notes,
        )

    def generate_matrix_summary(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """여러 이벤트 로그를 집계하여 MITRE ATT&CK 전술 및 기법별 통계를 도출합니다."""
        tactic_counts: Dict[str, int] = {}
        technique_counts: Dict[str, Dict[str, Any]] = {}
        severity_counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for ev in events:
            res = self.map_event(ev)
            tactic = res.tactic
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

            tid = res.primary_technique.technique_id
            tname = res.primary_technique.technique_name
            if tid not in technique_counts:
                technique_counts[tid] = {
                    "technique_id": tid,
                    "technique_name": tname,
                    "tactic": tactic,
                    "count": 0,
                    "severity": res.severity,
                }
            technique_counts[tid]["count"] += 1
            severity_counts[res.severity] = severity_counts.get(res.severity, 0) + 1

        return {
            "total_events": len(events),
            "tactics_distribution": tactic_counts,
            "techniques_breakdown": list(technique_counts.values()),
            "severity_distribution": severity_counts,
        }

    def export_navigator_layer(
        self,
        events: List[Dict[str, Any]],
        layer_name: str = "NEXUS-GUARD ATT&CK Enterprise Matrix",
    ) -> Dict[str, Any]:
        """ATT&CK Navigator(v4.5)와 100% 호환되는 JSON 레이어를 생성합니다."""
        summary = self.generate_matrix_summary(events)
        techniques_list = []

        max_count = max([t["count"] for t in summary["techniques_breakdown"]] or [1])

        for t in summary["techniques_breakdown"]:
            score = t["count"]
            color = "#f43f5e" if t["severity"] == "CRITICAL" else ("#fb923c" if t["severity"] == "HIGH" else "#38bdf8")
            techniques_list.append({
                "techniqueID": t["technique_id"],
                "score": score,
                "color": color,
                "comment": f"탐지 건수: {score}건 (위험도: {t['severity']}) - NEXUS-GUARD 능동 방어 집행",
                "enabled": True,
            })

        return {
            "name": layer_name,
            "versions": {
                "attack": "14",
                "navigator": "4.5",
                "layer": "4.3",
            },
            "domain": "enterprise-attack",
            "description": "NEXUS-GUARD 엔터프라이즈 AI-XDR 능동 방어 실시간 탐지 레이어",
            "techniques": techniques_list,
            "gradient": {
                "colors": ["#10b981", "#fbbf24", "#f43f5e"],
                "minValue": 0,
                "maxValue": max_count,
            },
            "legendItems": [
                {"label": "CRITICAL (치명적)", "color": "#f43f5e"},
                {"label": "HIGH (높음)", "color": "#fb923c"},
                {"label": "MEDIUM (중간)", "color": "#38bdf8"},
                {"label": "SECURE/LOW (정상/낮음)", "color": "#10b981"},
            ],
        }
