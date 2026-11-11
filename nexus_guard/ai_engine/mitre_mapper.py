# -*- coding: utf-8 -*-
"""NEXUS-GUARD AI Engine: MITRE ATT&CK Matrix 매핑 엔진.

인그레스 침해 공격, 취약점 진단 항목, FIM 변조 이벤트를
글로벌 표준 MITRE ATT&CK 엔터프라이즈 매트릭스에 실시간으로 매핑하고
CISO 및 관제사를 위한 전술(Tactics) 및 기법(Techniques) 커버리지를 제공합니다.
"""
from __future__ import annotations

import re
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional


@dataclass
class MitreTechnique:
    """MITRE ATT&CK 기법 데이터 클래스."""
    technique_id: str          # e.g., "T1595.002", "T1190"
    technique_name: str        # e.g., "Vulnerability Scanning"
    tactic: str                # e.g., "Reconnaissance", "Initial Access"
    tactic_id: str             # e.g., "TA0043", "TA0001"
    severity: str              # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    description: str           # 상세 위협 설명
    remediation_playbook: str  # 권장 긴급 대응 플레이북
    detection_timestamp: str   # ISO 타임스탬프
    source_event: str          # 이벤트 원본 유형
    matched_indicator: str     # 매칭된 지표 (IP, 경로, 파일명 등)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# 사전에 정의된 표준 엔터프라이즈 매트릭스 템플릿
STANDARD_TECHNIQUES: Dict[str, Dict[str, str]] = {
    "T1595": {
        "name": "Active Scanning / Decoy Probing",
        "tactic": "Reconnaissance",
        "tactic_id": "TA0043",
        "severity": "HIGH",
        "desc": "공격자가 시스템의 취약점이나 미끼 경로(/.env, /wp-admin 등)를 탐색하기 위해 능동 스캔을 수행합니다.",
        "playbook": "PLAYBOOK-REC-01: 실시간 403 인메모리 차단, 소스 IP 임시 격리 및 침해 경로 블랙리스트 등록",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "severity": "CRITICAL",
        "desc": "인터넷에 노출된 웹 애플리케이션의 SQL 인젝션, BOLA 권한 결함, 디렉터리 순회 취약점을 악용합니다.",
        "playbook": "PLAYBOOK-EXP-02: WAF 인라인 쿼리 차단, AST 정적 매개변수화 강제, 세션 파기 및 403 반환",
    },
    "T1070": {
        "name": "Indicator Removal on Host / Defense Evasion",
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "severity": "CRITICAL",
        "desc": "공격자가 침적을 숨기기 위해 보안 감사 로그를 변조하거나 소스코드/환경설정 파일을 무단 수정·삭제합니다.",
        "playbook": "PLAYBOOK-EVA-03: FIM 디지털 지문 즉시 검증, 변조 파일 원본 롤백 격리, 백업 스토리지 무결성 대조",
    },
    "T1059": {
        "name": "Command & Scripting / Prompt Injection",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "severity": "CRITICAL",
        "desc": "LLM 프롬프트 인젝션 탈옥, 시스템 명령어 주입, 비인가 스크립트 실행을 통해 호스트 제어권을 획득하려 합니다.",
        "playbook": "PLAYBOOK-EXE-04: AI 캐스케이드 라우터 즉각 차단, 프롬프트 입력 살균 필터 가동, 실행 프로세스 종료",
    },
    "T1499": {
        "name": "Endpoint Denial of Service (DoS)",
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "severity": "HIGH",
        "desc": "초당 수천 건의 급격한 패킷 플러딩, Slowloris, 무차별 대입으로 엔드포인트 자원을 고갈시킵니다.",
        "playbook": "PLAYBOOK-IMP-05: Rate Limiter 한도 강화, 비정상 소스 대역 인바운드 방화벽 일괄 드롭, 큐 백프레셔 발동",
    },
    "T1110": {
        "name": "Brute Force / Credential Stuffing",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "severity": "HIGH",
        "desc": "다수의 계정 또는 단일 계정에 대해 자동화된 사전 대입 또는 크리덴셜 스터핑 공격을 감행합니다.",
        "playbook": "PLAYBOOK-CRE-06: 15분 계정 동결(Account Freeze), CAPTCHA 강제 또는 IP 기반 접속 차단",
    },
    "T1505": {
        "name": "Server Software Component: Web Shell",
        "tactic": "Persistence",
        "tactic_id": "TA0003",
        "severity": "CRITICAL",
        "desc": "웹 루트 또는 소스코드 디렉터리에 악성 백도어 파일(.py, webshell)을 신규 생성하여 지속성을 확보합니다.",
        "playbook": "PLAYBOOK-PER-07: 신규 파일 격리 샌드박스 이동, 웹 서버 재기동 및 FIM 화이트리스트 베이스라인 대조",
    },
}


class MitreAttackMapper:
    """MITRE ATT&CK Matrix 실시간 자동 매핑 엔진."""

    def __init__(self, max_history: int = 1000):
        self._lock = threading.Lock()
        self._history: deque[MitreTechnique] = deque(maxlen=max_history)
        self._technique_counts: Dict[str, int] = {tid: 0 for tid in STANDARD_TECHNIQUES}
        self._tactic_counts: Dict[str, int] = {
            "Reconnaissance": 0,
            "Initial Access": 0,
            "Execution": 0,
            "Persistence": 0,
            "Defense Evasion": 0,
            "Credential Access": 0,
            "Impact": 0,
        }

    @staticmethod
    def _iso_now() -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def map_log_event(self, event: Dict[str, Any]) -> Optional[MitreTechnique]:
        """단일 실시간 보안 로그 이벤트를 MITRE ATT&CK 기법으로 자동 매핑합니다."""
        if not isinstance(event, dict):
            return None

        ev = str(event.get("event_type") or event.get("event") or "").strip().lower()
        path = str(event.get("path") or event.get("request_path") or "").strip().lower()
        ip = str(event.get("src_ip") or event.get("client_ip") or "127.0.0.1").strip()
        detail = str(event.get("detail") or event.get("desc") or event.get("msg") or "").lower()

        matched_id: Optional[str] = None

        # 1. T1595: 정찰 및 미끼 탐침
        if (
            ev in ("decoy_triggered", "recon_scan", "port_scan")
            or any(p in path for p in ["/.env", "/wp-admin", "/.git", "/actuator", "/config", "/phpmyadmin"])
            or "decoy" in detail
            or "reconnaissance" in detail
        ):
            matched_id = "T1595"

        # 2. T1059: 명령어 실행 및 프롬프트 인젝션
        elif (
            ev in ("prompt_injection_detected", "cmd_exec", "eval_exploit")
            or "prompt_injection" in ev
            or "jailbreak" in detail
            or "ignore previous instructions" in detail
        ):
            matched_id = "T1059"

        # 3. T1070: 방어 회피 및 로그/파일 변조 시도
        elif (
            ev in ("fim_hash_mismatch", "log_cleared", "tamper_detected")
            or "hash_mismatch" in ev
            or "indicator removal" in detail
            or "tamper" in detail
        ):
            matched_id = "T1070"

        # 4. T1499: DoS 공격 및 패킷 폭증
        elif (
            ev in ("rate_limit_exceeded", "dos_spike", "traffic_flood", "slowloris")
            or "denial of service" in detail
            or "flood" in detail
        ):
            matched_id = "T1499"

        # 5. T1110: 무차별 대입 및 크리덴셜 스터핑
        elif (
            ev in ("login_locked", "brute_force", "credential_stuffing")
            or "brute-force" in detail
            or "login failed" in detail
        ):
            matched_id = "T1110"

        # 6. T1190: 웹 애플리케이션 취약점 악용 (SQLi, BOLA 등)
        elif (
            ev in ("sqli_blocked", "bola_violation", "traversal_blocked")
            or "sqli" in ev
            or "sql injection" in detail
            or "bola" in detail
            or "403" in str(event.get("status_code", ""))
        ):
            matched_id = "T1190"

        if not matched_id:
            return None

        std = STANDARD_TECHNIQUES[matched_id]
        tech = MitreTechnique(
            technique_id=matched_id,
            technique_name=std["name"],
            tactic=std["tactic"],
            tactic_id=std["tactic_id"],
            severity=std["severity"],
            description=std["desc"],
            remediation_playbook=std["playbook"],
            detection_timestamp=self._iso_now(),
            source_event=ev or "security_log",
            matched_indicator=f"IP={ip} Path={path or '-'}",
        )

        with self._lock:
            self._history.appendleft(tech)
            self._technique_counts[matched_id] = self._technique_counts.get(matched_id, 0) + 1
            tac = std["tactic"]
            self._tactic_counts[tac] = self._tactic_counts.get(tac, 0) + 1

        return tech

    def map_fim_alert(self, alert: Dict[str, Any]) -> MitreTechnique:
        """FIM 파일 무결성 경보를 MITRE 기법으로 매핑합니다."""
        atype = str(alert.get("type", "")).upper()
        rel_file = str(alert.get("file", "unknown"))

        if "NEW_FILE" in atype:
            tech_id = "T1505"  # Persistence: Web Shell
        elif "MODIFIED" in atype:
            tech_id = "T1070"  # Defense Evasion: Indicator Removal / Tampering
        else:
            tech_id = "T1070"

        std = STANDARD_TECHNIQUES[tech_id]
        tech = MitreTechnique(
            technique_id=tech_id,
            technique_name=std["name"],
            tactic=std["tactic"],
            tactic_id=std["tactic_id"],
            severity="CRITICAL" if "MODIFIED" in atype or "NEW_FILE" in atype else "HIGH",
            description=f"FIM 위변조 감지: {alert.get('desc', std['desc'])} (파일: {rel_file})",
            remediation_playbook=std["playbook"],
            detection_timestamp=self._iso_now(),
            source_event=f"FIM_{atype}",
            matched_indicator=f"File={rel_file}",
        )

        with self._lock:
            self._history.appendleft(tech)
            self._technique_counts[tech_id] = self._technique_counts.get(tech_id, 0) + 1
            self._tactic_counts[std["tactic"]] = self._tactic_counts.get(std["tactic"], 0) + 1

        return tech

    def map_scanner_finding(self, finding: Dict[str, Any]) -> MitreTechnique:
        """취약점 진단 점검 항목을 MITRE 기법으로 매핑합니다."""
        title = str(finding.get("title", "")).lower()
        desc = str(finding.get("desc", "")).lower()
        sev = str(finding.get("severity", "MEDIUM")).upper()

        if "ast" in title or "sql" in title or "포트" in title or "노출" in title:
            tech_id = "T1190"  # Exploit Public-Facing App
        elif "비밀번호" in title or "secret" in title or "키" in title:
            tech_id = "T1110"  # Credential Access
        elif ".env" in title or "환경 파일" in title:
            tech_id = "T1595"  # Reconnaissance / Config Exposure
        else:
            tech_id = "T1190"

        std = STANDARD_TECHNIQUES[tech_id]
        tech = MitreTechnique(
            technique_id=tech_id,
            technique_name=std["name"],
            tactic=std["tactic"],
            tactic_id=std["tactic_id"],
            severity=sev,
            description=f"정밀 진단 결함: {finding.get('title', '')} - {finding.get('desc', '')}",
            remediation_playbook=std["playbook"],
            detection_timestamp=self._iso_now(),
            source_event="VULN_SCAN_FINDING",
            matched_indicator=f"Finding={finding.get('title', '')}",
        )

        with self._lock:
            self._history.appendleft(tech)
            self._technique_counts[tech_id] = self._technique_counts.get(tech_id, 0) + 1
            self._tactic_counts[std["tactic"]] = self._tactic_counts.get(std["tactic"], 0) + 1

        return tech

    def get_matrix_coverage(self) -> Dict[str, Any]:
        """MITRE ATT&CK 엔터프라이즈 매트릭스 전체 커버리지 현황을 반환합니다."""
        with self._lock:
            techniques_status = []
            for tid, std in STANDARD_TECHNIQUES.items():
                hit_count = self._technique_counts.get(tid, 0)
                techniques_status.append({
                    "technique_id": tid,
                    "technique_name": std["name"],
                    "tactic": std["tactic"],
                    "tactic_id": std["tactic_id"],
                    "severity": std["severity"],
                    "hits": hit_count,
                    "status": "DETECTED" if hit_count > 0 else "STANDBY (MONITORED)",
                    "remediation_playbook": std["playbook"],
                    "description": std["desc"],
                })

            total_techniques = len(STANDARD_TECHNIQUES)
            active_hits = sum(1 for t in techniques_status if t["hits"] > 0)
            total_events = len(self._history)

            return {
                "total_monitored_techniques": total_techniques,
                "detected_techniques_count": active_hits,
                "total_mitre_events": total_events,
                "tactics_summary": dict(self._tactic_counts),
                "matrix": techniques_status,
                "last_updated": self._iso_now(),
            }

    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """최근 매핑된 MITRE ATT&CK 이벤트 목록을 반환합니다."""
        with self._lock:
            return [t.to_dict() for t in list(self._history)[:limit]]

    def clear(self) -> None:
        """이력 및 카운트를 클린 초기화합니다 (클린 슬레이트 보장)."""
        with self._lock:
            self._history.clear()
            for tid in self._technique_counts:
                self._technique_counts[tid] = 0
            for tac in self._tactic_counts:
                self._tactic_counts[tac] = 0

    @classmethod
    def map_event(cls, event_type: str = "", description: str = "") -> Dict[str, Any]:
        """클래스 레벨 헬퍼: 이벤트 타입 및 설명 문자열을 MITRE ATT&CK 사전 딕셔너리로 반환."""
        ev_dict = {"event_type": event_type, "desc": description}
        temp_mapper = cls()
        tech = temp_mapper.map_log_event(ev_dict)
        if tech:
            return {
                "tactic_id": tech.tactic_id,
                "tactic_name": tech.tactic,
                "tactic_kr": tech.tactic,
                "technique_id": tech.technique_id,
                "technique_name": tech.technique_name,
                "technique_kr": tech.technique_name,
                "severity": tech.severity,
                "playbook": tech.remediation_playbook,
            }
        return {
            "tactic_id": "TA0043",
            "tactic_name": "Reconnaissance",
            "tactic_kr": "정찰 (Recon)",
            "technique_id": "T1592",
            "technique_name": "Gather Victim Host Information",
            "technique_kr": "정상 트래픽 감시",
            "severity": "INFO",
            "playbook": "None",
        }

    @classmethod
    def calculate_matrix_coverage(cls, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """클래스 레벨 헬퍼: 이벤트 목록을 받아 5대 핵심 전술 요약 맵을 반환."""
        mapper = cls()
        for ev in events:
            mapper.map_log_event(ev)
        cov = mapper.get_matrix_coverage()
        
        # 5대 핵심 전술 맵 반환 (CISO 보고서용)
        core_tactics = [
            ("TA0043", "Reconnaissance", "정찰 및 사전 탐침", "#38bdf8"),
            ("TA0001", "Initial Access", "최초 침투 시도", "#f59e0b"),
            ("TA0005", "Defense Evasion", "방어 체계 우회", "#f43f5e"),
            ("TA0002", "Execution", "비인가 명령 실행", "#ec4899"),
            ("TA0040", "Impact", "시스템 침해 및 파괴", "#dc2626"),
        ]
        res = {}
        for tid, name, kr, col in core_tactics:
            cnt = cov["tactics_summary"].get(name, 0)
            res[tid] = {
                "id": tid,
                "name": name,
                "name_kr": kr,
                "color": col,
                "count": cnt,
            }
        return res
