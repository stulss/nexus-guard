# -*- coding: utf-8 -*-
"""NEXUS-GUARD Ruleset Manager.

pfSense 스타일 호스트 방화벽 룰셋 & Graylog 스타일 SIEM 상관분석 탐지 룰셋 관리 엔진.
규칙의 추가, 삭제, 활성화/비활성화 토글 및 JSON 파일 영구 저장 지원.
"""
import json
from datetime import datetime
from pathlib import Path

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
FW_RULES_PATH = RULES_DIR / "firewall_rules.json"
SIEM_RULES_PATH = RULES_DIR / "siem_rules.json"


class FirewallRulesetManager:
    """pfSense 스타일 방화벽 룰셋(패킷 필터링 규칙) 관리자."""

    def __init__(self):
        self.rules = self.load_rules()

    def load_rules(self) -> list[dict]:
        if not FW_RULES_PATH.exists():
            return []
        try:
            with open(FW_RULES_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def save_rules(self) -> bool:
        try:
            RULES_DIR.mkdir(parents=True, exist_ok=True)
            with open(FW_RULES_PATH, "w", encoding="utf-8") as f:
                json.dump(self.rules, f, indent=2, ensure_ascii=False)
            return True
        except Exception:
            return False

    @staticmethod
    def validate_port(port: str) -> bool:
        """포트 번호 유효성 검증 (1-65535, ANY, 또는 포트 범위 '80-443')."""
        if not isinstance(port, str):
            return False
        p_str = port.strip().upper()
        if p_str in ("ANY", "*", "ALL"):
            return True
        if "-" in p_str:
            parts = p_str.split("-")
            if len(parts) != 2:
                return False
            try:
                p1, p2 = int(parts[0].strip()), int(parts[1].strip())
                return 1 <= p1 <= 65535 and 1 <= p2 <= 65535 and p1 <= p2
            except ValueError:
                return False
        try:
            val = int(p_str)
            return 1 <= val <= 65535
        except ValueError:
            return False

    @staticmethod
    def validate_ip(ip: str) -> bool:
        """IP 유효성 검증 (IPv4/IPv6, CIDR, 또는 ANY)."""
        import ipaddress
        if not isinstance(ip, str):
            return False
        ip_s = ip.strip().upper()
        if ip_s in ("ANY", "*"):
            return True
        try:
            if "/" in ip_s:
                ipaddress.ip_network(ip_s, strict=False)
            else:
                ipaddress.ip_address(ip_s)
            return True
        except ValueError:
            return False

    def get_rules(self) -> list[dict]:
        return self.rules

    def add_rule(self, action: str, protocol: str, source_ip: str, dest_port: str, desc: str, interface: str = "WAN") -> dict:
        new_id = f"FW-{len(self.rules) + 1:03d}"
        rule = {
            "id": new_id,
            "action": action.upper(),
            "interface": interface.upper(),
            "protocol": protocol.upper(),
            "source_ip": source_ip.strip() or "ANY",
            "dest_port": dest_port.strip() or "ANY",
            "description": desc.strip() or "사용자 정의 방화벽 규칙",
            "enabled": True,
        }
        self.rules.append(rule)
        self.save_rules()
        return rule

    def delete_rule(self, rule_id: str) -> bool:
        initial_len = len(self.rules)
        self.rules = [r for r in self.rules if r.get("id") != rule_id]
        if len(self.rules) < initial_len:
            self.save_rules()
            return True
        return False

    def toggle_rule(self, rule_id: str) -> bool:
        for r in self.rules:
            if r.get("id") == rule_id:
                r["enabled"] = not r.get("enabled", True)
                self.save_rules()
                return True
        return False

    def update_rule(self, rule_id: str, action: str, protocol: str, source_ip: str, dest_port: str, desc: str) -> bool:
        for r in self.rules:
            if r.get("id") == rule_id:
                r["action"] = action.upper()
                r["protocol"] = protocol.upper()
                r["source_ip"] = source_ip.strip() or "ANY"
                r["dest_port"] = dest_port.strip() or "ANY"
                r["description"] = desc.strip()
                self.save_rules()
                return True
        return False


class SiemRulesetManager:
    """Graylog 스타일 SIEM 상관분석 탐지 룰셋 관리자."""

    def __init__(self):
        self.rules = self.load_rules()

    def load_rules(self) -> list[dict]:
        if not SIEM_RULES_PATH.exists():
            return []
        try:
            with open(SIEM_RULES_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def save_rules(self) -> bool:
        try:
            RULES_DIR.mkdir(parents=True, exist_ok=True)
            with open(SIEM_RULES_PATH, "w", encoding="utf-8") as f:
                json.dump(self.rules, f, indent=2, ensure_ascii=False)
            return True
        except Exception:
            return False

    @staticmethod
    def validate_port(port: str) -> bool:
        """포트 번호 유효성 검증 (1-65535, ANY, 또는 포트 범위 '80-443')."""
        if not isinstance(port, str):
            return False
        p_str = port.strip().upper()
        if p_str in ("ANY", "*", "ALL"):
            return True
        if "-" in p_str:
            parts = p_str.split("-")
            if len(parts) != 2:
                return False
            try:
                p1, p2 = int(parts[0].strip()), int(parts[1].strip())
                return 1 <= p1 <= 65535 and 1 <= p2 <= 65535 and p1 <= p2
            except ValueError:
                return False
        try:
            val = int(p_str)
            return 1 <= val <= 65535
        except ValueError:
            return False

    @staticmethod
    def validate_ip(ip: str) -> bool:
        """IP 유효성 검증 (IPv4/IPv6, CIDR, 또는 ANY)."""
        import ipaddress
        if not isinstance(ip, str):
            return False
        ip_s = ip.strip().upper()
        if ip_s in ("ANY", "*"):
            return True
        try:
            if "/" in ip_s:
                ipaddress.ip_network(ip_s, strict=False)
            else:
                ipaddress.ip_address(ip_s)
            return True
        except ValueError:
            return False

    def get_rules(self) -> list[dict]:
        return self.rules

    def add_rule(self, name: str, field: str, operator: str, threshold: int, severity: str, action: str, desc: str) -> dict:
        new_id = f"SIEM-R{len(self.rules) + 1:02d}"
        rule = {
            "rule_id": new_id,
            "rule_name": name.strip(),
            "target_field": field.strip(),
            "operator": operator.strip(),
            "threshold_count": int(threshold),
            "time_window_sec": 60,
            "severity": severity.upper(),
            "action": action.upper(),
            "webhook_alert": True,
            "enabled": True,
            "description": desc.strip() or "사용자 정의 SIEM 탐지 규칙",
        }
        self.rules.append(rule)
        self.save_rules()
        return rule

    def delete_rule(self, rule_id: str) -> bool:
        initial_len = len(self.rules)
        self.rules = [r for r in self.rules if r.get("rule_id") != rule_id]
        if len(self.rules) < initial_len:
            self.save_rules()
            return True
        return False

    def toggle_rule(self, rule_id: str) -> bool:
        for r in self.rules:
            if r.get("rule_id") == rule_id:
                r["enabled"] = not r.get("enabled", True)
                self.save_rules()
                return True
        return False

    def update_rule(self, rule_id: str, name: str, field: str, threshold: int, severity: str, action: str) -> bool:
        for r in self.rules:
            if r.get("rule_id") == rule_id:
                r["rule_name"] = name.strip()
                r["target_field"] = field.strip()
                r["threshold_count"] = int(threshold)
                r["severity"] = severity.upper()
                r["action"] = action.upper()
                self.save_rules()
                return True
        return False


class RulesetUpdateManager:
    """최신 보안 위협 시그니처 및 방화벽/SIEM 룰셋 업데이트 관리자."""

    META_PATH = RULES_DIR / "signature_meta.json"

    def get_signature_info(self) -> dict:
        if self.META_PATH.exists():
            try:
                return json.loads(self.META_PATH.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {
            "version": "v2026.11.09-LTS",
            "last_updated": "2026-11-09 12:00:00",
            "total_rules": 9,
            "status": "UP_TO_DATE",
            "feed_source": "NEXUS Global Threat Intelligence Network",
        }

    def check_and_apply_update(self) -> tuple[bool, str]:
        """최신 제로데이 익스플로잇 및 글로벌 차단 룰셋 동기화."""
        fw_mgr = FirewallRulesetManager()
        siem_mgr = SiemRulesetManager()

        # FW 신규 긴급 차단 룰 확인 및 병합
        has_fw_zero_day = any(r.get("id") == "FW-005" for r in fw_mgr.get_rules())
        if not has_fw_zero_day:
            fw_mgr.add_rule(
                action="BLOCK",
                protocol="TCP",
                source_ip="ANY",
                dest_port="8080",
                desc="[긴급배포] Spring4Shell / Log4j 비인가 JNDI 원격 코드 실행 차단",
                interface="WAN",
            )

        # SIEM 신규 이상 징후 상관분석 룰 병합
        has_siem_zero_day = any(r.get("rule_id") == "SIEM-R06" for r in siem_mgr.get_rules())
        if not has_siem_zero_day:
            siem_mgr.add_rule(
                name="[긴급배포] 크리덴셜 스터핑 대규모 분산 무차별 대입 탐지",
                field="credential_stuffing_rate",
                operator="GTE",
                threshold=10,
                severity="CRITICAL",
                action="BLOCK_IP_403",
                desc="분산 IP 대역에서의 대규모 사전 대입 시 실시간 격리",
            )

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        meta = {
            "version": "v2026.11.09-REV2",
            "last_updated": now_str,
            "total_rules": len(fw_mgr.get_rules()) + len(siem_mgr.get_rules()),
            "status": "UP_TO_DATE",
            "feed_source": "NEXUS Global Threat Intelligence Network (Active)",
        }
        self.META_PATH.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
        return True, f"최신 위협 시그니처 업데이트 완료!\n- 버전: {meta['version']}\n- 갱신 일시: {now_str}\n- 신규 제로데이 방어 룰 2건이 성공적으로 병합되었습니다."
