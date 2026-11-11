# -*- coding: utf-8 -*-
"""NEXUS-GUARD Engine: 통합 환경 설정 관리자 (Config Manager)."""
import json
import os
from pathlib import Path
from typing import Any, Dict, Tuple, Union

CONFIG_DIR = Path(__file__).resolve().parents[1]
CONFIG_FILE = CONFIG_DIR / "config.json"
CONFIG_EXAMPLE_FILE = CONFIG_DIR / "config.example.json"

DEFAULT_CONFIG: Dict[str, Any] = {
    "_comment": "NEXUS-GUARD 통합 환경 설정 파일 (신규 설치: 사용자 지정 필요 / 1-클릭 가이드 지원)",
    "version": "2.5.0-LTS",
    "deployment_mode": "standalone",
    "target_service": {
        "web_portal_url": "",
        "web_portal_host": "",
        "web_portal_port": "",
        "db_host": "",
        "db_port": "",
        "db_name": "",
        "db_user": "",
    },
    "ai_xdr_engine": {
        "primary_provider": "groq",
        "groq_api_key": "",
        "groq_model": "openai/gpt-oss-120b",
        "nvidia_api_key": "",
        "nvidia_base_url": "https://integrate.api.nvidia.com/v1",
        "nvidia_model": "nvidia/llama-3.1-nemotron-70b-instruct",
        "ollama_base_url": "",
        "ollama_model": "qwen2.5:7b",
        "threat_score_threshold": 80,
        "timeout_seconds": 10,
    },
    "external_integrations": {
        "pfsense": {
            "enabled": False,
            "host": "",
            "webgui_port": 443,
            "feed_url": "",
            "alias_name": "",
            "polling_interval_minutes": 1,
            "block_duration_minutes": 15,
            "sync_windows_netsh": True,
            "api_token": "",
        },
        "graylog": {
            "enabled": False,
            "host": "",
            "gelf_udp_port": 12201,
            "web_port": 9000,
            "protocol": "UDP",
            "stream_name": "",
            "min_log_level": "WARNING",
            "facility": "nexus-guard-soc",
        },
        "wazuh": {
            "enabled": False,
            "manager_host": "",
            "manager_port": 1514,
            "api_port": 55000,
            "agent_id": "",
            "agent_name": "",
            "fim_interval_seconds": 10,
            "hash_algorithm": "SHA-256",
            "monitored_paths": "",
        },
        "webhooks": {
            "discord_alert_url": "",
            "slack_alert_url": "",
            "n8n_soar_url": "",
            "alert_threshold": "HIGH",
            "enable_incident_auto_dispatch": False,
        },
    },
    "active_defense": {
        "defense_mode": "ON",
        "block_duration_minutes": 15,
        "decoy_paths": [
            "/.env",
            "/.git",
            "/.git/config",
            "/.aws/credentials",
            "/wp-login.php",
            "/wp-admin",
            "/phpmyadmin",
            "/admin.php",
            "/config.json",
            "/.ds_store",
        ],
        "protected_whitelist_ips": [
            "127.0.0.1",
            "::1",
            "192.168.3.10",
            "192.168.3.14",
            "192.168.3.15",
        ],
    },
    "file_integrity_monitoring": {
        "auto_watch_enabled": True,
        "polling_interval_seconds": 10,
        "watch_directories": [
            "app",
            "db",
            "nexus_guard",
        ],
        "watch_extensions": [
            ".py",
            ".env",
            ".sql",
            ".json",
        ],
    },
}


class GuardConfigManager:
    """설정 파일 로딩 및 영구 저장을 담당하는 매니저."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(GuardConfigManager, cls).__new__(cls)
            cls._instance._data = {}
            cls._instance.load_config()
        return cls._instance

    def load_config(self) -> Dict[str, Any]:
        """config.json을 로드하며, 없으면 기본값으로 생성합니다."""
        if not CONFIG_FILE.exists():
            self.save_config(DEFAULT_CONFIG)
            # example 파일도 생성
            CONFIG_EXAMPLE_FILE.write_text(json.dumps(DEFAULT_CONFIG, indent=2, ensure_ascii=False), encoding="utf-8")
            self._data = dict(DEFAULT_CONFIG)
        else:
            try:
                self._data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            except Exception:
                self._data = dict(DEFAULT_CONFIG)

        # .env 파일과 동기화 (GROQ_API_KEY 등)
        env_path = CONFIG_DIR.parent / ".env"
        if env_path.exists():
            for line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.startswith("GROQ_API_KEY="):
                    val = line.split("=", 1)[1].strip()
                    if val and not self._data["ai_xdr_engine"].get("groq_api_key"):
                        self._data["ai_xdr_engine"]["groq_api_key"] = val
                elif line.startswith("NVIDIA_API_KEY="):
                    val = line.split("=", 1)[1].strip()
                    if val and not self._data["ai_xdr_engine"].get("nvidia_api_key"):
                        self._data["ai_xdr_engine"]["nvidia_api_key"] = val

        return self._data

    def get_data(self) -> Dict[str, Any]:
        return self._data

    def get_config(self) -> Dict[str, Any]:
        return self._data

    def save_config(self, new_data: Dict[str, Any]) -> None:
        """설정을 config.json에 파일로 기록합니다."""
        self._data = new_data
        CONFIG_FILE.write_text(json.dumps(new_data, indent=2, ensure_ascii=False), encoding="utf-8")
        if not CONFIG_EXAMPLE_FILE.exists():
            CONFIG_EXAMPLE_FILE.write_text(json.dumps(DEFAULT_CONFIG, indent=2, ensure_ascii=False), encoding="utf-8")

    def reset_to_defaults(self) -> Dict[str, Any]:
        """기본 설정으로 초기화합니다."""
        self.save_config(DEFAULT_CONFIG)
        return self._data

    def apply_preset(self, preset_key: str) -> Dict[str, Any]:
        """원클릭 환경 프리셋(초보자 단독, 엔터프라이즈 SOC, 로컬 개발) 적용."""
        self._data["deployment_mode"] = preset_key
        if preset_key == "standalone":
            # 초보자 권장: 외부 장비 없이 로컬 WAF + 호스트 netsh + FIM으로 완전 독립 구동
            self._data.setdefault("external_integrations", {})
            self._data["external_integrations"].setdefault("pfsense", {})["enabled"] = False
            self._data["external_integrations"].setdefault("graylog", {})["enabled"] = False
            self._data["external_integrations"].setdefault("wazuh", {})["enabled"] = False
            self._data.setdefault("active_defense", {})["defense_mode"] = "ON"
            self._data.setdefault("target_service", {})["web_portal_url"] = "http://127.0.0.1:5070"
            self._data.setdefault("target_service", {})["db_host"] = "127.0.0.1"
        elif preset_key == "enterprise_soc":
            # 기업 관제: pfSense 피드, Graylog GELF, Wazuh Agent 전면 활성화
            self._data.setdefault("external_integrations", {})
            self._data["external_integrations"].setdefault("pfsense", {})["enabled"] = True
            self._data["external_integrations"].setdefault("graylog", {})["enabled"] = True
            self._data["external_integrations"].setdefault("wazuh", {})["enabled"] = True
            self._data["external_integrations"]["pfsense"]["host"] = "192.168.3.1"
            self._data["external_integrations"]["graylog"]["host"] = "192.168.3.10"
            self._data["external_integrations"]["wazuh"]["manager_host"] = "192.168.3.20"
        elif preset_key == "developer_local":
            # 개발자: 로컬 Docker 컨테이너 및 Ollama 로컬 LLM 바인딩
            self._data.setdefault("ai_xdr_engine", {})["primary_provider"] = "ollama"
            self._data["ai_xdr_engine"]["ollama_base_url"] = "http://127.0.0.1:11434"
            self._data.setdefault("target_service", {})["web_portal_url"] = "http://127.0.0.1:5070"

        self.save_config(self._data)
        return self._data

    def export_bundle(self, export_path: Union[str, Path]) -> bool:
        """설정 및 룰셋 전체를 단일 백업 번들 파일로 내보내기."""
        try:
            p = Path(export_path)
            rules_dir = CONFIG_DIR / "rules"
            fw_rules = []
            siem_rules = []
            if (rules_dir / "firewall_rules.json").exists():
                fw_rules = json.loads((rules_dir / "firewall_rules.json").read_text(encoding="utf-8"))
            if (rules_dir / "siem_rules.json").exists():
                siem_rules = json.loads((rules_dir / "siem_rules.json").read_text(encoding="utf-8"))

            bundle = {
                "bundle_version": "2.5.0-LTS",
                "export_timestamp": p.stem,
                "config": self._data,
                "firewall_rules": fw_rules,
                "siem_rules": siem_rules,
            }
            p.write_text(json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8")
            return True
        except Exception:
            return False

    def import_bundle(self, import_path: Union[str, Path]) -> Tuple[bool, str]:
        """백업 번들 파일에서 설정 및 룰셋을 완벽 복원."""
        try:
            p = Path(import_path)
            if not p.exists():
                return False, f"백업 파일 '{p.name}'을 찾을 수 없습니다."
            content = json.loads(p.read_text(encoding="utf-8"))
            if "config" in content:
                self.save_config(content["config"])
            rules_dir = CONFIG_DIR / "rules"
            rules_dir.mkdir(parents=True, exist_ok=True)
            if "firewall_rules" in content:
                (rules_dir / "firewall_rules.json").write_text(
                    json.dumps(content["firewall_rules"], indent=2, ensure_ascii=False), encoding="utf-8"
                )
            if "siem_rules" in content:
                (rules_dir / "siem_rules.json").write_text(
                    json.dumps(content["siem_rules"], indent=2, ensure_ascii=False), encoding="utf-8"
                )
            return True, f"백업 번들 '{p.name}'에서 설정 및 룰셋을 성공적으로 복원했습니다."
        except Exception as e:
            return False, f"복원 중 오류 발생: {e}"
