# -*- coding: utf-8 -*-
"""NEXUS-GUARD AI Engine: 초고속 4중 하이브리드 AI 캐스케이드 라우터.

1순위: Groq Cloud LPU (openai/gpt-oss-120b) -> 0.5초 초고속 추론 (98% 단축)
2순위: NVIDIA NIM 클라우드 -> 복합 침해 분석 1차 백업
3순위: Docker Ollama (온프레미스 qwen2.5:7b) -> 폐쇄망/네트워크 단절 대비
4순위: Built-in Rule Engine (0.01초 내장) -> 최악의 전산 마비 시 가용성 100% 보장
"""
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional, Tuple


MAX_RESPONSE_BYTES = 256 * 1024
MAX_ANALYSIS_CHARS = 2000


def _read_json(response) -> Dict[str, Any]:
    raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("response_too_large")
    return json.loads(raw.decode("utf-8"))


def _clean_text(value: Any) -> str:
    """LLM 출력은 비신뢰 입력: 문자열이 아니거나 비어 있으면 예외로 다음 단계 폴백을 유도한다."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("invalid_model_output")
    return value[:MAX_ANALYSIS_CHARS]


class AiCascadeRouter:
    """4계층 고가용성 AI 추론 라우터."""

    def __init__(self):
        self.groq_api_key = os.environ.get("GROQ_API_KEY", "")
        self.nvidia_api_key = os.environ.get("NVIDIA_API_KEY", "")
        ollama = os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
        # file:// 등 urllib 이 지원하는 다른 스킴으로 로컬 파일을 읽게 만드는 설정 오염 방지: http(s) 만 허용
        if urllib.parse.urlparse(ollama).scheme not in ("http", "https"):
            ollama = "http://127.0.0.1:11434"
        self.ollama_url = ollama.rstrip("/")

    def infer(self, prompt: str, system_prompt: str = "당신은 능동형 사이버 보안 AI 판정관입니다.",
              event: Optional[Dict[str, Any]] = None) -> Tuple[str, str, float]:
        """4단계 폴백을 순회하며 위협 분석을 수행합니다.
        
        반환값:
            (응답_텍스트, 사용된_프로바이더_명칭, 소요_시간_초)
        """
        start_time = time.time()

        # 1. Groq LPU (0.5초 초고속 엔진)
        if self.groq_api_key:
            try:
                res = self._call_groq(prompt, system_prompt)
                return res, "Groq LPU (gpt-oss-120b)", round(time.time() - start_time, 3)
            except Exception:
                pass

        # 2. NVIDIA NIM 클라우드
        if self.nvidia_api_key:
            try:
                res = self._call_nvidia(prompt, system_prompt)
                return res, "NVIDIA NIM", round(time.time() - start_time, 3)
            except Exception:
                pass

        # 3. 온프레미스 Ollama (로컬 CPU/GPU)
        try:
            res = self._call_ollama(prompt, system_prompt)
            return res, "Ollama Local (qwen2.5)", round(time.time() - start_time, 3)
        except Exception:
            pass

        # 4. Built-in 정규식/룰 엔진 (0.01초 절대 가용성 보장)
        res = self._call_builtin(prompt, event)
        return res, "Builtin Guard Engine", round(time.time() - start_time, 3)

    def _call_groq(self, prompt: str, system: str) -> str:
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.groq_api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": "openai/gpt-oss-120b",
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 512,
        }
        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers)
        with urllib.request.urlopen(req, timeout=5) as response:
            data = _read_json(response)
            return _clean_text(data["choices"][0]["message"]["content"])

    def _call_nvidia(self, prompt: str, system: str) -> str:
        url = "https://integrate.api.nvidia.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.nvidia_api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": "nvidia/llama-3.1-nemotron-70b-instruct",
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "max_tokens": 512,
        }
        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers)
        with urllib.request.urlopen(req, timeout=5) as response:
            data = _read_json(response)
            return _clean_text(data["choices"][0]["message"]["content"])

    def _call_ollama(self, prompt: str, system: str) -> str:
        url = f"{self.ollama_url}/api/generate"
        payload = {
            "model": "qwen2.5:7b",
            "prompt": f"{system}\n\n[사용자 질의]: {prompt}",
            "stream": False,
        }
        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as response:
            data = _read_json(response)
            return _clean_text(data["response"])

    # 구조화 이벤트 기반 내장 룰 (프롬프트 전체 키워드 검색은 username=salary 같은 값으로 타인을 BLOCK 시키거나
    # XSS/경로 순회/로그인 실패 폭주를 20점으로 놓쳤다). 판정에는 event 유형·경로·요청 값만 쓰고 사용자명은 쓰지 않는다.
    _RX_DECOY = re.compile(r"(?i)(?:^|/)(?:\.env|\.git|\.aws|wp-login\.php|wp-admin|phpmyadmin|xmlrpc\.php|server-status)(?:$|[/.])")
    _RX_XSS = re.compile(r"(?i)(<\s*script|<\s*img[^>]*\bon\w+\s*=|<\s*svg[^>]*\bon\w+|javascript\s*:|\bon(?:error|load|click)\s*=)")
    _RX_SQLI = re.compile(r"(?i)(\bunion\b\s+(?:all\s+)?select\b|\bor\b\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+|\bsleep\s*\(|\bbenchmark\s*\(|;\s*drop\b|'\s*(?:or|and)\s+')")
    _RX_TRAVERSAL = re.compile(r"(?i)(\.\./|\.\.\\|%2e%2e(?:%2f|/|%5c)|etc/passwd|etc/shadow)")

    def _call_builtin(self, prompt: str, event: Optional[Dict[str, Any]] = None) -> str:
        if isinstance(event, dict):
            return self._builtin_for_event(event)
        prompt_lower = prompt.lower()
        if any(kw in prompt_lower for kw in [".env", ".git", "wp-admin", "scan"]):
            return "위험도: 90점 | 판정: 악의적 정찰 목적의 디코이/경로 스캔 탐지. 즉시 IP 차단 권고."
        if any(kw in prompt_lower for kw in ["auth_failed", "brute_force", "password"]):
            return "위험도: 85점 | 판정: 무차별 대입(Brute-Force) 계정 탈취 시도 탐지. 계정 15분 잠금 및 세션 만료 권고."
        if any(kw in prompt_lower for kw in ["bola", "idor", "confidential", "salary"]):
            return "위험도: 95점 | 판정: 비인가 권한 승격 및 기밀 데이터 무단 열람 시도 탐지. 403 차단 및 감사 로그 보존 권고."
        return "위험도: 20점 | 판정: 통상적인 보안 로그. 특이 위협 징후 미발견."

    def _builtin_for_event(self, event: Dict[str, Any]) -> str:
        etype = str(event.get("event") or event.get("event_type") or "").lower()
        values = " ".join(str(event.get(k, "")) for k in ("path", "value", "query", "url", "request") if event.get(k) is not None)
        try:
            count = int(event.get("count") or event.get("failed_attempts") or event.get("event_count") or 0)
        except (TypeError, ValueError):
            count = 0
        if self._RX_DECOY.search(values) or etype in ("decoy_probe", "decoy_triggered"):
            return "위험도: 90점 | 판정: 악의적 정찰 목적의 디코이/경로 스캔 탐지. 즉시 IP 차단 권고."
        if etype in ("bola", "idor", "restricted_document_read") or "bola" in etype or "idor" in etype:
            return "위험도: 95점 | 판정: 비인가 권한 승격 및 기밀 데이터 무단 열람 시도 탐지. 403 차단 및 감사 로그 보존 권고."
        if self._RX_SQLI.search(values) or self._RX_XSS.search(values):
            return "위험도: 85점 | 판정: 인젝션(SQLi/XSS) 공격 페이로드 탐지. IP 차단 및 감사 로그 보존 권고."
        if self._RX_TRAVERSAL.search(values):
            return "위험도: 85점 | 판정: 경로 순회(Path Traversal) 시도 탐지. IP 차단 권고."
        if etype in ("auth_failed", "brute_force", "login_failure", "bad_password") and count >= 5 or etype == "brute_force":
            return "위험도: 85점 | 판정: 무차별 대입(Brute-Force) 계정 탈취 시도 탐지. 계정 15분 잠금 및 세션 만료 권고."
        if etype in ("auth_failed", "login_failure", "bad_password", "authz_deny"):
            return "위험도: 40점 | 판정: 개별 인증/권한 실패. 반복 여부 모니터링 필요."
        return "위험도: 20점 | 판정: 통상적인 보안 로그. 특이 위협 징후 미발견."
