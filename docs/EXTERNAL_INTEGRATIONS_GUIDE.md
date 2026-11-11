# 🔌 [NEXUS-GUARD] 외부 연동 프로그램 구성 및 셋업 종합 가이드 (External Integrations Master Runbook)

> **문서 번호:** NX-INT-GUIDE-2026-V1  
> **작성자:** 홍주형 (웹/DB 보안 하드닝 총괄 · 코어 아키텍처 · AI 엔지니어링)  
> **시스템 버전:** NEXUS-GUARD v2.5.0-LTS & NEXUS WORK 실증 포털  
> **최종 갱신일:** 2026-11-11  

---

## 📌 목차

1. [외부 연동 아키텍처 및 통신 토폴로지](#1-외부-연동-아키텍처-및-통신-토폴로지)
2. [전체 연동 프로그램 프로토콜 & 포트 맵](#2-전체-연동-프로그램-프로토콜--포트-맵)
3. [보호 대상 웹 포털 & 데이터베이스 연동](#3-보호-대상-웹-포털--데이터베이스-연동)
4. [4중 AI-XDR 하이브리드 추론 엔진 연동 (Groq / Ollama / NVIDIA NIM)](#4-4중-ai-xdr-하이브리드-추론-엔진-연동-groq--ollama--nvidia-nim)
5. [pfSense 차세대 네트워크 경계 방화벽 연동 (pfBlockerNG)](#5-pfsense-차세대-네트워크-경계-방화벽-연동-pfblockerng)
6. [Graylog 중앙 SIEM 연동 (GELF UDP 12201)](#6-graylog-중앙-siem-연동-gelf-udp-12201)
7. [Wazuh 호스트 EDR / FIM 연동 및 Standalone 가동](#7-wazuh-호스트-edr--fim-연동-및-standalone-가동)
8. [Webhooks & n8n SOAR 오케스트레이션 자동화 연동](#8-webhooks--n8n-soar-오케스트레이션-자동화-연동)
9. [Windows 호스트 커널 방화벽 (netsh) 연동 및 긴급 격리](#9-windows-호스트-커널-방화벽-netsh-연동-및-긴급-격리)
10. [GUI 4단계 온보딩 위저드 및 1-클릭 프리셋 프로파일 활용법](#10-gui-4단계-온보딩-위저드-및-1-클릭-프리셋-프로파일-활용법)
11. [연동 실패 시 원인 진단 및 트러블슈팅 FAQ](#11-연동-실패-시-원인-진단-및-트러블슈팅-faq)

---

## 1. 외부 연동 아키텍처 및 통신 토폴로지

NEXUS-GUARD는 엔터프라이즈 SOC(보안 관제 센터) 인프라와의 유기적 협조 및 외부 장비가 없는 일반 PC 환경에서의 완전한 자체 완결형(Standalone) 가동을 동시에 만족하도록 설계되었습니다.

```mermaid
flowchart TD
    subgraph INGRESS["[1] 외부 네트워크 경계 (Ingress Border)"]
        HACKER["공격자 / 외부 트래픽"] -->|인바운드 패킷| PFSENSE["pfSense 경계 방화벽\n(pfBlockerNG IP 드롭)"]
        PFSENSE -->|허용 트래픽| NETSH["Windows netsh 호스트 방화벽\n(커널 레벨 패킷 필터링)"]
    end

    subgraph WORKSPACE["[2] NEXUS-GUARD 엔드포인트 방어 & 웹 포털"]
        NETSH -->|포트 5070| WAF["NEXUS-GUARD 미들웨어\n(WAF 403 차단 & 디코이 트랩)"]
        WAF --> APP["NEXUS WORK 웹 포털\n(Flask / Python)"]
        APP --> DB[("MySQL / MariaDB\n(포트 3306/3307)")]
        
        GUI["NEXUS-GUARD 데스크톱 콘솔\n(CustomTkinter 60FPS)"] <-->|실시간 동기화| ENGINE["NEXUS-GUARD 코어 엔진\n(FIM, 차단표, AST 파서)"]
        ENGINE --> FIM["자체 SHA-256 FIM 감시\n(app, db, .env 무결성 검증)"]
    end

    subgraph AI_CASCADE["[3] 4중 AI-XDR 하이브리드 분석 엔진"]
        ENGINE -->|1순위 (0.5초 LPU)| GROQ["Groq LPU 클라우드\n(openai/gpt-oss-120b)"]
        ENGINE -.->|2순위 (엔터프라이즈)| NIM["NVIDIA NIM API\n(Nemotron-70B)"]
        ENGINE -.->|3순위 (폐쇄망/오프라인)| OLLAMA["Ollama 로컬 LLM\n(qwen2.5:7b / 11434)"]
        ENGINE -.->|4순위 (오프라인 무장애)| RULE["시스템 내장 휴리스틱 룰\n(100% 무중단 폴백)"]
    end

    subgraph SIEM_SOAR["[4] 중앙 관제 & 자동 대응 (SIEM / SOAR)"]
        ENGINE -->|GELF UDP 12201| GRAYLOG["Graylog 중앙 SIEM\n(이상 징후 상관 분석)"]
        ENGINE -.->|TCP 1514| WAZUH["Wazuh Manager\n(엔터프라이즈 호스트 감사)"]
        ENGINE -->|Webhook POST 5678| N8N["n8n SOAR 자동화 워크플로우\n(Jira 티켓 발행 / 슬랙 전파)"]
        ENGINE -->|Incoming Webhook| CHAT["Discord / Slack\n(실시간 침해 경보 채널)"]
    end
```

---

## 2. 전체 연동 프로그램 프로토콜 & 포트 맵

| 연동 대상 솔루션 | 프로토콜 / 기본 포트 | 설정 파일 JSON 키 (`nexus_guard/config.json`) | 주요 기능 및 연동 목적 | 페일세이프 (외부 장비 부재 시) |
|---|---|---|---|---|
| **🌐 보호 대상 웹 포털** | HTTP / `5070` (또는 `5000`) | `target_service.web_portal_url` | WAF 인스펙션, 디코이 트랩, 침해 IP 403 차단 | 단독 테스트 주소(127.0.0.1:5070) 자동 채우기 지원 |
| **🗄️ 보호 대상 DB** | TCP / `3306` (또는 `3307`) | `target_service.db_host`, `db_port` | 포트 개방 감사, AST 정적 쿼리 점검 타깃 | 로컬 소스코드 파서만으로 정적 SQLi 100% 진단 |
| **🤖 Groq LPU (AI-XDR)** | HTTPS / `443` REST API | `ai_xdr_engine.groq_api_key` | 0.5초 초고속 LPU 기반 AI 실시간 위협 트리아지 판정 | 내장 정규식 및 휴리스틱 룰 엔진으로 100% 자동 폴백 |
| **🦙 Ollama (로컬 LLM)** | HTTP / `11434` REST API | `ai_xdr_engine.ollama_base_url` | 폐쇄망/오프라인 환경 전용 로컬 On-Premise AI 추론 | 인터넷 단절 상태에서도 로컬 GPU/CPU로 완전 독립 판정 |
| **🧱 pfSense 방화벽** | HTTP / `443` (WebGUI) | `external_integrations.pfsense.feed_url` | pfBlockerNG 패키지 통한 경계 방화벽 인바운드 Drop | Windows 호스트 방화벽(netsh) 로컬 차단 위주로 가동 |
| **📊 Graylog (SIEM)** | GELF UDP / `12201` | `external_integrations.graylog.host` | SOC 통합 보안 감사 로그 실시간 스트리밍 수집 | 로컬 `logs/security.jsonl`에 누락 없이 영구 보존 |
| **🛡️ Wazuh (EDR / FIM)** | TCP / `1514`, `55000` | `external_integrations.wazuh.manager_host` | 엔터프라이즈 호스트 보안 감사 및 EDR 수집 | 내장 SHA-256 FIM 엔진이 10초 주기로 100% 독립 감시 |
| **⚡ n8n (SOAR)** | HTTP / `5678` Webhook | `external_integrations.webhooks.n8n_soar_url` | 인시던트 티켓 자동 발행, Slack 알림, 대응 자동화 | 로컬 이벤트 큐 및 GUI 팝업 알림으로 안전 유지 |
| **💬 Discord / Slack** | HTTPS / `443` Webhook | `external_integrations.webhooks.discord_alert_url` | 보안 관제팀 실시간 리치 임베드 알림 카드 발송 | 콘솔 UI 실시간 위협 피드에 안전 적재 |
| **💻 Windows 커널 방화벽** | Windows OS `netsh` API | `external_integrations.pfsense.sync_windows_netsh` | OS 커널 레벨 네트워크 패킷 차단 & 1-클릭 호스트 격리 | 관리자 권한 실행 시 자동 가동 (루프백 페일세이프 보호) |

---

## 3. 보호 대상 웹 포털 & 데이터베이스 연동

NEXUS-GUARD는 특정 웹 서비스에 고정되지 않는 독립형 보안 에이전트로 패키징되어 있어, 처음 실행 시 `target_service`는 빈 상태(`""`)로 시작합니다.

### 3.1 웹 포털 연동 절차 (`NEXUS WORK` 기준)
1. **포털 서버 실행:**
   ```bash
   # MySQL 컨테이너 기동 후 웹 서버 실행
   docker compose up -d
   .venv\Scripts\python run.py
   # 기본 웹 포털 주소: http://127.0.0.1:5070 (상태 확인: http://127.0.0.1:5070/healthz)
   ```
2. **NEXUS-GUARD 데스크톱 콘솔 실행:**
   ```bash
   .venv\Scripts\python -m nexus_guard.gui
   ```
3. **[⚙️ 환경 설정 & 외부 연동] 탭에서 등록:**
   - 상단 `[⚡ 내 PC 로컬 테스트 주소 자동 채우기 (127.0.0.1:5070)]` 버튼 클릭.
   - 또는 수동 입력:
     - `웹 포털 URL`: `http://127.0.0.1:5070`
     - `포털 IP / Host`: `127.0.0.1`
     - `포털 Port`: `5070`
     - `DB Host`: `127.0.0.1`
     - `DB Port`: `3307` (또는 `3306`)
   - 하단의 `[💾 변경 설정 저장]` 버튼 클릭.
4. **결과 확인:**
   - 대시보드 상단 센서 스트립의 **`● 감시 웹 포털:`** 라벨이 `미등록`에서 `http://127.0.0.1:5070` (초록색 `[CORE]`)으로 즉시 전환됩니다.

### 3.2 일반 타사 Flask 웹 서비스에 장착하는 방법
기존에 운영 중인 Flask 웹사이트가 있다면 단 한 줄로 NEXUS-GUARD의 모든 보호 체계(디코이 허니팟, 실시간 IP 차단, 보안 헤더 5종)를 장착할 수 있습니다:

```python
from flask import Flask
from nexus_guard import NexusGuard

app = Flask(__name__)

# 단 한 줄로 능동 보안 가드 초기화
guard = NexusGuard()
guard.init_app(app)

if __name__ == "__main__":
    app.run(port=8080)
```

---

## 4. 4중 AI-XDR 하이브리드 추론 엔진 연동 (Groq / Ollama / NVIDIA NIM)

NEXUS-GUARD는 API 호출 비용, 응답 지연 시간, 폐쇄망 오프라인 환경을 모두 해결하기 위해 **4중 계층형 캐스케이드 라우터([`AiCascadeRouter`](file:///C:/Users/user/Desktop/nexus-work-portfolio/nexus_guard/ai_engine/cascade_router.py))**를 탑재하고 있습니다.

### 4.1 Groq LPU 연동 (초고속 실시간 트리아지 - 권장)
- **특징:** 전용 언어 처리 장치(LPU)를 활용하여 0.5초 수준의 압도적인 속도로 위협 로그를 판정합니다.
- **설정 절차:**
  1. [Groq Console (https://console.groq.com)](https://console.groq.com) 접속 및 무료 계정 생성.
  2. `API Keys` 메뉴에서 신규 키 발급 (`gsk_...`).
  3. 콘솔 [설정] 탭의 `Groq API Key` 입력란에 붙여넣기.
  4. 모델 선택: `openai/gpt-oss-120b` (기본값) 또는 `llama-3.3-70b-versatile`.
  5. `[💾 변경 설정 저장]` 클릭.

### 4.2 Ollama 온프레미스 로컬 LLM 연동 (완전 폐쇄망/오프라인)
- **특징:** 외부 인터넷 접속이 불가능한 금융/국방 인트라넷 환경에서 PC 내부 자원만으로 동작합니다.
- **설정 절차:**
  1. Ollama 설치 후 모델 다운로드:
     ```bash
     ollama run qwen2.5:7b
     # 또는 경량 모델: ollama run llama3.2
     ```
  2. Ollama REST API 데몬이 `http://127.0.0.1:11434`에서 자동 대기합니다.
  3. 콘솔 [설정] 탭에서:
     - `기본 AI 엔진`: `Ollama (로컬 폐쇄망 On-Premise)` 선택.
     - `Ollama Base URL`: `http://127.0.0.1:11434`
     - `Ollama 모델명`: `qwen2.5:7b` (또는 로컬에 다운로드한 모델명)
  4. 외부 API 키 없이 100% 로컬 AI 보안 관제가 작동합니다.

### 4.3 NVIDIA NIM 연동 (엔터프라이즈 고신뢰 모델)
- **설정 절차:**
  1. [NVIDIA build.nvidia.com](https://build.nvidia.com)에서 무료 1,000 크레딧 키 발급 (`nvapi-...`).
  2. `NVIDIA API Key`에 입력 (기본 Base URL: `https://integrate.api.nvidia.com/v1`, 모델: `nvidia/llama-3.1-nemotron-70b-instruct`).

### 4.4 API 키가 없을 때의 동작 (시스템 내장 규칙 폴백)
- API 키를 전혀 입력하지 않거나 인터넷이 끊겨도 안심하십시오.
- NEXUS-GUARD 내부의 **CWE/OWASP 기반 정규식 및 휴리스틱 룰 엔진**이 4단계 폴백으로 즉시 자동 가동되어, 디코이 탐침, SQLi, LLM 탈옥 시도를 오탐 없이 100% 차단합니다.

---

## 5. pfSense 차세대 네트워크 경계 방화벽 연동 (pfBlockerNG)

NEXUS-GUARD에서 적발된 침해 IP를 네트워크 최외곽의 pfSense 경계 방화벽과 동기화하여 인트라넷 진입 자체를 원천 차단하는 연동 방식입니다.

### 5.1 연동 메커니즘
```
[공격자 탐침] ➔ [NEXUS-GUARD 실시간 차단] ➔ [/api/blocked-ips.txt 피드 발행] ➔ [pfSense pfBlockerNG 1분 주기 Cron 폴링] ➔ [WAN/LAN Drop 룰 자동 반영]
```

### 5.2 pfSense WebGUI 설정 가이드 (포트 443)
1. pfSense 관리자 콘솔(`https://<pfSense-IP>`)에 로그인합니다.
2. `System > Package Manager`에서 **`pfBlockerNG-devel`** 패키지가 설치되어 있는지 확인합니다.
3. 상단 메뉴 `Firewall > pfBlockerNG > IP > IPv4`로 이동합니다.
4. `+ Add` 버튼을 클릭하여 새 IPv4 커스텀 피드 그룹을 생성합니다:
   - **Action:** `Deny Inbound` (또는 필요 시 `Deny Both`)
   - **Update Frequency:** `Every 1 hour` (테스트 실시간 반영 시 `Every 5 minutes` 설정)
   - **IPv4 Custom List:**
     - **Format:** `Auto`
     - **State:** `ON`
     - **Source:** `http://<NEXUS-포털-IP>:5070/api/blocked-ips.txt` (또는 호스팅 중인 피드 URL)
     - **Header/Label:** `NEXUS_XDR_FEED`
5. 하단의 `Save IPv4 Settings`를 클릭합니다.
6. `Firewall > pfBlockerNG > Update` 메뉴로 이동하여 `Update > Run`을 실행하면 피드가 즉시 동기화됩니다.

### 5.3 NEXUS-GUARD 콘솔에서의 연결 진단
- GUI 콘솔 6번째 [설정] 탭에서 `pfSense 차단 피드 URL`란에 URL을 입력합니다.
- 우측의 **`[pfSense 피드 통신 테스트]`** 버튼을 클릭합니다.
- 정상 수신 시: `pfSense 피드 통신 성공 (HTTP 200) - 현재 피드 차단 IP 수: N건` 팝업이 출력됩니다.

---

## 6. Graylog 중앙 SIEM 연동 (GELF UDP 12201)

NEXUS-GUARD에서 발생하는 모든 보안 인시던트(디코이 탐침, 계정 잠금, IP 차단, AST 진단 결과)를 엔터프라이즈 표준 GELF 규격으로 Graylog에 실시간 전송합니다.

### 6.1 Graylog 서버 Input 생성 가이드 (포트 9000 Web Console)
1. 브라우저로 Graylog 웹 콘솔(`http://<Graylog-IP>:9000`)에 접속합니다.
2. 상단 메뉴 `System > Inputs`로 이동합니다.
3. 드롭다운 선택 메뉴에서 **`GELF UDP`**를 선택하고 **`Launch new input`**을 클릭합니다:
   - **Node:** 현재 Graylog 노드 선택
   - **Title:** `NEXUS-GUARD GELF UDP Input`
   - **Bind address:** `0.0.0.0`
   - **Port:** `12201`
   - **Receive Buffer Size:** `262144` (기본값)
4. `Save` 버튼을 누르면 GELF UDP 수신기가 `RUNNING` 상태로 활성화됩니다.

### 6.2 NEXUS-GUARD 콘솔 연동 및 전송 검증
1. GUI 콘솔 [설정] 탭의 `외부 보안 장비 연동` 섹션으로 이동합니다.
2. **Graylog SIEM 호스트**: Graylog 서버 IP(예: `192.168.3.10` 또는 `127.0.0.1`) 입력.
3. **GELF UDP 포트**: `12201`
4. **타겟 스트림명**: `NEXUS_SECURITY_STREAM`
5. **`[GELF UDP 패킷 테스트]`** 버튼 클릭:
   - `GELF UDP 패킷 발송 완료 (타겟 스트림: NEXUS_SECURITY_STREAM)` 메시지가 출력됩니다.
6. Graylog 검색 콘솔(`Search`)에서 `facility:nexus-guard-soc`를 검색하여 전송된 테스트 패킷이 1바이트 유실 없이 수신되었는지 확인합니다.

---

## 7. Wazuh 호스트 EDR / FIM 연동 및 Standalone 가동

### 7.1 엔터프라이즈 Wazuh 서버가 구축된 환경
1. [설정] 탭의 `Wazuh Manager Host`에 Wazuh 서버 IP를 입력합니다 (기본 통신 포트: `1514`, API 포트: `55000`).
2. 에이전트 식별자(`Agent ID`)를 입력합니다.
3. `[Wazuh Agent 연결 테스트]` 버튼을 클릭하여 TCP 소켓 연결성을 확인합니다.

### 7.2 Wazuh 서버가 없는 단독 PC 환경 (Standalone FIM 모드)
- 엔터프라이즈 환경이 아니더라도 걱정할 필요가 없습니다.
- NEXUS-GUARD는 자체 경량 무결성 엔진인 [`FileIntegrityMonitor`](file:///C:/Users/user/Desktop/nexus-work-portfolio/nexus_guard/engine/fim.py)를 내장하고 있습니다.
- `app/`, `nexus_guard/`, `db/`, `.env` 등 핵심 보안 코드의 SHA-256 디지털 지문을 10초 주기로 자체 백그라운드 대조하여, 파일 변조 발생 즉시 대시보드에 붉은색 경보를 띄우고 세부 변조 내역을 표시합니다.

---

## 8. Webhooks & n8n SOAR 오케스트레이션 자동화 연동

침해 인시던트 발생 시 보안 관제팀 메신저로 실시간 카드를 발송하고, n8n을 통해 3자 보안 워크플로우를 전자동 실행합니다.

### 8.1 Discord / Slack 알림 연동
1. **Discord:** 채널 설정 ➔ `연동` ➔ `웹후크 만들기` ➔ Webhook URL 복사.
2. **Slack:** 워크스페이스 관리 ➔ `Incoming WebHooks` 앱 추가 ➔ Webhook URL 복사.
3. 콘솔 [설정] 탭의 `Discord 웹훅 URL` 및 `Slack 웹훅 URL`란에 각각 붙여넣기.
4. 우측의 **`[웹훅 발송 테스트]`** 버튼 클릭:
   - 해당 메신저 채널에 `🔔 [NEXUS-GUARD] 웹훅 테스트 성공!` 리치 임베드 카드가 즉시 수신됩니다.

### 8.2 n8n SOAR 자동 대응 파이프라인 구축
1. n8n 콘솔(`http://<n8n-IP>:5678`)에 로그인하여 새 워크플로우를 생성합니다.
2. **Webhook 트리거 노드** 추가:
   - **HTTP Method:** `POST`
   - **Path:** `/webhook/nexus-incident`
3. 후속 노드 구성:
   - **Slack 노드:** 야간 당직 엔지니어 긴급 멘션 발송.
   - **Jira / GitHub 노드:** 긴급 보안 인시던트 이슈 티켓 자동 생성.
   - **MySQL 노드:** 감사 증적 DB 영구 적재.
4. NEXUS-GUARD [설정] 탭의 `n8n SOAR URL`에 `http://<n8n-IP>:5678/webhook/nexus-incident` 입력.
5. `침해 발생 시 자동 디스패치 활성화` 체크박스를 켜고 `[저장]`을 누르면 침해 감지 즉시 n8n 워크플로우가 자동 호출됩니다.

---

## 9. Windows 호스트 커널 방화벽 (netsh) 연동 및 긴급 격리

### 9.1 Windows Defender Firewall (netsh) 직접 통제
- **별도 소프트웨어 설치 불필요:** Windows OS에 기본 내장된 커널 방화벽 통제 유틸리티(`netsh.exe`)를 활용합니다.
- **동작 원리:**
  - GUI 또는 엔진에서 차단이 집행되면 백그라운드에서 다음 커널 명령이 즉시 실행됩니다:
    ```cmd
    netsh advfirewall firewall add rule name="NEXUS_GUARD_BLOCK_192_168_7_77" dir=in action=block remoteip=192.168.7.77
    ```
  - Windows 고급 보안이 포함된 Windows Defender 방화벽의 인바운드 규칙에 실시간 등록되어 OS 커널 수준에서 패킷을 즉시 Drop합니다.

### 9.2 1-클릭 긴급 호스트 네트워크 격리 (Emergency Host Containment)
- 글로벌 엔터프라이즈 EDR(SentinelOne Singularity Quarantine, CrowdStrike RTR) 규격을 완벽 지원합니다.
- 대시보드 히어로 배너 우측 상단의 **`[🚨 1-클릭 긴급 호스트 격리]`** 버튼을 클릭하면:
  1. 관리자 확인 다이얼로그 출력.
  2. 승인 즉시 관리 콘솔 제어 플레인(`127.0.0.1`, `::1`)을 제외한 모든 외부 인바운드/아웃바운드 포트(80, 443, 8080, 5000-5099)가 전면 차단됩니다.
  3. CISO 비상 감사 증적에 격리 식별자(`CID-...`)와 집행 타임스탬프가 각인됩니다.
  4. 복구 시에는 **`[🟢 격리 해제 (정상 복구)]`** 버튼을 누르면 4단계 자동 복구 플레이북이 실행되어 시스템이 1초 만에 안전 복원됩니다.

---

## 10. GUI 4단계 온보딩 위저드 및 1-클릭 프리셋 프로파일 활용법

NEXUS-GUARD 콘솔 좌측 6번째 탭인 **[⚙️ 환경 설정 & 외부 연동]** 탭에서 제공하는 편의 기능입니다.

### 10.1 4단계 온보딩 위저드 (Step-by-Step)
- **1단계 (보호 대상 지정):** 보호할 웹 포털 URL과 DB 포트 입력.
- **2단계 (AI 분석기 선택):** Groq LPU, NVIDIA NIM, Ollama 중 선호 추론기 지정.
- **3단계 (외부 장비 연동):** pfSense, Graylog, Wazuh, n8n 연동 주소 입력 (선택 사항).
- **4단계 (저장 & 진단 실행):** `[💾 변경 설정 저장]` 클릭으로 `config.json`에 영구 반영 및 실시간 바인딩.

### 10.2 1-클릭 환경 프리셋 프로파일 4선
상단 프리셋 버튼 클릭 한 번으로 모든 입력란이 최적값으로 자동 완성됩니다:
1. **`🏠 단독 PC 안심 모드 (초보자 추천)`**:
   - 외부 인프라 없이 로컬 WAF 입구 차단, 내장 정규식 AI 규칙, 자체 SHA-256 FIM 엔진 위주로 가동.
2. **`🏢 엔터프라이즈 SOC 풀 연동 모드`**:
   - pfSense(443), Graylog GELF(12201), Wazuh(1514), n8n(5678) 5대 인프라 풀 연동 세팅 일괄 입력.
3. **`💻 로컬 개발자 모드 (Port 5070 / Mock)`**:
   - `http://127.0.0.1:5070` 참조 포털 및 로컬 DB 전용 세팅.
4. **`🧹 모든 설정 비우기 (초기 설치 상태 클린 초기화)`**:
   - 언제든지 설정란을 완전히 비워 100점 만점 초기 설치 클린 상태로 1초 리셋 지원.

---

## 11. 연동 실패 시 원인 진단 및 트러블슈팅 FAQ

### Q1. 대시보드 상단에 `● 감시 웹 포털: 미등록 ([설정] 탭 등록)`이라고 뜹니다.
- **원인:** 신규 설치 상태로 `config.json`의 감시 대상 주소가 비어 있는 정상적인 클린 슬레이트 상태입니다.
- **조치:** 6번째 [설정] 탭에서 `[⚡ 내 PC 로컬 테스트 주소 자동 채우기]` 버튼을 누르고 `[저장]`을 클릭하면 초록색 `[CORE]`(정상 연동)로 바뀝니다.

### Q2. Graylog GELF 패킷 테스트를 눌렀는데 패킷이 안 갑니다.
- **원인:** Graylog 서버의 `System > Inputs`에 `GELF UDP (포트 12201)` Input이 생성되어 있지 않거나 방화벽 UDP 12201 포트가 닫혀 있는 경우입니다.
- **조치:** Graylog 콘솔에서 GELF UDP Input의 상태가 `RUNNING`인지 확인하고, 인바운드 UDP 12201 포트를 개방하십시오.

### Q3. pfSense 피드 통신 테스트 시 연결 오류가 발생합니다.
- **원인:** 피드를 제공하는 웹 포털 서버(`python run.py`, 포트 5070)가 아직 기동되지 않았기 때문입니다.
- **조치:** 포털 서버(`run.py`)를 띄운 후 다시 테스트 버튼을 누르면 정상 HTTP 200이 수신됩니다.

### Q4. Groq API 키가 없으면 보안 검사가 안 되나요?
- **답변:** 전혀 문제 없습니다. API 키가 없어도 시스템 내장 정규식 엔진이 4단계 폴백으로 작동하여 디코이 탐침, SQLi, LLM 탈옥 시도를 100% 정상 차단합니다.

### Q5. 1-클릭 긴급 호스트 격리를 누르면 내 컴퓨터가 먹통이 되나요?
- **답변:** 아닙니다. NEXUS-GUARD는 루프백(`127.0.0.1`, `::1`, `localhost`) 관리자 플레인을 절대 화이트리스트로 보호하므로, 외부 공격 트래픽만 차단되고 콘솔 조작 및 복구 플레이북은 안전하게 유지됩니다.
