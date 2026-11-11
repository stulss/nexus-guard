# NEXUS-GUARD: AI-Powered Active Defense Security Suite

NEXUS-GUARD는 Flask 기반 웹 애플리케이션 및 엔터프라이즈 인프라를 위한 **독립형 능동 보안 엔진 & 데스크톱 SOC 관제 콘솔**입니다.
가짜 미끼 경로(디코이/허니팟) 탐침 격리, 능동 방화벽 netsh IP 차단, AST 정적 인젝션 검증, 4중 AI-XDR 하이브리드 판정 엔진(Groq -> NVIDIA NIM -> Ollama -> 내장 규칙)을 탑재하여 웹 서비스의 침해 시도를 실시간으로 탐지하고 차단합니다.

---

## 📌 목차

1. [핵심 기능 및 아키텍처](#1-핵심-기능-및-아키텍처)
2. [초기 기동 시 클린 슬레이트 상태 (Clean State)](#2-초기-기동-시-클린-슬레이트-상태-clean-state)
3. [대상 웹 사이트 미등록 상태 안내 및 [설정] 탭 등록 방법](#3-대상-웹-사이트-미등록-상태-안내-및-설정-탭-등록-방법)
4. [실제 공격 방어 시연 가이드 (Simulation Runbook)](#4-실제-공격-방어-시연-가이드-simulation-runbook)
5. [0 Dummy Data 원칙 및 무결성 관리](#5-0-dummy-data-원칙-및-무결성-관리)
6. [독립 플러그인 한 줄 연동 (`NexusGuard`)](#6-독립-플러그인-한-줄-연동-nexusguard)
7. [CLI 커맨드라인 인터페이스 레퍼런스](#7-cli-커맨드라인-인터페이스-레퍼런스)
8. [외부 연동 프로그램별 상세 셋업 가이드 (Integrations Guide)](#8-외부-연동-프로그램별-상세-셋업-가이드-integrations-guide)

---

## 1. 핵심 기능 및 아키텍처

- **디코이 허니팟 방패 (`core/decoy.py`):** 미끼 경로(`/.env`, `/.git`, `/wp-login.php` 등) 접근 시 즉각 404 기만 응답 및 메모리/방화벽 블랙리스트 등록.
- **다단계 방화벽 엔진 (`engine/firewall.py`):** 애플리케이션 계층 403 격리 및 Windows 호스트 방화벽(`netsh advfirewall`) 인바운드 차단 룰 자동 등록.
- **4중 AI-XDR 트리아지 (`ai_engine/cascade_router.py`):** LPU 초고속 추론(Groq) → 클라우드 NIM(NVIDIA) → 온프레미스 LLM(Ollama) → 100% 내장 규칙 폴백 파이프라인.
- **파일 무결성 감시 FIM (`engine/`):** 핵심 코드 및 설정 파일의 SHA-256 해시를 주기적으로 대조하여 비인가 변조 감시.
- **데스크톱 관제센터 GUI (`gui/native_app.py`):** SentinelOne 다크 테마 디자인 토큰(`theme.py`), 360도 사이버 위협 레이더, 트래픽 파형 모니터링.

---

## 2. 초기 기동 시 클린 슬레이트 상태 (Clean State)

NEXUS-GUARD를 처음 실행(`python -m nexus_guard.gui`)했을 때, 시스템은 **하드코딩된 더미 공격자나 허위 침해 로그가 일체 존재하지 않는 완전한 초기 클린 상태(Clean Slate)** 로 시작합니다:

```text
======================================================================
  🛡️  NEXUS-GUARD 데스크톱 관제센터 초기 상태 (Clean Slate)
======================================================================
  • 종합 위협 판정: SYSTEM SECURE (위험도 0 / 100)
  • 활성 위협 건수: 0 Active Threats (활성 공격자 없음)
  • 차단된 위협 IP: 0 Blocked IPs (0 건)
  • 감시 웹 포털:   미등록 ([설정] 탭 등록)
  • 감시 대상 DB:   미등록 ([설정] 탭 등록)
  • 360도 레이더:   00.KALI [○ DEMO SIM] / 01.pfSense [○ STANDBY] / 03.SIEM [○ STANDBY]
======================================================================
```

| 관제 항목 | 초기 표시 상태 | 동작 설명 |
|---|---|---|
| **활성 위협 (Active Threats)** | `0 Active Threats` | `• 감시 상태: 활성 공격자 없음 (클린 네트워크)` — 실제 공격 트래픽 유입 전까지 비정상 신호 미감지 |
| **차단 IP (Blocked IPs)** | `0 Blocked IPs (0 건)` | 초기 인메모리 블랙리스트 공백(`{}`) 상태 — 초록색 안전 지표 |
| **종합 위협 판정 (Verdict)** | `SYSTEM SECURE` | `🛡️ 종합 위협 판정: SYSTEM SECURE (위험도 0 / 100)` — 보안 점수 100점 만점 유지 |
| **감시 웹 포털** | `미등록 ([설정] 탭 등록)` | `config.json`의 감시 대상 주소가 비어 있는 기본 클린 상태 |
| **대상 DB** | `미등록 ([설정] 탭 등록)` | DB 주소 미등록 상태 |
| **인프라 노드 토폴로지** | `STANDBY / DEMO SIM` | 설정 파일에 등록되지 않은 외부 장비는 정직하게 대기 모드(`○ STANDBY`)로 표시 |

---

## 3. 대상 웹 사이트 미등록 상태 안내 및 [설정] 탭 등록 방법

NEXUS-GUARD는 특정 서비스에 종속되지 않는 범용 패키지로 배포되므로, 신규 설치 시 [`nexus_guard/config.json`](config.json)의 `target_service`는 빈 값(`""`)으로 초기화되어 있습니다.
이에 따라 대시보드 상단 센서 스트립에 **`미등록 ([설정] 탭 등록)`** 안내가 표시됩니다.

보호할 대상 웹 사이트(예: 로컬 참조 포털 `http://127.0.0.1:5070` 또는 실제 사내 웹 서버)를 등록하는 2가지 방법입니다:

### 방법 A: 4단계 온보딩 위저드 (GUI 6번째 [설정] 탭)
GUI 좌측 사이드바의 **[⚙️ 환경 설정 & 외부 연동]** 탭 상단에서 제공되는 4단계 안내를 따릅니다:

1. **1단계: 보호 대상 지정 (🌐 웹/DB 주소 입력)**
   - 보호 대상 포털 URL(`http://127.0.0.1:5070`)과 DB 포트(`3307`)를 입력합니다.
   - **⚡ 빠른 셋업 도우미:** 상단의 `[⚡ 내 PC 로컬 테스트 주소 자동 채우기 (127.0.0.1:5070)]` 버튼을 클릭하면 1초 만에 로컬 기본값이 자동 입력됩니다.
2. **2단계: AI 분석기 선택 (🤖 AI-XDR 엔진 선택)**
   - Groq, NVIDIA NIM, Ollama 중 원하는 추론기를 선택합니다. (API 키가 없어도 내장 룰셋 기반으로 100% 정상 작동)
3. **3단계: 외부 장비 연동 (🧱 방화벽/SIEM, 선택 사항)**
   - pfSense 차단 피드, Graylog GELF, Wazuh EDR 연동 주소를 지정합니다. (미구축 환경에서는 비워두어도 Standalone 모드로 안전하게 작동)
4. **4단계: 저장 & 진단 실행 (🔍 정밀 검증 시작)**
   - 하단의 `[💾 변경 설정 저장]` 버튼을 클릭하면 `nexus_guard/config.json`에 영구 저장되며, 대시보드의 상태가 실시간 녹색(`[CORE]` / 정상 연동)으로 즉각 바뀝니다.

### 방법 B: 1-클릭 환경 프리셋 프로파일 활용
[설정] 탭의 프리셋 버튼으로 원클릭 환경 구성을 지원합니다:
- **`🏠 단독 PC 안심 모드 (초보자/단독실행 추천)`**: 복잡한 외부 장비 없이 로컬 netsh 차단과 WAF 입구 격리 위주로 즉시 가동.
- **`🏢 엔터프라이즈 SOC 풀 연동 모드`**: pfSense, Graylog, Wazuh 5대 인프라 풀 연동 세팅.
- **`💻 로컬 개발자 모드 (Port 5070 / Mock)`**: 5070 포트 참조 포털 연동 세팅.
- **`🧹 모든 설정 비우기 (초기 설치 상태 클린 초기화)`**: 언제든지 설정란을 완전히 비워 신규 설치 클린 상태로 1초 리셋 지원.

---

## 4. 실제 공격 방어 시연 가이드 (Simulation Runbook)

실제 침해 탐지, 능동 방어, IP 차단 및 복구 과정을 직접 눈으로 확인할 수 있는 시뮬레이션 명령어를 제공합니다.

### 핵심 시연 명령어 3선

#### 1) 미끼 경로 디코이 침투 시도 (`demo_runner.py --scenario 1`)
```bash
python demo_runner.py --scenario 1
```
- 공격자 IP(`192.168.7.77`)가 계정 탈취 브루트포스 5회 실패 후 계정 잠금 및 지속 침투 시도를 감행합니다.
- 데스크톱 GUI 콘솔에서 차단 IP가 실시간 등록되고, 레이더의 KALI 노드가 `[▲ ATTACK]`(Laser Crimson)으로 즉각 점등되며 위협 판정이 `HIGH THREAT`으로 전환되는 것을 확인할 수 있습니다.
- *(전용 디코이 허니팟 탐침 시연은 `python demo_runner.py --scenario 3`으로 가짜 `/.env` 및 404 스캔 차단을 즉시 재현할 수 있습니다.)*

#### 2) NEXUS-GUARD 내장 모의 공격 (`nexus_guard.cli attack`)
```bash
python -m nexus_guard.cli attack
```
- NEXUS-GUARD CLI 도구를 통해 내장된 모의 공격 시뮬레이션을 즉시 가동합니다(기본값: 시나리오 1).
- 번호를 지정하여 원하는 시나리오를 선별 실행할 수 있습니다:
  ```bash
  python -m nexus_guard.cli attack 1   # 계정 탈취 브루트포스 & 디코이 침투 시도
  python -m nexus_guard.cli attack 2   # AI 프롬프트 인젝션 탈옥 시도
  python -m nexus_guard.cli attack 3   # 디코이(허니팟) 탐침 및 404 스캔
  python -m nexus_guard.cli attack 4   # IDOR 권한 침해 및 결재선 위조
  python -m nexus_guard.cli attack 5   # 분산 패스워드 스프레이
  ```

#### 3) 시연 후 1초 원상복구 (`demo_runner.py --cleanup` 또는 `cli cleanup`)
```bash
python demo_runner.py --cleanup
# 또는 CLI 명령어:
python -m nexus_guard.cli cleanup
```
- 시연 과정에서 차단된 테스트 IP(`192.168.7.77`, `203.0.113.*` 등 8개) 및 잠긴 테스트 계정(`park` 등 4개)을 1초 만에 초기화하여 다시 깨끗한 클린 상태로 원상복구합니다.
- **감사 증적 보존:** 시연용 임시 차단 테이블만 정리되며, 실제 운영 침해 감사 로그(`security_audit_logs`, `logs/security.jsonl`)는 APPEND-ONLY 규칙에 따라 영구 보존됩니다.

---

## 5. 0 Dummy Data 원칙 및 무결성 관리

- **가짜 공격자 배제:** 초기 구동 시 인메모리 블랙리스트는 비어 있으며(`{}`), 더미 공격자 데이터가 하드코딩되어 있지 않습니다.
- **실측 텔레메트리:** GUI의 시스템 지표는 OS 실제 프로세스 및 네트워크 I/O 실측치와 연동됩니다.
- **이벤트 기반 동적 바인딩:** 공격자 정보 및 위험도 판정은 실제 침해 패킷 유입 또는 모의 시나리오 실행 시 `logs/security.jsonl`에 기록된 로그를 실시간 테일링하여 생성됩니다.

---

## 6. 독립 플러그인 한 줄 연동 (`NexusGuard`)

Flask 웹 애플리케이션에 NEXUS-GUARD 핵심 능동 방어를 한 줄로 장착할 수 있습니다:

```python
from flask import Flask
from nexus_guard import NexusGuard

app = Flask(__name__)

# 단 한 줄로 디코이 탐침 404 격리, 침해 IP 403 차단, 보안 헤더 5종 활성화
guard = NexusGuard()
guard.init_app(app)

if __name__ == "__main__":
    app.run(port=8080)
```

- 동작 범위:
  * 미끼 경로 접근 감지 시 HTTP 404 기만 응답 및 블랙리스트 등록
  * 차단된 IP로부터의 요청 시 HTTP 403 Forbidden 즉시 반환
  * 필수 보안 헤더 5종(CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Strict-Transport-Security) 자동 주입

---

## 7. CLI 커맨드라인 인터페이스 레퍼런스

```bash
# 1. 현재 보안 상태 및 웹 포털 연결 상태 확인
python -m nexus_guard.cli status

# 2. 능동 방어 모드 On/Off 토글
python -m nexus_guard.cli toggle on    # 능동 방어 모드 가동 (403 입구 차단 활성화)
python -m nexus_guard.cli toggle off   # 모의 침투 취약 모드로 전환

# 3. 내장 모의 침투 공격 시뮬레이션
python -m nexus_guard.cli attack       # 기본 시나리오 1 (디코이/브루트포스 침투)
python -m nexus_guard.cli attack 3     # 시나리오 3 (디코이 허니팟 탐침)

# 4. 차단 IP 및 잠금 계정 1초 원상복구
python -m nexus_guard.cli cleanup
```

---

## 8. 외부 연동 프로그램별 상세 셋업 가이드 (Integrations Guide)

NEXUS-GUARD를 엔터프라이즈 환경 및 타 보안 솔루션과 연동하기 위한 프로그램별 셋업 규격과 검증 절차입니다. 모든 연동 파라미터는 [`nexus_guard/config.json`](config.json) 또는 데스크톱 GUI의 6번째 **[⚙️ 환경 설정 & 외부 연동]** 탭에서 편집할 수 있습니다.

### 8.1 연동 프로그램 통신 매트릭스

| 대상 솔루션 | 프로토콜 / 포트 | 연동 목적 | 페일세이프 (미연결 시 동작) |
|---|---|---|---|
| **🌐 Web Portal (Flask)** | HTTP / `5070` | WAF 입구 패킷 검사, 디코이 트랩, IP 403 차단 | 단독 테스트 주소(127.0.0.1:5070) 모의 연동 |
| **🗄️ Database (MariaDB/MySQL)** | TCP / `3306`, `3307` | 취약 포트 감사, AST 정적 쿼리 분석 대상 | 로컬 AST 소스 파서만으로 100% 정적 검사 |
| **🤖 Groq LPU (AI-XDR)** | HTTPS / `443` REST | 0.5초 초고속 LPU 기반 AI 위협 트리아지 판정 | 시스템 내장 정규식 및 휴리스틱 룰 엔진 폴백 |
| **🦙 Ollama (로컬 LLM)** | HTTP / `11434` REST | 폐쇄망/온프레미스 전용 오프라인 AI 분석기 | 클라우드 통신 차단 상태에서도 로컬 완결 동작 |
| **🧱 pfSense 방화벽** | HTTP / `443` (WebGUI) | pfBlockerNG 기반 WAN/LAN 인바운드 Drop 자동화 | Windows 호스트 방화벽(netsh) 로컬 차단 유지 |
| **📊 Graylog (SIEM)** | GELF UDP / `12201` | SOC 중앙 보안 감사 로그 실시간 스트리밍 수집 | 로컬 `logs/security.jsonl`에 누락 없이 영구 적재 |
| **🛡️ Wazuh (EDR / FIM)** | TCP / `1514`, `55000` | 엔터프라이즈 에이전트 연동 호스트 보안 무결성 감사 | 자체 SHA-256 FIM 엔진이 10초 주기로 100% 독립 감시 |
| **⚡ n8n (SOAR)** | HTTP / `5678` Webhook | 인시던트 티켓 자동 발행, Slack 알림, 복구 자동화 | 로컬 이벤트 큐 및 SSE 스트리머로 독립 유지 |
| **💬 Discord / Slack** | HTTPS / `443` Webhook | 보안 팀 실시간 리치 임베드 알림 카드 발송 | 콘솔 알림 및 로그 파일 기록 유지 |
| **💻 Windows 커널 방화벽** | Windows OS `netsh` | OS 커널 레벨 네트워크 패킷 차단 & 1-클릭 호스트 격리 | 관리자 권한 실행 시 자동 가동 (루프백 페일세이프 보호) |

---

### 8.2 프로그램별 상세 연동 방법

#### 1. 보호 대상 웹 포털 (NEXUS ERP / 타 사내 시스템)
1. 보호 대상 웹 애플리케이션의 `run.py` 또는 `app.py`에 미들웨어를 장착합니다:
   ```python
   from nexus_guard import NexusGuard
   guard = NexusGuard()
   guard.init_app(app)
   ```
2. GUI 6번째 [설정] 탭의 `web_portal_url`에 포털 주소(`http://127.0.0.1:5070`)를 지정하고 `[저장]`을 클릭합니다.
3. 대시보드 상단 센서 스트립의 웹 포털 항목이 초록색 `[CORE]`(정상 연동)로 즉시 전환됩니다.

#### 2. AI-XDR 엔진 (Groq / Ollama / NVIDIA NIM)
- **Groq LPU (권장):** [console.groq.com](https://console.groq.com)에서 무료 API 키를 발급받아 `groq_api_key`에 입력합니다 (모델: `openai/gpt-oss-120b`). 0.5초 수준의 실시간 위협 트리아지가 가동됩니다.
- **Ollama (폐쇄망/오프라인):** 외부 인터넷이 단절된 환경에서 `ollama run qwen2.5:7b`를 띄운 뒤 `ollama_base_url`에 `http://127.0.0.1:11434`를 입력하면 100% 로컬 AI 연동이 완료됩니다.
- **API 키 미입력 시:** 시스템에 내장된 정규식/휴리스틱 규칙 엔진으로 자동 폴백되어 기능이 멈추지 않습니다.

#### 3. pfSense 차세대 방화벽 (pfBlockerNG)
1. pfSense 관리자 콘솔(`https://<pfSense-IP>`)에 로그인합니다.
2. `Firewall > pfBlockerNG > IP > IPv4`에서 `Add`를 눌러 새 커스텀 리스트를 만듭니다:
   - **List Name:** `NEXUS_XDR_BLOCKLIST`
   - **Source URL:** `http://<포털-IP>:5070/api/blocked-ips.txt`
   - **Action:** `Deny Inbound`
3. GUI [설정] 탭에서 `[pfSense 피드 통신 테스트]`를 클릭하여 피드 반환 상태(HTTP 200)를 검증합니다.

#### 4. Graylog SIEM (GELF UDP 12201)
1. Graylog 콘솔(`http://<Graylog-IP>:9000`) ➔ `System > Inputs` 이동.
2. 드롭다운에서 `GELF UDP` 선택 후 `Launch new input` 클릭 (Port: `12201`, Bind address: `0.0.0.0`).
3. GUI [설정] 탭에서 Graylog 호스트 IP를 입력하고 `[GELF UDP 패킷 테스트]`를 누르면 테스트 패킷이 전송되며 Graylog 화면에 즉각 수신됩니다.

#### 5. Wazuh EDR / 호스트 FIM
1. Wazuh Manager IP를 입력하고 `[Wazuh Agent 연결 테스트]`를 클릭하여 1514 포트 연결성을 확인합니다.
2. 외부 Wazuh 서버가 없더라도 NEXUS-GUARD 자체 SHA-256 FIM 엔진이 `app/`, `nexus_guard/`, `db/`, `.env` 등을 10초 주기로 무중단 자체 감시합니다.

#### 6. Webhooks & n8n SOAR
1. Discord 또는 Slack의 Incoming Webhook URL을 복사하여 입력합니다.
2. n8n 콘솔(`http://<n8n-IP>:5678`)에서 `Webhook (POST)` 노드를 생성하여 URL을 등록합니다.
3. `[웹훅 발송 테스트]` 버튼을 누르면 채널 및 n8n 워크플로우에 즉시 테스트 카드가 수신됩니다.

#### 7. Windows 호스트 커널 방화벽 (netsh)
1. 별도 외부 설치 없이 Windows OS 내장 `netsh advfirewall`과 직접 연동됩니다.
2. 차단할 IP 입력 후 `[차단]` 시 OS 레벨 인바운드 차단 규칙이 즉시 등록됩니다.
3. 비상 시 대시보드의 `[🚨 1-클릭 긴급 호스트 격리]`를 누르면 루프백(127.0.0.1) 관리 콘솔을 제외한 전면 네트워크가 1초 만에 격리됩니다.
