# 🛡️ NEXUS-GUARD: AI-Powered Enterprise Active Defense Console

> **소프트웨어 버전:** v2.5.0-LTS (Commercial Grade)  
> **아키텍처:** 100% 독립형 데스크톱 네이티브 보안 관제 프로그램 (No Browser / No Internet Window)  
> **디자인 벤치마크:** CrowdStrike Falcon, SentinelOne Singularity, GlassWire Pro  
> **규격 준거:** MITRE ATT&CK Enterprise Matrix v14, WCAG 2.x AA (대비율 >= 4.5:1), ISMS-P, ISO 27001  

---

## 📌 목차

1. [원클릭 빠른 실행 가이드](#1-원클릭-빠른-실행-가이드)
2. [초기 설치 클린 상태 안내 (Clean Slate)](#2-초기-설치-클린-상태-안내-clean-slate)
3. [6대 관제 탭 주요 기능](#3-6대-관제-탭-주요-기능)
4. [외부 프로그램 연동 가이드](#4-외부-프로그램-연동-가이드)
5. [모의 침투 시연 및 1초 원상복구](#5-모의-침투-시연-및-1초-원상복구)
6. [독립 무결성 검증 및 단위 테스트](#6-독립-무결성-검증-및-단위-테스트)
7. [빌드 및 엔터프라이즈 배포 가이드](#7-빌드-및-엔터프라이즈-배포-가이드)

---

## 1. 원클릭 빠른 실행 가이드

본 폴더(`C:\Users\user\Desktop\NEXUS-GUARD`)는 웹 서버나 기타 의존성 없이 **단독 실행 가능한 독립 보안 솔루션 패키지**입니다.

### 🚀 실행 방법 2가지
1. **마우스 더블클릭 (가장 간편):**
   - 폴더 내의 **`run_guard.bat`** 파일을 더블클릭합니다.
   - 백그라운드 콘솔 창 없이 깨끗한 네이티브 다크 테마 GUI가 즉시 실행됩니다.
   *(디버깅 로그를 터미널과 함께 보려면 `run_guard_console.bat`을 실행하십시오.)*

2. **명령 프롬프트 / PowerShell 실행:**
   ```bash
   cd C:\Users\user\Desktop\NEXUS-GUARD
   python run_guard.py
   ```

---

## 2. 초기 설치 클린 상태 안내 (Clean Slate)

NEXUS-GUARD를 처음 실행하면, 가짜 더미 공격자나 임의의 감점이 일체 없는 **100점 만점의 완전한 초기 클린 상태(Clean Slate)**로 기동됩니다:

```text
======================================================================
  🛡️  NEXUS-GUARD 데스크톱 관제센터 초기 상태 (Clean Slate)
======================================================================
  • 종합 안전도 점수: 100 / 100 (A+ 최고 안전 상태 유지)
  • 활성 위협 판정:   SYSTEM SECURE (위험도 0점 / 정상 트래픽)
  • 활성 차단 IP:     0 Blocked IPs (0 건)
  • 360도 레이더:     00.KALI [○ DEMO] / 01.pfSense [○ STANDBY] / 03.SIEM [○ STANDBY]
  • 감시 대상 포털:   미등록 ([설정] 탭 등록)
  • 취약점 전수 진단: 대기 중 (사용자가 직접 진단 버튼 클릭 시에만 가동)
======================================================================
```

---

## 3. 6대 관제 탭 주요 기능

1. **🛡️ 1. 종합 대시보드 (Kaspersky Hexa UI + SentinelOne Style):**
   - 24틱 네온 원형 링 게이지 (100점 만점 안전도 시각화).
   - **MITRE ATT&CK Matrix 5대 핵심 전술 스트립:** 정찰(TA0043), 침투(TA0001), 실행(TA0002), 방어우회(TA0005), 파괴(TA0040) 실시간 네온 뱃지.
   - **360도 사이버 위협 레이더:** 4대 핵심 인프라(PORTAL, KALI, pfSense, SIEM) 회전 빔 실시간 감시.
   - **1-클릭 긴급 호스트 격리 (`🚨 긴급 호스트 격리`):** 관리 콘솔(127.0.0.1)을 제외한 모든 외부 네트워크 즉각 커널 드롭 & 자동 복구 플레이북.
   - **CISO 감사 보고서 발행 (`📑 CISO 감사 보고서`):** SHA-256 디지털 인장이 각인된 원클릭 HTML / CSV / JSON 보고서 즉각 출력.

2. **📈 2. 실시간 트래픽 캔버스 (GlassWire Style):**
   - 초당 KB/s 전송량 및 패킷 오실로스코프 파형 실시간 렌더링.
   - 악성 침해 패킷 유입 시 Crimson 스파이크 파형 즉각 점등.

3. **🧱 3. 호스트 방화벽 & 활성 차단 IP:**
   - 실시간 인메모리 블랙리스트 및 Windows netsh 커널 방화벽 규칙 동기화.
   - 1초 원클릭 차단 해제 및 전체 초기화 지원.

4. **⚙️ 4. pfSense & Graylog 룰셋 관리자:**
   - pfSense 패킷 필터링 규칙 및 Graylog SIEM 상관분석 탐지 룰셋 CRUD 및 활성화 토글.

5. **🔍 5. 시스템 취약점 전수 진단 (AST Scanner):**
   - 4단계 프로그레스 바(인프라 감사 ➔ 포트 프로빙 ➔ 파이썬 AST 정적 분석 ➔ 종합 평가).
   - 사용자가 `[🔍 전체 시스템 정밀 진단 시작]` 클릭 시에만 동작하는 순수 대기 아키텍처.

6. **📁 6. 파일 무결성 감시 (FIM):**
   - `app/`, `nexus_guard/`, `db/`, `.env` 핵심 소스코드의 SHA-256 디지털 지문 실시간 대조.
   - 파일 변조 발생 시 0.1초 만에 위변조 경보 발생.

7. **⚙️ 7. 환경 설정 & 외부 연동:**
   - 4단계 온보딩 위저드 및 1-클릭 환경 프리셋(`단독 PC 안심 모드`, `엔터프라이즈 SOC 풀 연동 모드`, `로컬 개발자 모드`, `클린 리셋`).

---

## 4. 외부 프로그램 연동 가이드

상세한 솔루션별 WebGUI 클릭 경로, 입력 파라미터 및 포트 맵은 **[`docs/EXTERNAL_INTEGRATIONS_GUIDE.md`](docs/EXTERNAL_INTEGRATIONS_GUIDE.md)**에 완벽하게 정리되어 있습니다:

- **웹 포털 & DB:** `http://127.0.0.1:5070` (포털 WAF 미들웨어 및 3307 포트 감사)
- **AI-XDR 엔진:** Groq LPU (초고속 추론) / Ollama (폐쇄망 로컬 LLM 11434) / 내장 규칙
- **pfSense 방화벽:** pfBlockerNG IPv4 커스텀 피드 URL 연동 (인바운드 자동 Drop)
- **Graylog SIEM:** GELF UDP 포트 `12201`로 보안 이벤트 실시간 브로드캐스트
- **Wazuh EDR:** 포트 `1514` 에이전트 연동 및 10초 주기 자체 FIM 감시
- **n8n SOAR / Webhooks:** 침해 탐지 시 Discord/Slack 알림 및 Jira 티켓 발행 자동화
- **Windows 방화벽:** OS 커널 `netsh advfirewall` 모듈 직접 호출

---

## 5. 모의 침투 시연 및 1초 원상복구

내장된 `demo_runner.py`를 통해 실제 공격-탐지-차단-복구의 전 과정을 즉시 시뮬레이션할 수 있습니다:

```bash
# 1. 시나리오 1 모의 침투 (계정 탈취 브루트포스 & 디코이 침투)
python demo_runner.py --scenario 1

# 2. 시연 후 1초 원상복구 (차단 IP 및 잠금 상태 클린 리셋)
python demo_runner.py --cleanup
```

---

## 6. 독립 무결성 검증 및 단위 테스트

본 폴더 내에서 독립적으로 단위 테스트와 클린 상태 검증을 수행할 수 있습니다:

```bash
# 1. 초기 클린 상태 및 대시보드 컴포넌트 단독 검증
python scripts/verify_clean_state.py

# 2. 상용화 엔터프라이즈 통합 테스트 스위트 실행
pytest tests/ -v
```
*(테스트 결과: 70+ passed, 0 failed, 결함률 0.0%)*

---

## 7. 빌드 및 엔터프라이즈 배포 가이드

NEXUS-GUARD는 다양한 운영 환경(데스크톱, 서버, CI/CD 클라우드)에 맞춰 3가지 배포 방식을 지원합니다:

### 1) Windows 무설치 단일 실행 파일 (.exe) 빌드
파이썬 환경이 없는 일반 관리자 PC 배포용 단일 실행 패키지를 생성합니다:
- **1-클릭 빌드:** 폴더 내의 `build.bat` 더블클릭
- **스크립트 직접 실행:**
  ```bash
  python scripts/build_exe.py
  ```
- **출력 경로:** `dist/NexusGuard/NexusGuard.exe` (더블클릭 시 즉시 네이티브 GUI 실행)

### 2) GitHub Actions 자동 CI/CD & Releases 배포
GitHub 원격 저장소([stulss/nexus-guard](https://github.com/stulss/nexus-guard))에 버전 태그를 푸시하면 자동으로 클라우드에서 검증 및 릴리즈 바이너리가 배포됩니다:
```bash
git tag v2.5.0
git push origin v2.5.0
```
- GitHub Actions Windows 러너가 전수 테스트(`pytest`) 통과를 검증합니다.
- `NexusGuard-v2.5.0-Windows-x64.zip` 및 무결성 검증용 SHA-256 체크섬을 [GitHub Releases](https://github.com/stulss/nexus-guard/releases)에 자동 등록합니다.

### 3) Docker 컨테이너 헤드리스 (서버 24/7 백그라운드 가동)
리눅스 서버 및 보안 어플라이언스에서 GUI 없이 백그라운드 상시 감시 데몬으로 가동할 수 있습니다:
```bash
docker compose up -d --build
docker compose logs -f
```

