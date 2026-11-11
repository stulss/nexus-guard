# 🛡️ NEXUS-GUARD: AI-Powered Enterprise Active Defense Console

> **소프트웨어 버전:** v2.5.0-LTS (Commercial Grade)  
> **아키텍처:** 100% 독립형 데스크톱 네이티브 보안 관제 프로그램 (No Browser / No Internet Window)  
> **디자인 벤치마크:** CrowdStrike Falcon, SentinelOne Singularity, GlassWire Pro  
> **규격 준거:** MITRE ATT&CK Enterprise Matrix v14, WCAG 2.x AA (대비율 >= 4.5:1), ISMS-P, ISO 27001  

---

### 👥 팀 정보 및 개인 기여 범위 (Project Metadata & Ownership)
* **팀 프로젝트 명 & 원본 저장소:** 4조 NEXUS 종합 인프라 보안 관제 프로젝트 ([팀 원본 저장소: stulss/nexus-work](https://github.com/stulss/nexus-work))
* **팀원 구성 및 역할 분담:**
  - **홍주형 (본인):** 포털 코어 아키텍트 & 보안 최고관리자 — **`NEXUS-GUARD` 보안 관제 콘솔 전담 설계 및 단독 개발 (100%)**, 웹/DB 보안 하드닝, AI-XDR 하이브리드 엔진 구축, FIM 무결성 감시 및 PyInstaller/CI·CD 배포 파이프라인 완성
  - **김태빈:** 중앙 보안관제(SOC) SIEM / SOAR 엔지니어링 (Graylog 룰셋 R1~R12, n8n 시나리오 워크플로)
  - **이시헌:** 네트워크 경계 보안 엔지니어링 (pfSense 방화벽 구축, HAProxy WAF 규칙, 망 연동 피드)
  - **진혜정:** 클라우드 & 가상화 인프라 엔지니어링 (Docker 가상화 환경 구축, 리소스 모니터링)
* **개인 GitHub 저장소:** [https://github.com/stulss/nexus-guard](https://github.com/stulss/nexus-guard)
* **📁 핵심 제출 문서 & 다운로드 링크:**
  - 🖥️ **공식 발표 슬라이드 PPTX:** [NEXUS_GUARD_발표자료.pptx](https://github.com/stulss/nexus-guard/raw/main/docs/presentation/NEXUS_GUARD_발표자료.pptx)
  - 📄 **공식 발표 슬라이드 PDF:** [NEXUS_GUARD_발표자료.pdf](https://github.com/stulss/nexus-guard/raw/main/docs/presentation/NEXUS_GUARD_발표자료.pdf)
  - 📑 **홍주형 이력서 & 자기소개서 (공식 PDF):** [홍주형_이력서_자기소개서.pdf](https://github.com/stulss/nexus-guard/raw/main/docs/presentation/홍주형_이력서_자기소개서.pdf)
  - 📝 **홍주형 이력서 & 자기소개서 (전문 MD):** [RESUME_홍주형_이력서_자기소개서.md](https://github.com/stulss/nexus-guard/blob/main/docs/RESUME_홍주형_이력서_자기소개서.md)
  - 🌐 **웹 포트폴리오 라이브:** [nexus-portfolio-nu.vercel.app](https://nexus-portfolio-nu.vercel.app)
* **본인 단독 산출물 & 기여도 (100%):**
  1. `NEXUS-GUARD` 독립형 엔터프라이즈 데스크톱 GUI 관제센터 풀스택 개발 (`CustomTkinter` 기반)
  2. 100/100 무오탐 클린 슬레이트(Clean Slate) 아키텍처 및 70개 전수 자동화 테스트 스위트 작성
  3. 실시간 MITRE ATT&CK Matrix 매핑 엔진, SHA-256 FIM 무결성 감시기, 능동 방어 디코이 트랩 구현
  4. Windows 독립 무설치 실행 파일(`NexusGuard.exe`) 빌드 스크립트 및 GitHub Actions CI/CD 릴리즈 자동화

---

## 📌 목차

1. [원클릭 빠른 실행 가이드](#1-원클릭-빠른-실행-가이드)
2. [초기 설치 클린 상태 안내 (Clean Slate)](#2-초기-설치-클린-상태-안내-clean-slate)
3. [6대 관제 탭 주요 기능](#3-6대-관제-탭-주요-기능)
4. [외부 프로그램 연동 가이드](#4-외부-프로그램-연동-가이드)
5. [모의 침투 시연 및 1초 원상복구](#5-모의-침투-시연-및-1초-원상복구)
6. [독립 무결성 검증 및 단위 테스트](#6-독립-무결성-검증-및-단위-테스트)
7. [빌드 및 엔터프라이즈 배포 가이드](#7-빌드-및-엔터프라이즈-배포-가이드)
8. [실전 트러블슈팅 및 피드백 개선 내역 (PARR 구조)](#8-실전-트러블슈팅-및-피드백-개선-내역-parr-구조)

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

---

## 8. 실전 트러블슈팅 및 피드백 개선 내역 (PARR 구조)

### 📌 Case 1: 초기 설치 시 임의 공격자 및 감점 노출 문제 ➔ 클린 슬레이트(Clean Slate) 아키텍처 완성
* **문제점 (Problem):** 신규 PC에서 최초 실행 시 공격자 IP(`192.168.3.200`)와 65점 감점이 이미 대시보드에 표기되어 있어, 독립 배포 프로그램으로서의 신뢰성과 사용자 경험 저하.
* **원인 분석 (Analysis):** 모의 침투 시연용 테스트 더미 데이터가 컴포넌트 생성자 기본값으로 하드코딩되어 있어 첫 실행 시 잔류함.
* **해결 조치 (Resolution):**
  1. `FirewallRuleManager`, `NativeApp`, `FIM` 등 모든 핵심 엔진의 상태를 순수 0건(`[]`, 0 threats)으로 재설계.
  2. 시스템 최초 시작 시 점수를 100/100 만점으로 고정하고, `test_clean_slate.py` 테스트를 구축하여 0건 보장 검증.
* **결과 (Result):** 신규 설치 시 0 Blocked IPs, 100점 만점의 완벽한 초기 클린 상태 유지 (자동화 검증 100% PASS).

### 📌 Case 2: XDR 분석 결론 및 360도 레이더 시각화 난이도 ➔ 초보자 친화적 고대비 UI 개편
* **문제점 (Problem):** 처음 프로그램을 접하는 사용자 입장에서 360도 레이더의 점/궤적이 무엇을 의미하는지, XDR 판정 결과가 위험한지 안전한지 직관적 파악이 어려움.
* **원인 분석 (Analysis):** SIEM/SOC 전문 용어 위주의 텍스트 배치 및 레이더 각 노드(인프라)에 대한 시각적 범례 부재.
* **해결 조치 (Resolution):**
  1. CrowdStrike & SentinelOne UI를 벤치마킹하여, 초보자용 한글 쉬운 해설 레이블(`초보자 안내: 현재 시스템에 유입되는 이상 트래픽이 없으며...`)을 상단에 전면 배치.
  2. 360도 레이더 하단에 4대 핵심 인프라(`00.KALI`, `01.pfSense`, `02.PORTAL`, `03.SIEM`) 범례 및 회전 빔 상태 네온 뱃지 탑재.
  3. WCAG 2.x AA 기준(대비율 4.5:1 이상)을 충족하는 네온 사이언(#00e5ff) & 에메랄드(#00e676) 고대비 테마 적용.
* **결과 (Result):** 관제사뿐만 아니라 일반 임원/CISO도 1초 만에 현재 안전도를 판독할 수 있는 직관적 UX 달성.

### 📌 Case 3: 새 PC/VM 환경에서의 설치 의존성 ➔ 무설치 실행 파일 & GitHub Actions CI/CD 구축
* **문제점 (Problem):** 파이썬이나 특정 라이브러리가 없는 타 PC 또는 VM에서 실행하려면 환경 구축에 시간이 소요되고 오류 발생 위험 존재.
* **원인 분석 (Analysis):** 소스코드(`.py`) 기반 실행만 지원하여 로컬 파이썬 런타임 종속성 발생.
* **해결 조치 (Resolution):**
  1. `PyInstaller`를 활용하여 모든 종속성(CustomTkinter, Tkinter, psutil 등)과 룰셋 에셋을 패키징하는 `build_exe.py` 및 `build.bat` 작성.
  2. GitHub Actions 클라우드 러너를 통해 태그 생성 시 전수 테스트 후 단일 실행 파일(`NexusGuard.exe`)을 Releases에 자동 배포하는 CI/CD 워크플로우 완성.
* **결과 (Result):** 파이썬 미설치 PC에서도 다운로드 후 더블클릭만으로 즉각 가동 가능.


