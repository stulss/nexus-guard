# 📄 [이력서 & 자기소개서 기본본] 홍주형 (Hong Juhyeong)

> **지원 분야:** 보안 소프트웨어 엔지니어 (Security Software Engineer) / 보안 아키텍트 / 백엔드 & 인프라 보안  
> **GitHub:** [https://github.com/stulss/nexus-guard](https://github.com/stulss/nexus-guard)  
> **포트폴리오:** [https://nexus-portfolio-nu.vercel.app](https://nexus-portfolio-nu.vercel.app)  
> **이메일:** doffl9737@gmail.com  
> **최신 갱신일:** 2026년 11월 11일  

---

## Ⅰ. 이력서 프로젝트 항목 (Resume Experience)

### 🛡️ NEXUS-GUARD: AI-Powered Enterprise Active Defense Security Suite (v2.5.0-LTS)
* **수행 기간:** 2026.10 ~ 2026.11 (상용화 및 클린 배포 완료)
* **담당 역할:** 포털 코어 아키텍트 & 보안 최고관리자 (**`NEXUS-GUARD` 보안 관제 콘솔 전담 설계 및 단독 개발 100%**)
* **사용 기술 스택:**
  - **Language & GUI:** Python 3.11+, CustomTkinter, Tkinter Canvas (오실로스코프 파형 & 360도 레이더 렌더링)
  - **Security Engines:** MITRE ATT&CK Matrix v14 매핑 엔진, SHA-256 FIM 무결성 감시, 호스트 방화벽(Netsh), SIEM 룰 엔진, 디코이(허니팟) 트랩
  - **AI & Cloud:** NVIDIA NIM (Llama-3.1-Nemotron-70B-Instruct), Groq LPU, Ollama
  - **DevOps & Packaging:** PyInstaller (17.5MB 단일 실행 파일), GitHub Actions CI/CD (테스트 및 자동 릴리즈), Docker
* **핵심 정량적 성과 수치:**
  - **자동화 테스트 검증 100% 통과:** 70개 단위/통합 테스트 스위트 전수 통과 (결함률 0.0%)
  - **무오탐 초기 안전 상태(Clean Slate):** 신규 설치 시 0건 위협, 100/100 만점의 클린 상태 보장
  - **초고속 위협 탐지 및 복구:** 디코이 탐침 시 0.1초 차단, 0.5초 AI-XDR 킬체인 분석, 1초 원상복구(Clean-up) 완성
  - **독립 무설치 배포 파이프라인:** 파이썬 미설치 PC에서도 1초 만에 더블클릭 구동되는 독립형 `.exe` 패키지 구축

---

## Ⅱ. 자기소개서 기본본 (Cover Letter & Problem Solving)

### [문항 1] 기존 시스템의 한계를 극복하고 완성도 높은 기술적 솔루션을 도출한 문제 해결 경험 (STAR 기법)
**"오탐과 의존성을 제거한 무결점 클린 슬레이트(Clean Slate) 보안 관제 솔루션 구축"**

* **Situation (상황):**  
  기존의 많은 보안 관제 도구와 학습용 프로젝트들은 최초 기동 시 사전에 주입된 더미 공격자 데이터나 임의의 감점 점수가 잔류하여, 실제 새 PC나 운영 환경에 설치했을 때 '시스템이 왜 시작부터 위험 상태인가?'라는 오탐과 사용자 불신을 초래했습니다. 또한 소스코드 기반 실행 방식은 파이썬 인터프리터 및 다양한 그래픽 라이브러리 종속성으로 인해 비개발자나 다른 환경에서 즉시 구동하기 어려운 장벽이 있었습니다.

* **Task (과제):**  
  새로운 PC에 처음 설치했을 때 어떠한 잔류 데이터도 없이 **'100점 만점 / 활성 위협 0건'**의 완벽한 신규 상태(Clean Slate)를 보장하는 독립형 네이티브 관제 소프트웨어를 완성하고, 파이썬이 없는 환경에서도 더블클릭 한 번으로 1초 만에 구동 가능한 상용화 수준의 패키징을 달성해야 했습니다.

* **Action (행동):**  
  1. **상태 관리 아키텍처 재설계:** `FirewallRuleManager`, `FileIntegrityMonitor`, `ControlCenter` 등 코어 모듈의 인스턴스 초기화 로직을 전면 정비하여, 외부 이벤트가 유입되기 전까지는 차단 목록 0건, 위협 점수 0점(종합 안전도 100점)을 유지하도록 상태 머신을 격리했습니다. 이를 검증하기 위해 `test_clean_slate.py` 테스트를 작성하여 배포 전 0건 상태를 자동 검증했습니다.
  2. **직관적인 비전문가용 UI/UX 혁신:** SentinelOne과 GlassWire의 직관적 UX를 벤치마킹하여, 360도 레이더에 4대 인프라 범례를 명시하고, 비전문가도 1초 만에 안전 여부를 파악할 수 있는 쉬운 한글 종합 판정 배너와 WCAG 2.x AA 고대비 가이드라인을 적용했습니다.
  3. **PyInstaller 및 GitHub Actions 자동 CI/CD 파이프라인 구축:** `scripts/build_exe.py`와 `build.bat`을 제작하여 17.5MB 단일 실행 파일(`NexusGuard.exe`)을 패키징하고, Git 태그 푸시 시 클라우드에서 70개 테스트를 통과해야만 GitHub Releases에 정식 배포 파일이 등록되는 자동화 체계를 완성했습니다.

* **Result (결과):**  
  신규 PC나 VM 어디서든 다운로드 후 더블클릭만으로 즉각 관제 콘솔이 실행되며, 100/100 만점의 클린 상태에서 실시간 트래픽 감시와 1초 모의 침투 시연을 완벽하게 재현할 수 있는 상용화 수준의 엔터프라이즈 솔루션으로 인정받았습니다.

---

### [문항 2] 능동 방어(Active Defense) 아키텍처 및 이기종 인프라 연동 역량
**"단순 탐지를 넘어 즉각 격리와 1초 복구를 실현한 차세대 Active Defense 체계"**

* **Situation & Task:**  
  전통적인 보안 체계는 방화벽에 기록된 로그를 사후에 분석하는 수동적 방식에 머물러 있어, 웹쉘 업로드나 기밀 파일(`.env`) 탈취와 같은 고속 침해 행위를 실시간으로 막아내지 못했습니다.

* **Action & Result:**  
  저는 시스템 공격 표면에 공격자가 침투할 만한 미끼 경로(`/.env`, `/.git`, `/admin.php`)를 전략적으로 배치하는 **디코이(Decoy Trap) 기술**을 구현했습니다. 공격자가 해당 경로에 단 1바이트라도 프로빙하는 즉시 0.1초 만에 커널 방화벽(`netsh advfirewall`)을 호출하여 해당 IP를 403 차단하고, 이 이벤트를 pfSense, Graylog(GELF UDP 12201), Wazuh(FIM SHA-256), n8n SOAR로 동시 전파하도록 설계했습니다.  
  더 나아가 시연 후 환경을 단 1초 만에 원래 상태로 리셋하는 `demo_runner.py --cleanup` 롤백 엔진을 구축하여, 운영 안정성과 유지보수성을 극대화했습니다.
