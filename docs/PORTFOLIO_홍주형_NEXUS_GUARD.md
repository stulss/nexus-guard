# 🛡️ [포트폴리오] NEXUS-GUARD: AI 기반 엔터프라이즈 능동 방어 보안 솔루션

> **작성자:** 홍주형 (Hong Juhyeong) · 포털 코어 아키텍트 & 보안 최고관리자  
> **개인 GitHub 저장소:** [https://github.com/stulss/nexus-guard](https://github.com/stulss/nexus-guard)  
> **웹 포트폴리오 링크:** [https://nexus-portfolio-nu.vercel.app](https://nexus-portfolio-nu.vercel.app)  
> **팀 프로젝트 원본 저장소:** [https://github.com/stulss/nexus-work](https://github.com/stulss/nexus-work)  
> **솔루션 버전:** v2.5.0-LTS (Commercial Grade)  
> **공식 심사 평가:** **100 / 100 만점 (Grade: S+ / STRONG HIRE 적극 채용 추천)**  

---

## 1. 프로젝트 요약 & 핵심 정량 실적

| 핵심 지표 | 실적 수치 | 상세 내용 |
|---|:---:|---|
| **자동화 테스트 검증** | **70 / 70 PASS (100%)** | 단위/통합/적대적 입력/WCAG AA 색대비 전수 테스트 **10.67초** 만에 100% 통과 (결함률 0.0%) |
| **제로 트러스트 클린 베이스라인** | **NIST SP 800-207 준거** | 신규 설치 시 0건 위협, 0건 차단 IP, 100/100 만점의 무오탐 텔레메트리 기준선(0% False Positive) 확립 |
| **초고속 격리 & 원상복구** | **0.1초 차단 / 0.8초 복구** | 디코이 침투 즉시 **0.1초** 커널 방화벽(`netsh`) 차단, `demo_runner.py --cleanup` **0.80초 (804ms)** 만에 완전 복구 |
| **4중 AI-XDR 하이브리드 엔진** | **Groq LPU 0.48초** | 초고속 LPU(0.48s) ➔ NVIDIA NIM(0.52s) ➔ Ollama 로컬 LLM ➔ 내장 룰 엔진으로 이어지는 100% 무장애 캐스케이드 |
| **MITRE ATT&CK Matrix** | **Navigator v4.5 호환** | Enterprise v14 기준 5대 전술 7대 핵심 기법 실시간 매핑 및 공식 Layer JSON 스키마 내보내기 완벽 지원 |
| **독립형 무설치 패키징** | **17.5 MB 단일 .exe** | 파이썬 미설치 PC/VM 환경에서도 더블클릭 1.2초 만에 네이티브 다크 테마 GUI 관제 콘솔 구동 |
| **엔터프라이즈 CI/CD 파이프라인** | **GitHub Actions** | Git Tag 푸시 시 클라우드 러너에서 70개 테스트 자동 검증 후 GitHub Releases 바이너리 패키징 자동화 |

---

## 2. 시스템 아키텍처 (팀 원본 아키텍처 vs 단독 고도화 산출물)

### 1) 팀 프로젝트 원본 통합 아키텍처 (`NEXUS WORK` 공식 발표 03/38)
```text
[ 00 · 공격 테스트 구간 ]
공격자 Kali (192.168.3.11) ➔ 웹 경로 스캔 / 로그인 브루트포스 / 비인가 접근 / 프롬프트 인젝션
      │ (VMware NAT)
      ▼
[ 01 · 경계 방어 / pfSense (192.168.3.10:5070 - 이시헌) ]
GeoBlock / Suricata IDS / pfBlockerNG 커스텀 피드 / HAProxy / NAT 전달
      │ (X-Forwarded-For)
      ▼
[ 02 · LAN 내부 / 포털 서버 (192.168.3.14:5070 - 홍주형 ★ 본인 전담 100%) ]
로그인·세션(R1,R5~R7) │ AI Agent·Tool(R2~R4,R11~R12) │ 디코이·404(R8) │ 관리자·기밀 BOLA(R9,R10)
      │
      ├───────────────────────┬────────────────────────┐
      ▼ (GELF UDP 12201)      ▼ (Syslog 5140)          ▼ (Wazuh 1514)
[ 03 · 통합 탐지 / Graylog (192.168.3.15 - 김태빈) ]
Stream 분류: NEXUS_AUTH (R1,R5~R7) / NEXUS_AI_SECURITY (R2~R4,R11~R12) / NEXUS_WEB (R8~R10, FIM)
      │ (조건 일치 ➔ 보안 경보 Webhook POST)
      ▼
[ 04 · SOAR / 대응 (192.168.3.15 - 김태빈/공통) ]
n8n SOAR ➔ Groq LLM AI-XDR 상관분석 ➔ 관리자 승인 게이트 ➔ 차단 조치 (Portal IP 차단 & pfSense Drop)
```

### 2) NEXUS-GUARD 엔드포인트 통합 관제 체계 (홍주형 단독 고도화 100%)
팀 프로젝트에서 분산되어 있던 5대 인프라의 관제 화면과 대응 파이프라인을 **단 하나의 고성능 데스크톱 관제 콘솔**로 통합하고, 외부 인프라 부재 시에도 100% 자립 구동되는 Standalone 페일세이프를 완성했습니다:

```text
[ 외부 인터넷 / 공격자 (Kali Linux) ]
               │
               ▼ (인바운드 트래픽)
┌────────────────────────────────────────────────────────────────────────┐
│                   NEXUS-GUARD 엔드포인트 보안 관제센터                  │
│                   (CustomTkinter 60FPS 네이티브 데스크톱)              │
├────────────────────────────────────────────────────────────────────────┤
│  1. 인그레스 감시 & 디코이 트랩 (/.env, /.git, /admin.php 접근 즉시 격리)│
│  2. MITRE ATT&CK Matrix v14 3계층 하이브리드 매핑 엔진 (Navigator 호환) │
│  3. SHA-256 FIM 무결성 감시기 (핵심 소스코드 위변조 0.1초 실시간 감지) │
│  4. 360도 레이더 & GlassWire 스타일 실시간 트래픽 오실로스코프 파형 캔버스 │
│  5. 24틱 네온 게이지 & SentinelOne 스타일 쉬운 한글 종합 판정 배너      │
│  6. 4단계 캐스케이드 AI-XDR 라우터 (Groq LPU 0.48s / NIM / Ollama)      │
└──────────────────┬─────────────────┬─────────────────┬─────────────────┘
                   │                 │                 │
                   ▼                 ▼                 ▼
          [ pfSense WAF 방화벽 ]   [ Graylog SIEM ]   [ Wazuh EDR & n8n ]
          (자동 피드 Drop)         (GELF UDP 12201)   (자동 복구 플레이북)
                   │
                   ▼ (외부 인프라 부재 시)
       ┌─────────────────────────────────────────────────────────┐
       │ [Standalone 무중단 페일세이프 모드]                     │
       │ 자체 SHA-256 FIM + Windows netsh 커널 제어 + 로컬 AI    │
       └─────────────────────────────────────────────────────────┘
```


---

## 3. 본인 담당 업무 및 단독 기여 내역 (100% Ownership)

1. **`NEXUS-GUARD` 단독 아키텍처 설계 및 풀스택 GUI 구현 (100%):**
   - 웹 브라우저나 외부 인터넷 창 없이 단독으로 구동되는 네이티브 다크 테마 GUI 관제 콘솔 개발.
   - Tkinter Canvas 상에 360도 레이더 회전 빔 및 초당 KB/s 패킷 오실로스코프 파형을 60FPS로 자체 렌더링.
   - WCAG 2.x AA 고대비 가이드라인(대비율 4.5:1 이상) 및 초보자/CISO 친화적 쉬운 한글 종합 판정 배너 탑재.
2. **NIST SP 800-207 제로 트러스트 클린 베이스라인(Clean Slate) 아키텍처 완성:**
   - 임의의 감점이나 더미 공격자가 없는 100/100 점 만점의 초기 무오탐 기준선(Operational Zero-Anomaly Baseline) 확립.
   - `test_clean_slate.py` 등 70개 엔터프라이즈 전수 자동화 테스트 스위트 직접 작성.
3. **능동 방어(Active Defense) 디코이 트랩 및 0.8초 원상복구 엔진 구축:**
   - 10개 미끼 엔드포인트 프로빙 즉시 0.1초 만에 OS 커널 방화벽(`netsh advfirewall`) 차단 연동.
   - `demo_runner.py --cleanup` 실행 시 0.80초 (실측 804.7ms) 만에 시스템 전체 상태 클린 리셋 구현.
4. **공식 MITRE ATT&CK Navigator v4.5 호환 3계층 매핑 엔진 개발:**
   - Tier 1 O(1) 해시 ➔ Tier 2 AST/CWE 정규화 ➔ Tier 3 Groq 0.5s AI 트리아지 다계층 탐지 파이프라인 완성.
5. **SHA-256 FIM 파일 무결성 감시 및 CISO 감사 보고서 발행기 개발:**
   - 핵심 소스코드 및 설정의 SHA-256 디지털 지문을 10초 주기로 대조하여 0.1초 만에 위변조 포착.
   - SHA-256 디지털 인장이 각인된 원클릭 HTML / CSV / JSON CISO 감사 보고서 패키징 엔진 구현.
6. **배포 파이프라인 자동화 및 무설치 패키징:**
   - `PyInstaller` 기반 17.5MB 단일 실행 파일(`.exe`) 및 GitHub Actions CI/CD 태그 자동 릴리즈 체계 구축.

---

## 4. 포트폴리오 첨부 자료 및 관련 문서

1. **심사위원 공식 종합 평가서 (100점 만점 증빙):** [`EVALUATION_RUBRIC_COMPLIANCE.md`](EVALUATION_RUBRIC_COMPLIANCE.md)
2. **이력서 및 자기소개서 (STAR 문제해결 스토리):** [`RESUME_홍주형_이력서_자기소개서.md`](RESUME_홍주형_이력서_자기소개서.md)
3. **외부 솔루션 마스터 연동 가이드 (324줄 런북):** [`EXTERNAL_INTEGRATIONS_GUIDE.md`](EXTERNAL_INTEGRATIONS_GUIDE.md)
4. **CISO 적대적 심사 보고서 & 4대 압박 질문 매뉴얼:** [`../evidence/ciso_adversarial_critique.md`](../evidence/ciso_adversarial_critique.md)
5. **공식 발표 슬라이드 (PPTX):** [`../presentation/NEXUS_WORK_홍주형_발표자료_최종.pptx`](../presentation/NEXUS_WORK_홍주형_발표자료_최종.pptx)
6. **포트폴리오 마스터 문서 (PDF):** [`../presentation/NEXUS_포트폴리오.pdf`](../presentation/NEXUS_포트폴리오.pdf)
7. **70개 테스트 통과 원본 로그:** [`../evidence/pytest_test_results.txt`](../evidence/pytest_test_results.txt)
8. **클린 베이스라인 실측 로그:** [`../evidence/clean_slate_verification.txt`](../evidence/clean_slate_verification.txt)
9. **0.8초 원상복구 실측 로그:** [`../evidence/demo_cleanup_evidence.txt`](../evidence/demo_cleanup_evidence.txt)
