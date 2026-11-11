# 🛡️ [포트폴리오] NEXUS-GUARD: AI 기반 엔터프라이즈 능동 방어 보안 솔루션

> **작성자:** 홍주형 (Hong Juhyeong) · 포털 코어 아키텍트 & 보안 최고관리자  
> **개인 GitHub 저장소:** [https://github.com/stulss/nexus-guard](https://github.com/stulss/nexus-guard)  
> **웹 포트폴리오 링크:** [https://nexus-portfolio-nu.vercel.app](https://nexus-portfolio-nu.vercel.app)  
> **팀 프로젝트 원본 저장소:** [https://github.com/stulss/nexus-work](https://github.com/stulss/nexus-work)  
> **버전:** v2.5.0-LTS (Commercial Grade)  

---

## 1. 프로젝트 요약 & 핵심 정량 실적

| 핵심 지표 | 실적 수치 | 상세 내용 |
|---|:---:|---|
| **자동화 테스트 검증** | **70 / 70 PASS (100%)** | 단위/통합/시각화/초기상태 전수 테스트 10.78초 만에 100% 통과 |
| **초기 클린 상태 보장** | **100 / 100 만점** | 신규 설치 시 0건 위협, 0건 차단 IP, 100점 무오탐(0% FP) 보장 |
| **독립형 패키징** | **17.5 MB 단일 .exe** | 파이썬 미설치 환경에서도 더블클릭 1초 만에 네이티브 관제 콘솔 구동 |
| **위협 감지 및 격리** | **0.1초 / 0.5초** | 디코이 침투 즉시 0.1초 커널 차단, AI-XDR 0.5초 복합 공격 체인 분석 |
| **CI/CD 자동 배포** | **GitHub Actions** | Git Tag 푸시 시 테스트 검증 및 GitHub Releases 자동 패키징 |

---

## 2. 시스템 아키텍처 (Clean-Slate Active Defense)

```text
[ 외부 인터넷 / 공격자 (Kali) ]
              │
              ▼ (인바운드 트래픽)
┌────────────────────────────────────────────────────────────────────────┐
│                   NEXUS-GUARD 엔드포인트 보안 관제센터                  │
├────────────────────────────────────────────────────────────────────────┤
│  1. 인그레스 감시 & 디코이 트랩 (/.env, /.git, /admin.php)               │
│  2. MITRE ATT&CK Matrix v14 매핑 엔진 (14대 전술 스트립 실시간 점등)     │
│  3. SHA-256 FIM 무결성 감시기 (소스코드 위변조 0.1초 감지)              │
│  4. 360도 레이더 & GlassWire 스타일 실시간 트래픽 캔버스                 │
│  5. 24틱 네온 게이지 & SentinelOne 스타일 쉬운 한글 종합 판정            │
└──────────────────┬─────────────────┬─────────────────┬─────────────────┘
                   │                 │                 │
                   ▼                 ▼                 ▼
          [ pfSense WAF 방화벽 ]   [ Graylog SIEM ]   [ Wazuh EDR & n8n ]
          (자동 피드 Drop)         (GELF UDP 12201)   (자동 복구 플레이북)
```

---

## 3. 본인 담당 업무 및 단독 기여 내역 (100%)

1. **`NEXUS-GUARD` 단독 아키텍처 설계 및 구현 (100%):**
   - 웹 브라우저나 외부 인터넷 창 없이 단독으로 구동되는 네이티브 다크 테마 GUI 관제 콘솔 개발
   - 360도 레이더 회전 빔 및 초당 KB/s 오실로스코프 파형 캔버스 자체 렌더링 구현
2. **클린 슬레이트(Clean Slate) 무결성 아키텍처 완성:**
   - 임의의 감점이나 더미 공격자가 없는 100점 만점 초기 상태 확립
   - `test_clean_slate.py` 등 70개 자동화 테스트 스위트 작성
3. **능동 방어(Active Defense) 디코이 트랩 및 1초 원상복구 엔진:**
   - 10개 미끼 엔드포인트 프로빙 즉시 403 차단 및 OS 방화벽 연동
   - `demo_runner.py --cleanup` 1초 만에 전체 상태 클린 리셋 구현
4. **배포 파이프라인 자동화:**
   - `PyInstaller` 기반 단일 실행 파일(`.exe`) 및 GitHub Actions CI/CD 구축

---

## 4. 포트폴리오 첨부 자료 목록

1. **발표 슬라이드 (PPTX):** [`NEXUS_WORK_홍주형_발표자료_최종.pptx`](docs/presentation/NEXUS_WORK_홍주형_발표자료_최종.pptx)
2. **포트폴리오 PDF:** [`NEXUS_포트폴리오.pdf`](docs/presentation/NEXUS_포트폴리오.pdf)
3. **외부 솔루션 연동 가이드:** [`EXTERNAL_INTEGRATIONS_GUIDE.md`](docs/EXTERNAL_INTEGRATIONS_GUIDE.md)
4. **이력서 및 자기소개서:** [`RESUME_홍주형_이력서_자기소개서.md`](docs/RESUME_홍주형_이력서_자기소개서.md)
