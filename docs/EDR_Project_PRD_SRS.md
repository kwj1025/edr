# EDR (Endpoint Detection and Response) 시스템 — 통합 문서 (PRD + SRS + 진행 상황)

버전: 2.0  
최초 작성일: 2026-05-22  
**최종 업데이트: 2026-06-29**

요약:
- Windows Sysmon(System Monitor) 이벤트를 수집하여 이상 행위 탐지 및 대응(EDR) 기능 제공
- 수집기(Collector), Fileless 탐지기(fileless_detector.py), 중앙 서버(FastAPI + PostgreSQL), 사용자 대시보드(Streamlit)로 구성
- 주요 수집 이벤트 ID: 1(프로세스 생성), 3(네트워크 연결), 5(프로세스 종료), 22(DNS 쿼리), 4104(PowerShell Script Block)
- MITRE ATT&CK 프레임워크 기반 이벤트 매핑(Tactic/Technique) 및 위험도 산정
- XGBoost 머신러닝 모델 통합으로 실시간 위협도 자동 판별 (Accuracy ~93.6%)
- VirusTotal API 연동으로 파일 해시 및 URL 악성 여부 판별 기능 내장
- psutil 기반 실시간 프로세스 모니터링 기능 내장

목차
1. 목표 및 배경 (PRD)
2. 기능 목록 (High-level)
3. 상세 요구사항 (SRS)
4. 아키텍처 및 스택
5. 데이터 모델
6. 화면 설계 및 UI 구성 (대시보드)
7. 현재 구현 진행 상황 (2026-06-29 기준)
8. 머신러닝(XGBoost) 구현 결과 및 히스토리

---

## 1. 목표 및 배경 (PRD)

- **목적:** 엔드포인트(Windows) 환경에서 발생하는 시스템 활동 로그를 실시간으로 수집하고 중앙화하여 위협을 분석/모니터링하는 EDR 프로토타입 구현.
- **성공 기준:**
  - PowerShell을 이용한 WinEvent 로그 수집 및 MITRE ATT&CK 기반 분류
  - 수집된 로그의 중앙 서버 전송 및 RDBMS(PostgreSQL) 적재
  - XGBoost 머신러닝 모델을 활용한 실시간 위협도 자동 판별
  - Fileless 공격(PowerShell 기반) 탐지 기능 제공
  - 직관적인 사용자(엔드포인트 에이전트) 웹 대시보드 제공
  - 의심스러운 파일 및 네트워크(URL)에 대한 VirusTotal 위협 인텔리전스 조회 가능
  - 실시간 프로세스 모니터링 기능 제공

---

## 2. 기능 목록 (High-level)

- **에이전트/사용자 기능:** 수동 Sysmon 이벤트 수집, Fileless 공격 탐지, 실시간 프로세스 모니터링, 중앙 서버로 로그 전송, 의심 파일/URL VirusTotal 검사
- **시스템 백엔드 기능:** 클라이언트 로그 수신 및 데이터베이스 저장, 조건별 로그 검색/필터링 API 제공
- **AI/ML 기능:** XGBoost 모델 실시간 추론, 위협도 4단계(Low/Medium/High/Critical) 분류, 악성 Recall 97% 달성

---

## 3. 상세 요구사항 (SRS)

### 3.1 기능적 요구사항

- **FR1: Sysmon 이벤트 수집 (sysmon_collector.py)**
  - Windows Event ID 1, 3, 5, 22 대상
  - `win32evtlog` 모듈을 통한 직접 로그 수집
  - 각 이벤트 메시지 파싱 후 MITRE ATT&CK Tactic/Technique 매핑 수행
  - `collect_fileless()` 함수: Event ID 4104(PowerShell Script Block Logging) 수집

- **FR2: Fileless 공격 탐지 (fileless_detector.py)** ← 신규 (2026-06-29)
  - 23개 의심 키워드(DownloadString, IEX, WScript.Shell 등) 기반 탐지
  - Base64 인코딩 패턴 감지 및 디코딩
  - 백그라운드 PowerShell 프로세스 탐지 (Hidden, NoProfile 등)
  - 복합 공격 체인 감지 (다운로드 + 실행)
  - MITRE ATT&CK 매핑 (TA0005, T1140 등)

- **FR3: XGBoost 실시간 위협도 판별 (threat_predictor.py)**
  - 학습된 모델(`xgboost_sysmon_model.json`) 및 인코더(`label_encoders.pkl`) 로드
  - 로그 수집 시 자동으로 위협도 판별 → 대시보드 테이블에 `XGBoost_위협도`, `XGBoost_라벨` 컬럼 추가
  - 미지 카테고리(Unknown) 안전 처리

- **FR4: 외부 위협 분석 (VirusTotal 연동)**
  - 사용자가 업로드한 파일의 SHA256 해시를 추출하여 VT API 검사
  - URL 분석 기능 제공 (Base64 인코딩 후 VT API 요청)

- **FR5: 중앙 서버 API (server.py)**
  - `POST /logs`: 여러 개의 로그를 JSON 형태로 수신 받아 DB 적재
  - `GET /logs`: host, level, limit 조건을 기반으로 로그 조회
  - `DELETE /logs`: 데이터 초기화용

- **FR6: 실시간 프로세스 모니터링** ← 신규 (2026-06-29)
  - `psutil`을 활용한 현재 실행 중인 프로세스 목록 수집
  - PID, 프로세스명, 상태, CPU%, 메모리(MB), 사용자, 시작 시간, 실행 경로 표시
  - 의심 키워드(powershell, cmd, mshta, rundll32, mimikatz 등 20개) 자동 탐지
  - 이름/경로 검색 필터, CPU%/메모리 정렬, 전체/의심만 탭 구분

### 3.2 비기능적 요구사항
- **NFR1:** 수집기는 Windows 환경에 한정하여 작동하며, pywin32 종속성 필요
- **NFR2:** XGBoost 모델 Test Accuracy ≥ 90% (현재 93.6% 달성)
- **NFR3:** Train-Val Gap ≤ 0.05 (과적합 방지, 현재 0.0009)

---

## 4. 아키텍처 및 개발 스택

- **프론트엔드 (대시보드):** Streamlit (Python) + Altair(차트 시각화) + Custom CSS(NanumSquareRound 폰트)
- **백엔드 (서버):** FastAPI + Uvicorn
- **데이터베이스:** PostgreSQL (SQLAlchemy ORM 연동)
- **엔드포인트 수집:** `win32evtlog` (Sysmon), `subprocess` (PowerShell 4104), `psutil` (프로세스)
- **AI/ML:** XGBoost 3.2.0 + scikit-learn + joblib
- **외부 연동:** VirusTotal API (REST API)

---

## 5. 데이터 모델

**SysmonLog 테이블 (sysmon_logs)**
- `id` (PK), `recv_time` (수신시간), `gen_time` (생성시간), `host_ip` (호스트 IP)
- `os_name`, `rule_level` (룰 레벨), `risk` (위험도: H/M/L)
- `detect_type` (탐지 유형), `tactic_id`, `tactic_name`, `technique_id`, `technique_name`
- `action_desc` (행위 내용), `process_name`, `event_id`
- `command_line`, `destination_ip`, `destination_port`, `query_name`
- `status` (상태), `ai_risk`, `ai_score` (XGBoost 판별 결과)

---

## 6. 화면 설계 (대시보드)

**사용자 대시보드 (user_dashboard.py)**
1. **상단 헤더:** 실시간 시계, 조회 범위 선택, 새로고침 버튼
2. **위험 현황 패널:** 총 탐지 건수, 신규/확인 중/보류/확인 완료 상태 지표
3. **최근 탐지 위협 테이블:** XGBoost_위협도, XGBoost_라벨 포함 컬럼
   - [🔍 Sysmon 로그 수집] 버튼: Event ID 1·3·5·22 수집 + XGBoost 판별 + 서버 전송
   - [🛡️ Fileless 공격 탐지] 버튼: Event ID 4104 수집 + 패턴 분석 + 서버 전송
4. **대응 결과 현황:** 자동 대응 ON/OFF 토글, 대응 이력 테이블
5. **하단 차트:** 위험도별 도넛 차트, 탐지 유형별 바 차트, VirusTotal 정밀 검사
6. **실시간 프로세스 모니터링:** ← 신규 (2026-06-29)
   - 요약 지표 (전체/의심 프로세스 수, CPU 1위)
   - 전체 탭 / 의심 프로세스만 탭 구분
   - 검색 필터 + 정렬 기준 선택 + 새로고침

---

## 7. 현재 구현 진행 상황 (2026-06-29 기준)

### 구현 완료된 항목
- ✅ 데이터베이스 스키마 구축(`database.py`) 및 PostgreSQL 연동 완료
- ✅ FastAPI 백엔드 구축(`server.py`): 조회, 생성, 삭제 엔드포인트 정상 작동
- ✅ Sysmon 이벤트 로컬 수집기(`sysmon_collector.py`): win32evtlog 연동, MITRE 정책 매핑 완료
- ✅ Fileless 공격 탐지 모듈(`fileless_detector.py`): 23개 키워드, Base64 감지, MITRE 매핑 완료
- ✅ XGBoost 학습 파이프라인(`train.py`): Data Leakage 제거, 희귀값 마스킹, 하이퍼파라미터 최적화 완료
- ✅ XGBoost 실시간 추론 모듈(`threat_predictor.py`): 대시보드 통합 완료
- ✅ 사용자 대시보드(`user_dashboard.py`): Fileless 탐지 버튼, 프로세스 모니터링, XGBoost 위협도 표시 완비
- ✅ Windows cp949 인코딩 에러 수정: 이모지 print → ASCII 텍스트로 교체

### 향후 보완/진행 가능 항목 (Pending)
- 🔄 **로그 중복 수집 방지:** 마지막 RecordId 기반 북마크 저장 로직 부재
- 🔄 **인증 체계:** Dashboard 및 API 접근에 대한 JWT 기반 인증 및 RBAC 도입 필요
- 🔄 **비동기 처리:** VirusTotal 폴링 중 UI 멈춤 현상 → 백그라운드 스레드 도입 필요
- 🔄 **추론 파이프라인 동기화:** `threat_predictor.py`에 학습과 동일한 전처리(누출 컬럼 제거 + 희귀값 마스킹) 적용 필요
- 🔄 **logging 모듈 도입:** print() 기반 로그 → logging 모듈로 전환 권장

---

## 8. 머신러닝(XGBoost) 구현 결과 및 히스토리

### 최종 확정 하이퍼파라미터

| 파라미터 | 값 | 비고 |
|----------|-----|------|
| `max_depth` | 3 | max_depth=5 실험 후 3으로 확정 |
| `n_estimators` | 2000 | n=1000 vs n=2000 비교 실험 후 채택 |
| `learning_rate` | 0.01 | 낮은 lr + 많은 n 조합으로 안정적 수렴 |
| `min_child_weight` | 5 | 과적합 방지 |
| `reg_alpha` | 2.0 | L1 정규화 |
| `reg_lambda` | 2.0 | L2 정규화 |
| `subsample` | 0.7 | 행 랜덤 샘플링 |
| `colsample_bytree` | 0.7 | 피처 랜덤 샘플링 |
| `gamma` | 1.0 | 최소 분기 이득 |

### 학습 결과 (최종)

| 지표 | 값 |
|------|-----|
| 5-Fold CV | **93.47% ± 0.31%** |
| Train Accuracy | 93.61% |
| Val Accuracy | 93.52% |
| Test Accuracy | **93.63%** |
| Test F1 | 93.62% |
| Train-Val Gap | **0.0009** (과적합 없음) |
| 악성 Recall | 97% |

### 주요 수정 히스토리

| 날짜 | 수정 내용 |
|------|-----------|
| 2026-05-22 | XGBoost 학습 환경 초기 구축 |
| 2026-05-23 | train/test 데이터 경로 확정, 과적합 방지 하이퍼파라미터 적용 |
| 2026-05-31 | XGBoost ↔ 사용자 대시보드 통합 (ThreatPredictor 클래스) |
| 2026-06-29 | **Data Leakage 발견 및 수정** (source_dataset 등 누출 컬럼 제거) |
| 2026-06-29 | **희귀값 마스킹 적용** (process_name 등 빈도 5 미만 → `__RARE__`) |
| 2026-06-29 | **하이퍼파라미터 최적화** (n=1000 vs n=2000 비교 실험 → n=2000 채택) |
| 2026-06-29 | **Fileless 탐지 모듈 통합** (fileless_detector.py → 대시보드 버튼 연동) |
| 2026-06-29 | **실시간 프로세스 모니터링 추가** (psutil 기반) |