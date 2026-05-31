# EDR (Endpoint Detection and Response) 시스템 — 통합 문서 (PRD + SRS + 진행 상황)

버전: 1.0  
작성일: 2026-05-22

요약:
- Windows Sysmon(System Monitor) 이벤트를 수집하여 이상 행위 탐지 및 대응(EDR) 기능 제공
- 수집기(Collector), 중앙 서버(FastAPI + PostgreSQL), 관리자/사용자 대시보드(Streamlit)로 구성
- 주요 수집 이벤트 ID: 1(프로세스 생성), 3(네트워크 연결), 5(프로세스 종료), 22(DNS 쿼리)
- MITRE ATT&CK 프레임워크 기반 이벤트 매핑(Tactic/Technique) 및 위험도 산정
- VirusTotal API 연동으로 파일 해시 및 URL 악성 여부 판별 기능 내장

목차
1. 목표 및 배경 (PRD)  
2. 기능 목록 (High-level)  
3. 상세 요구사항 (SRS)  
4. 아키텍처 및 스택  
5. 데이터 모델  
6. 화면 설계 및 UI 구성 (대시보드)  
7. 현재 구현 진행 상황 (2026-05-22 기준)

---

1) 목표 및 배경 (PRD)
- 목적: 엔드포인트(Windows) 환경에서 발생하는 시스템 활동 로그를 실시간으로 수집하고 중앙화하여 위협을 분석/모니터링하는 EDR 프로토타입 구현.
- 성공 기준:
  - PowerShell을 이용한 WinEvent 로그 수집 및 MITRE ATT&CK 기반 분류
  - 수집된 로그의 중앙 서버 전송 및 RDBMS(PostgreSQL) 적재
  - 직관적인 사용자(엔드포인트 에이전트) 및 관리자(통합 모니터링) 웹 대시보드 제공
  - 의심스러운 파일 및 네트워크(URL)에 대한 VirusTotal 위협 인텔리전스 조회 가능

---

2) 기능 목록 (High-level)
- 에이전트/사용자 기능: 수동/자동 Sysmon 이벤트 수집, 중앙 서버로 로그 전송, 의심 파일/URL VirusTotal 검사
- 시스템 백엔드 기능: 클라이언트 로그 수신 및 데이터베이스 저장, 조건별 로그 검색/필터링 API 제공
- 관리자 기능: 수집된 전체 엔드포인트 로그 모니터링, 위험도별 알람, 통계 및 차트 시각화(Altair 등)

---

3) 상세 요구사항 (SRS)

3.1 기능적 요구사항 (요약)
- FR1: Sysmon 이벤트 수집 (sysmon_collector.py)
  - Windows Event ID 1, 3, 5, 22 대상
  - PowerShell `Get-WinEvent` 구문을 실행하여 로그 추출
  - 각 이벤트 메시지 파싱 후 MITRE ATT&CK Tactic/Technique 매핑 수행
- FR2: 외부 위협 분석 (VirusTotal 연동)
  - 사용자가 업로드한 파일의 SHA256 해시를 추출하여 VT API 검사
  - URL 분석 기능 제공 (Base64 인코딩 후 VT API 요청)
- FR3: 중앙 서버 API (server.py)
  - `POST /logs`: 여러 개의 로그를 JSON 형태로 수신 받아 DB 적재
  - `GET /logs`: host, level, limit 조건을 기반으로 로그 조회
  - `DELETE /logs`: 데이터 초기화용
- FR4: UI 대시보드 연동
  - Streamlit을 활용해 사용자 대시보드(user_dashboard.py)와 관리자 대시보드(admin_dashboard.py) 완전 분리 운영

3.2 비기능적 요구사항
- NFR1: 성능 및 호환성
  - 수집기는 Windows 환경에 한정하여 작동하며, pywin32 등의 종속성 필요
- NFR2: 확장성
  - AI Risk 및 AI Score 등 추후 머신러닝/AI 위협 분석 모델을 연동할 수 있도록 데이터베이스 스키마(ai_score 등) 선반영

---

4) 아키텍처 및 개발 스택
- 프론트엔드 (대시보드): Streamlit (Python) + Altair(차트 시각화) + Custom CSS(NanumSquareRound 폰트 등)
- 백엔드 (서버): FastAPI + Uvicorn
- 데이터베이스: PostgreSQL (SQLAlchemy ORM 연동)
- 엔드포인트 수집: Python `subprocess` (PowerShell 호출) 및 `win32evtlog`
- 외부 연동: VirusTotal API (REST API)

---

5) 데이터 모델

SysmonLog 테이블 (sysmon_logs)
- id (PK), recv_time (수신시간), gen_time (생성시간), host_ip (호스트 IP)
- os_name, rule_level (룰 레벨: 중요/일반), risk (위험도: H/M/L)
- detect_type (탐지 유형), tactic_id, tactic_name, technique_id, technique_name
- action_desc (행위 내용 파싱 텍스트), process_name, event_id
- command_line, destination_ip, destination_port, query_name
- status (상태), ai_risk, ai_score (추후 확장)

---

6) 화면 설계 (대시보드)

(1) 관리자 대시보드 (admin_dashboard.py)
- 다크 테마 기반, Custom CSS를 통한 깔끔한 UI 구성 (metric-card 등)
- 1) 핵심 지표 패널: 총 수집 로그 수, 위험도(High/Medium/Low) 분류 통계, 원형 프로그레스바 등
- 2) 시각화: Altair 기반의 위협 탐지 추이(시계열 차트), Tactic 별 분포 바 차트 등
- 3) 상세 데이터 표: DataFrame으로 로그 확인

(2) 사용자/엔드포인트 대시보드 (user_dashboard.py)
- 1) Sysmon 로그 수집 패널: Event ID (1,3,5,22) 대상 데이터 로컬 수집 및 세션 저장
- 2) 중앙 서버 전송 버튼: 수집된 데이터를 FastAPI `/logs` 로 전송
- 3) VirusTotal 연동 패널: 파일 업로드 및 URL 입력 폼 제공, 검사 상태 폴링 및 결과 시각화(Malicious/Undetected 통계 반환)

---

7) 현재 구현 진행 상황 (2026-05-22 기준)

[구현 완료된 항목]
- ✅ 데이터베이스 스키마 구축 (`database.py`) 및 PostgreSQL 연동 완료
- ✅ FastAPI 백엔드 구축 (`server.py`): 조회, 생성, 삭제 엔드포인트 정상 작동
- ✅ Sysmon 이벤트 로컬 수집기 (`sysmon_collector.py`): PowerShell 연동, 메시지 정규화, MITRE 정책 매핑 기능 완료
- ✅ 사용자 대시보드 (`user_dashboard.py`): VT 연동(파일/URL 검사), 로컬 Sysmon 수집, 서버 전송 인터페이스 완비
- ✅ 관리자 대시보드 (`admin_dashboard.py`): 수집 데이터 통계 및 Altair 기반 차트, Custom CSS 디자인 적용 완료

[향후 보완/진행 가능 항목 (Pending)]
- 🔄 실시간 로깅 체계: 현재는 버튼을 통한 수동/배치 수집 위주이므로, 백그라운드 데몬 형태의 자동 전송 체계 도입 고려
- 🔄 사용자/관리자 인증 체계: Dashboard 및 API 접근에 대한 토큰 기반 인증(JWT) 및 권한 관리 시스템(RBAC) 도입 필요

---

8) 머신러닝(XGBoost) 구현 계획 (Implementation Roadmap)

개요
- 대상: 1인 개발자
- 총 소요: 약 1 Phase (1 man/day)
- 목표: 수집된 Sysmon 로그 데이터셋을 기반으로 위협도(위험 수준)를 예측하는 AI/머신러닝 파이프라인 구축 및 백엔드 연동.

Phase 1: XGBoost 자동 학습 환경 및 서버 연동 (~1 man/day)
목표: 데이터 수신 시 전처리부터 학습, 그리고 실시간 추론(Inference)까지 완료할 수 있는 통합 ML 환경 구성.

구현 항목:
1. 학습 환경 기초 구성 (완료됨)
   - `xgboost/train.py` 뼈대 및 CLI 인자(`argparse`) 구성
   - LabelEncoder를 활용한 범용 문자열 자동 전처리 로직 구현
   - 모델(`.json`) 및 인코더(`.pkl`) 저장 모듈 완성
2. 데이터셋 주입 및 모델 학습 (진행 예정)
   - 정답(위험도)이 라벨링된 실제 Sysmon 데이터셋(.csv) 확보
   - `train.py` 실행을 통한 하이퍼파라미터(max_depth, learning_rate 등) 최적화
3. 백엔드(FastAPI) 실시간 연동
   - `server.py`에서 서버 기동 시 `xgboost_sysmon_model.json` 및 `label_encoders.pkl` 메모리 로드
   - `POST /logs` 엔드포인트 내에 머신러닝 추론 로직 삽입
   - 예측 결과를 `ai_risk`, `ai_score` 필드에 매핑하여 PostgreSQL DB에 저장
4. 대시보드 시각화 연동
   - `admin_dashboard.py`에 '일반 룰(Rule) 위험도'와 'AI 예측 위험도'의 불일치(Anomaly)를 시각화하는 위젯 추가

검증 항목:
- 제공된 데이터셋으로 학습했을 때 Accuracy 90% 이상 도달 여부 확인
- FastAPI `/logs` 엔드포인트 수신 시 기존 동기 처리 속도 대비 병목이 발생하지 않는지 확인
- 문자열 데이터(예: 새로운 프로세스 이름) 유입 시 LabelEncoder의 예외 처리(Unknown) 작동 확인

테스트:
- 학습/테스트 분할 데이터 검증 (train_test_split)
- 수동으로 악성 로그(ID 1, 3 연계) JSON을 FastAPI로 쏘아 `ai_risk="H"`가 찍히는지 통합 테스트