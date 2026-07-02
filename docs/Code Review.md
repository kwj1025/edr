# EDR 프로젝트 전체 코드 리뷰 보고서

본 문서는 EDR(Endpoint Detection and Response) 시스템 프로젝트의 전체 소스 코드를 아키텍처, 성능, 보안, 유지보수성 등 다각도에서 분석한 코드 리뷰 보고서입니다.

최초 작성일: 2026-05-22  
**최종 업데이트: 2026-06-29**

---

## 1. 아키텍처 및 시스템 구조 (Architecture)

### 긍정적 측면 (Pros)
- **모듈화 및 역할 분리:** 백엔드(FastAPI), 데이터베이스(SQLAlchemy), 프론트엔드 대시보드(Streamlit), 수집기(Sysmon Collector), Fileless 탐지기(fileless_detector.py), 머신러닝 모듈(XGBoost)이 각각 독립 구조로 분리되어 있어 유지보수성과 확장성이 우수합니다.
- **RESTful API 설계:** FastAPI를 활용한 `/logs` 엔드포인트(GET, POST, DELETE) 설계가 직관적이고 표준을 잘 따르고 있습니다.
- **ML 파이프라인 통합:** `ThreatPredictor` 클래스를 통해 XGBoost 모델을 대시보드에 통합하여, 로그 수집과 동시에 위협도 판별이 이루어지는 end-to-end 파이프라인이 구성되었습니다.
- **실시간 프로세스 모니터링:** `psutil` 기반의 프로세스 모니터링 섹션이 대시보드에 추가되어 현재 실행 중인 프로세스를 실시간으로 확인 가능합니다.

### 개선 권고사항 (Cons & Recommendations)
- **비동기 처리(Async) 부재:** FastAPI의 `server.py` 엔드포인트와 SQLAlchemy 모델이 여전히 동기(Sync) 방식으로 구현되어 있습니다. 대량의 로그 트래픽이 동시다발적으로 발생할 경우 병목 현상이 발생할 수 있습니다.  
  👉 **권고:** 향후 `async/await` 지원 드라이버(`asyncpg`)와 `AsyncSession` 도입을 권장합니다.

---

## 2. 보안 (Security)

### 긍정적 측면 (Pros)
- VirusTotal API 연동을 통해 파일 해시 및 URL 검사가 효과적으로 구현되어 있습니다.
- Fileless 공격 탐지 모듈이 추가되어 PowerShell 스크립트 블록 로깅(Event ID 4104) 기반 탐지가 가능합니다. Base64 난독화 디코딩 및 MITRE ATT&CK 매핑도 포함됩니다.
- 의심 프로세스 키워드(powershell, mshta, rundll32, certutil, mimikatz 등 20개)를 활용한 실시간 탐지가 대시보드에 내장되어 있습니다.

### 개선 권고사항 (Cons & Recommendations)
- **하드코딩된 인증 정보:**
  - `backend/database.py` 내 `DATABASE_URL`에 DB 계정 정보가 평문 하드코딩되어 있습니다.
  - `user_dashboard.py` 내 VirusTotal API Key가 평문으로 관리되고 있습니다.  
  👉 **권고:** `.env` + `python-dotenv`로 분리하고, `.gitignore`에 등록하여 소스 컨트롤에 노출되지 않도록 해야 합니다.
- **인증/인가(Auth) 부재:** FastAPI 엔드포인트와 대시보드에 접근하기 위한 인증 체계(JWT, API Token 등)가 없습니다. 최소한의 API Key 검증이 필요합니다.

---

## 3. 코드 품질 및 성능 (Code Quality & Performance)

### 백엔드 (`server.py`, `database.py`)
- **Pydantic 모델 활용:** `LogItem`, `LogBatch`를 통한 타입 안정성이 우수합니다.
- **ORM 직렬화:** `getattr` 기반 딕셔너리 변환은 잘 동작하나, Pydantic `response_model`로 더 간결하게 작성 가능합니다.

### 대시보드 (`user_dashboard.py`)
- **상태 관리:** `st.session_state`를 통한 로그/응답 결과/프로세스 목록 관리가 Streamlit 라이프사이클에 잘 부합합니다.
- **인코딩 이슈 해결:** 이전 버전에서 이모지 포함 `print()` 문이 Windows cp949에서 `UnicodeEncodeError`를 일으키던 문제가 `[OK]`, `[FAIL]`, `[WARN]` ASCII 텍스트로 교체되어 해결되었습니다.
- **Deprecated API 정리:** `use_container_width=True` → `width='stretch'`로 Streamlit 1.56 호환 처리 완료.

### 수집기 (`sysmon_collector.py`, `fileless_detector.py`)
- `collect_fileless()` 함수가 추가되어 PowerShell 이벤트 로그(Event ID 4104)를 수집하고 Sysmon 표준 포맷으로 변환합니다.
- MITRE ATT&CK 매핑(TA0005, T1140 등)이 Fileless 위협에도 적용됩니다.
- 👉 **권고:** 로그 중복 수집 방지를 위한 마지막 수집 위치(Bookmark) 저장 로직 부재는 여전히 개선이 필요합니다.

### XGBoost 모듈 (`train.py`, `threat_predictor.py`)
- **Data Leakage 해결 (2026-06-29):** `source_dataset`, `source_file`, `process_guid`, `parent_process_guid`, `process_group_no`, `process_event_order` 등 누출 컬럼을 제거하여 99.9% → 93.6%로 현실적인 성능을 달성했습니다.
- **희귀값 마스킹:** `process_name`, `command_line` 등에서 빈도 5 미만 희귀값을 `__RARE__`로 마스킹하여 특정 공격 도구 이름 암기 문제를 해결했습니다.
- **하이퍼파라미터 최적화:** n=1000 vs n=2000 비교 실험을 통해 `max_depth=3`, `n_estimators=2000`으로 최종 확정. Train-Val Gap 0.0009로 과적합 없음.

---

## 4. 확장성 및 유지보수성 (Scalability & Maintainability)

### 긍정적 측면 (Pros)
- `database.py` 스키마에 `ai_risk`, `ai_score` 필드가 선반영되어 ML 연동 준비가 완료된 상태입니다.
- XGBoost, Fileless 탐지, 프로세스 모니터링이 모두 독립 모듈로 분리되어 유지보수가 용이합니다.
- `compare_n_estimators.py` 등 실험 스크립트가 `xgboost/` 폴더에 보존되어 재현 가능한 실험 환경이 갖춰졌습니다.

### 개선 권고사항 (Cons & Recommendations)
- **로깅 시스템:** `print()` 위주 구조 → `logging` 모듈 도입으로 파일 기록 체계 전환 권장.
- **테스트 코드:** `pytest` 기반 단위 테스트 도입 권장.
- **`threat_predictor.py` 인코딩 통일:** 학습 시 `__RARE__` 마스킹 로직이 추론 시에도 동일하게 적용되는지 주기적으로 검증 필요.

---

## 5. 아쉬운 점 및 구체적인 수정 필요 사항 (Shortcomings & Fixes)

### 5.1 아쉬운 점 (Shortcomings)
1. **로그 수집 중복 문제 (`sysmon_collector.py`)**
   - 버튼을 여러 번 누르면 동일한 로그가 중복 저장됩니다. 마지막 수집 위치(Bookmark/RecordId) 기반 필터링 로직이 없습니다.
2. **광범위한 예외 처리 안티패턴 (`server.py`)**
   - `except Exception:`으로 모든 에러를 삼켜 원인 파악이 어렵습니다.
3. **VirusTotal 검사 중 UI 멈춤 (`user_dashboard.py`)**
   - `_wait_vt` 함수의 `time.sleep(10)` 반복으로 검사 중 UI가 얼어붙는 UX 저하가 발생합니다.
4. **XGBoost 추론 시 전처리 동기화 미검증**
   - `threat_predictor.py`에서 학습 시와 동일한 `__RARE__` 마스킹 및 컬럼 제거가 자동 적용되지 않을 수 있습니다.

### 5.2 수정해야 할 부분 (Required Fixes)
1. **중복 방지 로직 추가:** 마지막 수집 `RecordId`를 로컬 파일에 저장하고 이후 수집 시 해당 시점 이후만 가져오도록 수정.
2. **명확한 예외 처리 및 로깅:** `except ValueError:` 등 구체적 에러 클래스 지정 + `logging` 모듈 도입.
3. **비동기 또는 백그라운드 태스크:** VirusTotal 폴링 중 메인 스레드가 멈추지 않도록 구조 변경.
4. **추론 파이프라인 전처리 통일:** `threat_predictor.py`에 학습과 동일한 누출 컬럼 제거 + 희귀값 마스킹 로직 적용.

---

## 6. 총평 (Summary)
현재 EDR 프로토타입은 **Sysmon 수집 → XGBoost 위협도 판별 → Fileless 탐지 → 실시간 프로세스 모니터링 → 서버 전송 → 대시보드 모니터링 → VirusTotal 위협 인텔리전스**까지 핵심 요구사항을 체계적으로 구현하고 있습니다.

특히 **Data Leakage 탐지 및 수정**, **하이퍼파라미터 실험적 최적화(n=1000 vs n=2000)**, **Fileless 공격 탐지 모듈 추가**, **실시간 프로세스 모니터링** 등 지속적인 고도화가 이루어지고 있습니다.

향후 **① 비동기 처리 도입 ② 환경변수 기반 보안 강화 ③ 추론 파이프라인 전처리 통일** 3가지를 보완하면 실제 운영 환경 수준의 시스템으로 완성될 것입니다.