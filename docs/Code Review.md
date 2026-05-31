# EDR 프로젝트 전체 코드 리뷰 보고서

본 문서는 EDR(Endpoint Detection and Response) 시스템 프로젝트의 전체 소스 코드를 아키텍처, 성능, 보안, 유지보수성 등 다각도에서 분석한 코드 리뷰 보고서입니다. 본 리뷰는 기존 소스 코드를 수정하지 않고 정적 분석(Static Analysis)을 통해 도출된 장점과 개선 권고사항을 정리한 것입니다.

작성일: 2026-05-22

---

## 1. 아키텍처 및 시스템 구조 (Architecture)

### 긍정적 측면 (Pros)
- **모듈화 및 역할 분리:** 백엔드(FastAPI), 데이터베이스(SQLAlchemy), 프론트엔드 대시보드(Streamlit), 수집기(Sysmon Collector), 머신러닝 모듈(XGBoost)이 각각 독립적인 파일 및 폴더 구조로 분리되어 있어 유지보수성과 확장성이 우수합니다.
- **RESTful API 설계:** FastAPI를 활용한 `/logs` 엔드포인트(GET, POST, DELETE) 설계가 매우 직관적이고 표준을 잘 따르고 있습니다.
- **가벼운 프론트엔드 구성:** Streamlit을 사용하여 사용자/관리자용 대시보드를 분리 구현함으로써, 복잡한 프론트엔드 프레임워크(React, Vue 등) 없이도 데이터 분석 및 시각화에 집중할 수 있도록 구성된 점이 인상적입니다.

### 개선 권고사항 (Cons & Recommendations)
- **비동기 처리(Async) 부재:** FastAPI는 기본적으로 비동기 처리(ASGI)에 강점이 있으나, 현재 `server.py`의 엔드포인트(`def receive_logs`)와 SQLAlchemy 모델은 동기(Sync) 방식으로 구현되어 있습니다. 대량의 로그 트래픽이 동시다발적으로 발생할 경우 병목 현상이 발생할 수 있습니다. 
  👉 **권고:** 향후 `async/await` 지원 데이터베이스 드라이버(`asyncpg` 등)와 `AsyncSession`을 도입하여 처리량을 늘리는 것을 권장합니다.

---

## 2. 보안 (Security)

### 긍정적 측면 (Pros)
- 위협 정보 조회를 위해 외부 API(VirusTotal)를 효과적으로 통합하여 파일 해시 및 URL 검사를 수행하는 점이 EDR 목적에 잘 부합합니다.

### 개선 권고사항 (Cons & Recommendations)
- **하드코딩된 인증 정보:** 
  - `backend/database.py` 파일 내에 `DATABASE_URL = "postgresql://edr_use:0000@localhost:5432/edr_db"`와 같이 데이터베이스 계정 정보가 평문으로 하드코딩되어 있습니다.
  - `dashboards/user_dashboard.py` 파일 내에 `API_KEY = "여기에_본인_VirusTotal_API_KEY_입력"`이 평문으로 관리되고 있습니다.
  👉 **권고:** `.env` 파일과 `python-dotenv` 또는 `os.environ`을 활용하여 중요 자격 증명(Credential)을 분리하고, GitHub 등 소스 컨트롤에 노출되지 않도록 해야 합니다.
- **인증/인가(Auth) 부재:** 현재 FastAPI `/logs` 엔드포인트와 관리자 대시보드에 접근하기 위한 인증(JWT, API Token 등) 체계가 없습니다. 내부 네트워크용이라 할지라도 최소한의 API Key 검증이 필요합니다.

---

## 3. 코드 품질 및 성능 (Code Quality & Performance)

### 백엔드 (`server.py`, `database.py`)
- **Pydantic 모델 활용:** 데이터 검증을 위해 Pydantic(`LogItem`, `LogBatch`)을 도입한 것은 타입 안정성 측면에서 훌륭한 선택입니다.
- **ORM 객체 변환:** `get_logs`에서 `getattr`을 이용해 ORM 객체를 딕셔너리로 변환하는 방식은 잘 동작하지만, Pydantic의 `response_model`을 활용하면 직렬화 코드를 더욱 간결하고 우아하게 작성할 수 있습니다.

### 대시보드 (`user_dashboard.py`, `admin_dashboard.py`)
- **상태 관리:** `st.session_state`를 활용하여 수집된 로그 상태를 관리하는 것은 Streamlit의 라이프사이클을 잘 이해하고 적용한 좋은 사례입니다.
- **Altair 시각화:** 복잡한 차트를 Altair를 사용해 반응형으로 매끄럽게 처리했습니다. 다만, 대량의 데이터(수만 건 이상)를 대시보드에서 렌더링할 경우 브라우저 렌더링 지연 및 메모리 문제가 발생할 수 있습니다.
  👉 **권고:** 서버 측에서 집계(Aggregation)를 수행한 결과를 받아와서 차트를 그리는 방식(Server-side rendering)으로 최적화하는 것을 고려해 보세요.

### 수집기 (`sysmon_collector.py`)
- **안정적인 쉘 호출:** 파이썬에서 `subprocess`를 통해 PowerShell `Get-WinEvent` 명령을 호출하고 결과를 JSON 형태로 추출하는 방식은 매우 영리하고 실용적인 접근법입니다. 
- **예외 처리:** 예외 발생 시 빈 리스트를 반환하여 프로그램이 크래시되지 않도록 처리한 점이 좋습니다.
- **개선 권고:** `subprocess.run` 이 호출될 때 `timeout=30`이 설정되어 있으나, 로그 양이 엄청나게 많을 경우 Timeout 에러가 날 수 있습니다. EventID 이외에 Time 범위 필터링(예: 최근 5분 등)을 PowerShell 쿼리에 추가하면 부하를 크게 줄일 수 있습니다.

---

## 4. 확장성 및 유지보수성 (Scalability & Maintainability)

### 긍정적 측면 (Pros)
- `database.py` 스키마에 `ai_risk`, `ai_score` 등 향후 머신러닝 연동을 위한 필드를 선제적으로 반영해 둔 점은 뛰어난 설계입니다.
- XGBoost 학습 환경이 독립적으로 구성되어 있어 시스템과 결합하기 용이합니다.

### 개선 권고사항 (Cons & Recommendations)
- **로깅 시스템:** `print()` 문 위주로 작성되어 있습니다. `logging` 모듈을 도입하여 INFO, WARNING, ERROR 로그를 파일로 기록하는 체계로 전환하면 향후 운영 단계에서 트러블슈팅에 큰 도움이 됩니다.
- **테스트 코드:** 현재 `tests` 폴더에 간단한 스크립트만 존재합니다. `pytest` 프레임워크를 도입하여 API의 응답 결과나 전처리기의 동작을 검증하는 단위 테스트(Unit Test)를 작성할 것을 권장합니다.

---

## 5. 아쉬운 점 및 구체적인 수정 필요 사항 (Shortcomings & Fixes)

실제 코드를 바탕으로 보았을 때, 당장 보완이 필요한 부분들을 '아쉬운 점'과 '수정해야 할 부분'으로 나누어 정리했습니다.

### 5.1 아쉬운 점 (Shortcomings)
1. **로그 수집 중복 문제 (`sysmon_collector.py`)**
   - 현재 `collect()` 함수는 `Get-WinEvent`를 호출하여 최신 로그를 가져오지만, 이전에 읽었던 위치(Bookmark)를 기억하는 상태 관리 로직이 없습니다. 대시보드에서 수집 버튼을 여러 번 누르면 동일한 로그가 계속 중복되어 서버(DB)에 저장되는 점이 아쉽습니다.
2. **광범위한 예외 처리 안티패턴 (`server.py`)**
   - `_parse_dt(dt_str)` 함수 등에서 `except Exception:`을 사용하여 모든 에러를 뭉뚱그려 무시(`return None`)하고 있습니다. 이렇게 예외를 삼켜버리면 추후 날짜 파싱 등에서 어떤 원인으로 문제가 발생했는지 파악하기 매우 어렵습니다.
3. **동기식 블로킹 코드로 인한 UI 멈춤 (`user_dashboard.py`)**
   - VirusTotal API 검사 결과를 기다리는 `_wait_vt` 함수 안에서 `time.sleep(10)`을 반복해서 사용하고 있습니다. 웹 프레임워크인 Streamlit 특성상 이 코드가 실행되는 100~120초 동안 UI가 완전히 얼어붙어 사용자가 다른 탭을 누르거나 조작할 수 없게 되는 사용자 경험(UX) 저하가 발생합니다.
4. **머신러닝 전처리기의 단순함 (`train.py`)**
   - 현재 범용성을 위해 결측치(NaN)가 나오면 단순히 0이나 'Missing' 텍스트로 채우고, 모든 문자열을 `LabelEncoder`로 단순 변환하고 있습니다. 랜덤 해시, 동적 프로세스명, 각기 다른 IP 주소가 들어왔을 때 단순히 숫자로 치환하는 것은 머신러닝 모델이 패턴을 학습하는 데 방해가 됩니다.

### 5.2 수정해야 할 부분 (Required Fixes)
1. **중복 방지 로직 추가**
   - 마지막으로 읽은 로그의 시간(`TimeCreated`)이나 고유 ID(`RecordId`)를 로컬 파일에 저장해두고, 다음 수집 시 해당 시점 이후의 로그만 가져오도록 PowerShell 쿼리와 파이썬 로직을 수정해야 합니다.
2. **명확한 예외 처리 및 로깅 적용**
   - `except ValueError:` 등 구체적인 에러 클래스를 지정하여 잡도록 수정하고, 잘못된 형식의 데이터가 들어왔을 때는 묵음 처리하지 않고 `logging` 모듈을 이용해 경고 로그를 남기도록 수정해야 합니다.
3. **비동기 또는 백그라운드 태스크 도입**
   - Streamlit의 `st.empty()`와 캐싱(caching) 기능, 혹은 Python의 백그라운드 스레드 방식을 도입하여 API 응답을 대기하는 동안에도 메인 UI 스레드가 멈추지 않고 비동기적으로 폴링(Polling)하도록 구조를 변경해야 합니다.
4. **특성 공학(Feature Engineering) 고도화**
   - IP 주소는 내부망/외부망, Known Port 등의 파생 변수로 쪼개고, 시간 데이터는 '시간대(새벽/오전 등)'로 변환하는 등 의미 있는 숫자로 특성 공학(Feature Engineering) 처리를 수행하는 전처리 로직을 반드시 구현해야 합니다.

---

## 6. 총평 (Summary)
현재 EDR 프로토타입 시스템은 **Windows 이벤트 로그 수집 ➡️ 서버 전송 및 DB 적재 ➡️ 대시보드 모니터링 ➡️ 위협 인텔리전스(VT) 연동**이라는 핵심 요구사항을 매우 깔끔하게 구현하고 있습니다. 

특히 파이썬의 풍부한 생태계(FastAPI, SQLAlchemy, Streamlit, Pandas, XGBoost)를 적재적소에 활용하여 빠르고 완성도 높은 시스템을 구축했습니다. 향후 실제 서비스(운영 환경)로 넘어가기 전, **1) 비동기 처리 도입 2) 중요 키값 환경변수 분리(보안) 3) 머신러닝 모델의 실시간 파이프라인 연동** 3가지 사항만 보완한다면 상용 수준의 시스템으로 거듭날 수 있을 것으로 기대됩니다.