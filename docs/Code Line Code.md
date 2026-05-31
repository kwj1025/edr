# EDR 프로젝트 코드 상세 설명서 (1:1 라인별 해석)

본 문서는 프로젝트의 핵심 파일들에 대해 **코드 한 줄**과 **그에 대한 설명 한 줄**이 번갈아 나오는 형식으로 작성된 상세 분석 문서입니다. 핵심 비즈니스 로직 위주로 발췌하여 작성되었습니다.

---

## 1. `backend/database.py` (데이터베이스 연결 및 스키마)

```python
from sqlalchemy import create_engine
```
> SQLAlchemy 라이브러리에서 데이터베이스 연결 엔진을 생성하는 함수를 가져옵니다.

```python
from sqlalchemy.orm import declarative_base, sessionmaker
```
> ORM 모델의 뼈대가 되는 기본 클래스를 만드는 함수와 세션을 생성하는 함수를 가져옵니다.

```python
DATABASE_URL = "postgresql://edr_use:0000@localhost:5432/edr_db"
```
> 접속할 PostgreSQL 데이터베이스의 계정, 비밀번호, 주소, 포트, DB 이름 정보를 문자열로 정의합니다.

```python
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
```
> 설정한 URL로 DB 연결 엔진을 생성하며, 연결이 유효한지 미리 확인하는 옵션을 켭니다.

```python
SessionLocal = sessionmaker(bind=engine)
```
> 생성한 DB 엔진과 연결되어 쿼리를 실행할 세션 객체(팩토리)를 만듭니다.

```python
Base = declarative_base()
```
> 모든 데이터베이스 테이블 클래스가 상속받아야 할 기본(Base) 객체를 생성합니다.

```python
class SysmonLog(Base):
```
> Base를 상속받아 Sysmon 로그를 저장할 테이블 모델(클래스)을 선언합니다.

```python
    __tablename__ = "sysmon_logs"
```
> 데이터베이스에 실제로 만들어질 테이블의 이름을 "sysmon_logs"로 지정합니다.

```python
    id = Column(Integer, primary_key=True, autoincrement=True)
```
> id라는 컬럼을 만들고, 정수형 기본키(Primary Key)로 설정하여 값이 자동으로 1씩 증가하게 만듭니다.

```python
    recv_time = Column(DateTime, default=datetime.now)
```
> 로그를 수신한 시간을 기록할 컬럼을 만들고, 값이 안 들어오면 현재 시간을 기본값으로 넣습니다.

```python
def init_db():
```
> 데이터베이스를 초기화(생성)하는 함수를 선언합니다.

```python
    Base.metadata.create_all(engine)
```
> 정의된 모든 모델(테이블) 구조를 실제 데이터베이스 엔진에 생성합니다.

```python
def get_db():
```
> API 요청이 올 때마다 DB 세션을 제공하기 위한 함수를 선언합니다.

```python
    db = SessionLocal()
```
> 데이터베이스와 통신할 새로운 세션 객체를 하나 생성합니다.

```python
    yield db
```
> 생성된 세션 객체를 호출자(API 라우터)에게 넘겨주고, 함수를 잠시 멈춥니다.

```python
    db.close()
```
> API 처리가 모두 끝나면 넘겨줬던 세션을 강제로 닫아 자원을 반환합니다.

---

## 2. `backend/server.py` (FastAPI 서버 통신)

```python
app = FastAPI(title="EDR 수집 서버", lifespan=lifespan)
```
> FastAPI 웹 애플리케이션 객체를 생성하고, 이름과 수명주기(시작/종료 이벤트)를 설정합니다.

```python
class LogBatch(BaseModel):
```
> 클라이언트에서 전송하는 데이터를 검증하기 위해 Pydantic 기반의 모델 클래스를 선언합니다.

```python
    logs: List[LogItem]
```
> 수신될 데이터 형식이 `LogItem` 객체들이 담긴 리스트(배열) 형태여야 함을 정의합니다.

```python
@app.post("/logs")
```
> 클라이언트가 HTTP POST 방식으로 "/logs" 주소에 접근할 때 실행될 라우터를 정의합니다.

```python
def receive_logs(batch: LogBatch, db: Session = Depends(get_db)):
```
> 검증된 로그 데이터 묶음(batch)과 DB 세션 객체를 매개변수로 받는 함수를 선언합니다.

```python
    for item in batch.logs:
```
> 전송받은 로그 배열(logs) 안의 개별 로그(item)를 하나씩 꺼내어 반복문을 실행합니다.

```python
        log = SysmonLog(host_ip=item.host_ip, event_id=item.event_id)
```
> 전달받은 값을 바탕으로 데이터베이스에 들어갈 ORM 모델(SysmonLog) 객체를 생성합니다.

```python
        db.add(log)
```
> 생성된 DB 모델 객체를 현재 세션의 저장 대기열에 추가합니다.

```python
    db.commit()
```
> 대기열에 추가된 모든 데이터를 실제 데이터베이스에 영구적으로 저장(반영)합니다.

```python
@app.get("/logs")
```
> 클라이언트가 HTTP GET 방식으로 "/logs" 주소에 접근할 때 실행될 라우터를 정의합니다.

```python
    query = db.query(SysmonLog).order_by(SysmonLog.recv_time.desc())
```
> 데이터베이스에서 SysmonLog 데이터를 수신 시간(recv_time) 기준 내림차순(최신순)으로 가져오는 쿼리를 만듭니다.

```python
    rows = query.limit(limit).all()
```
> 생성된 쿼리를 실행하여 지정된 개수(limit)만큼의 데이터를 가져와 rows 변수에 담습니다.

---

## 3. `collector/sysmon_collector.py` (로그 수집기)

```python
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
```
> 수집할 Windows Sysmon 이벤트 로그가 위치한 시스템 채널 경로를 문자열로 지정합니다.

```python
TARGET_EVENT_IDS = {1, 3, 5, 22}
```
> 전체 이벤트 중 우리가 수집할 타겟 Event ID(프로세스, 네트워크 등) 4가지를 세트로 정의합니다.

```python
def collect(max_records: int = 500) -> list[dict]:
```
> 최대 수집할 레코드 수를 500개로 지정하여 로그를 수집하는 함수를 선언합니다.

```python
    ps_script = f"$events = Get-WinEvent -LogName '{SYSMON_CHANNEL}'"
```
> PowerShell 환경에서 해당 채널의 로그를 가져오는 명령어 문자열을 구성합니다.

```python
    proc = subprocess.run(["powershell", "-Command", ps_script], capture_output=True)
```
> 파이썬의 subprocess 모듈을 이용해 윈도우 PowerShell을 백그라운드에서 실행하고, 결과값을 캡처합니다.

```python
    raw = proc.stdout.strip()
```
> 실행 완료 후 화면(표준 출력)에 찍힌 결과물에서 불필요한 공백을 제거하고 변수에 담습니다.

```python
    events_json = json.loads(raw)
```
> 문자열 형태로 된 JSON 결과물을 파이썬에서 다룰 수 있는 객체(리스트/딕셔너리)로 변환합니다.

```python
    for ev in events_json:
```
> 가져온 전체 이벤트 목록에서 하나씩 꺼내어 반복문을 실행합니다.

```python
        mitre = _MITRE_MAP[event_id]
```
> 수집된 이벤트 ID를 바탕으로 미리 정의해 둔 MITRE ATT&CK 분류 정보 딕셔너리에서 값을 찾습니다.

```python
        rows.append({"위험도": risk, "행위 내용": msg})
```
> 분석이 끝난 위험도와 행위 내용 등을 하나의 딕셔너리로 묶어 최종 결과물(rows) 리스트에 추가합니다.

---

## 4. `xgboost/train.py` (AI 머신러닝 학습 모델)

```python
def load_data(filepath):
```
> 학습에 사용할 데이터셋 파일의 경로를 매개변수로 받아 로드하는 함수를 선언합니다.

```python
    df = pd.read_csv(filepath)
```
> Pandas 라이브러리를 이용하여 CSV 형식의 파일을 읽고 데이터프레임(표 형식)으로 만듭니다.

```python
def preprocess_data(df, target_col):
```
> 불러온 데이터프레임과 맞추고자 하는 정답(타겟) 컬럼명을 받아 데이터를 가공하는 함수를 선언합니다.

```python
    y_raw = df[target_col]
```
> 전체 데이터 중 모델이 맞춰야 할 정답(타겟) 컬럼만 잘라내어 별도의 변수에 저장합니다.

```python
    X_raw = df.drop(columns=[target_col])
```
> 전체 데이터 중 정답(타겟) 컬럼을 제외한 나머지 특성(Feature) 데이터들만 잘라내어 저장합니다.

```python
    le = LabelEncoder()
```
> 문자열 데이터를 컴퓨터가 이해할 수 있는 숫자로 변환해주기 위한 라벨 인코더 객체를 생성합니다.

```python
    X_raw[col] = le.fit_transform(X_raw[col])
```
> 컬럼의 문자열 종류를 학습함과 동시에 모두 0, 1, 2 등의 수치형 데이터로 변환하여 덮어씁니다.

```python
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
```
> 전체 데이터를 학습용 80%, 시험(테스트)용 20%의 비율로 무작위 분할합니다.

```python
    model = xgb.XGBClassifier(n_estimators=100, learning_rate=0.1)
```
> XGBoost 분류 모델을 나무(Tree) 개수 100개, 학습 속도 0.1의 옵션으로 초기화합니다.

```python
    model.fit(X_train, y_train)
```
> 분할해 둔 80%의 학습용 특성(X)과 정답(y) 데이터를 모델에 집어넣어 학습을 진행시킵니다.

```python
    model.save_model(args.save_model)
```
> 학습이 완벽하게 끝난 모델을 추후 사용하기 위해 지정된 파일 이름(json)으로 디스크에 저장합니다.

---

## 5. `dashboards/user_dashboard.py` & `admin_dashboard.py` (UI/UX)

```python
import streamlit as st
```
> 파이썬 코드로 웹 대시보드 UI를 그릴 수 있게 해주는 Streamlit 라이브러리를 불러옵니다.

```python
res = requests.post(f"{SERVER_URL}/logs", json={"logs": formatted})
```
> 수집된 로그 딕셔너리를 JSON 포맷으로 변환하여 FastAPI 백엔드 서버의 "/logs" 주소로 전송합니다.

```python
def analyze_file_vt(uploaded_file):
```
> 파일 업로드 위젯을 통해 들어온 파일을 매개변수로 받아 VirusTotal 검사를 수행하는 함수입니다.

```python
    h = hashlib.sha256(data).hexdigest()
```
> 업로드된 파일 데이터의 고유한 지문(SHA256 해시값)을 수학적으로 계산하여 추출합니다.

```python
    res = requests.get(f"https://www.virustotal.com/api/v3/files/{h}", headers=HEADERS)
```
> 추출한 해시값을 VirusTotal 외부 API 주소에 얹어서 전송하고, 해당 파일의 악성 여부 결과를 받아옵니다.

```python
if st.button("🔍 Sysmon 로그 수집"):
```
> 화면에 "Sysmon 로그 수집" 이라는 이름의 클릭 가능한 버튼 UI를 생성합니다.

```python
    with st.spinner("Sysmon 이벤트 수집 중…"):
```
> 버튼이 눌리면 내부 동작이 끝날 때까지 화면에 뱅글뱅글 도는 로딩 애니메이션을 띄워둡니다.

```python
chart = alt.Chart(risk_df).mark_arc().encode(theta="건수:Q", color="위험도:N")
```
> Altair 시각화 라이브러리를 이용해 건수를 크기로, 위험도를 색상으로 하는 원형(파이/도넛) 차트 객체를 생성합니다.

```python
st.altair_chart(chart, use_container_width=True)
```
> 생성된 차트 객체를 Streamlit 화면상에 가로 너비에 꽉 차게(반응형으로) 렌더링(표시)합니다.