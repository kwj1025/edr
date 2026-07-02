# EDR 프로젝트 코드 상세 설명서 (1:1 라인별 해석)

본 문서는 프로젝트의 핵심 파일들에 대해 **코드 한 줄**과 **그에 대한 설명 한 줄**이 번갈아 나오는 형식으로 작성된 상세 분석 문서입니다. 핵심 비즈니스 로직 위주로 발췌하여 작성되었습니다.

최초 작성일: 2026-05-22  
**최종 업데이트: 2026-06-29**

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

## 3. `collector/sysmon_collector.py` (Sysmon 로그 수집기)

```python
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
```
> 수집할 Windows Sysmon 이벤트 로그가 위치한 시스템 채널 경로를 문자열로 지정합니다.

```python
TARGET_EVENT_IDS = {1, 3, 5, 22}
```
> 전체 이벤트 중 수집할 타겟 Event ID(프로세스 생성/네트워크/종료/DNS) 4가지를 세트로 정의합니다.

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
    events_json = json.loads(raw)
```
> 문자열 형태로 된 JSON 결과물을 파이썬에서 다룰 수 있는 객체(리스트/딕셔너리)로 변환합니다.

```python
    mitre = _MITRE_MAP[event_id]
```
> 수집된 이벤트 ID를 바탕으로 미리 정의해 둔 MITRE ATT&CK 분류 정보 딕셔너리에서 값을 찾습니다.

```python
def collect_fileless(max_records: int = 100) -> list[dict]:
```
> Fileless 공격 탐지를 위해 PowerShell 이벤트(Event ID 4104)를 수집하는 함수를 선언합니다. (2026-06-29 추가)

```python
    rows.append({"위험도": risk, "행위 내용": msg})
```
> 분석이 끝난 위험도와 행위 내용 등을 하나의 딕셔너리로 묶어 최종 결과물(rows) 리스트에 추가합니다.

---

## 4. `collector/fileless_detector.py` (Fileless 공격 탐지기) ← 신규 추가 (2026-06-29)

```python
_SUSPICIOUS_KEYWORDS = ["DownloadString", "IEX", "New-Object", "WScript.Shell", ...]
```
> PowerShell 스크립트에서 Fileless 공격 징후를 나타내는 23개의 의심 키워드 목록을 정의합니다.

```python
def detect_fileless(script_block: str) -> dict:
```
> PowerShell 스크립트 블록 문자열을 받아 의심 패턴을 분석하고 위협도 점수를 반환하는 함수를 선언합니다.

```python
    score += sum(1 for kw in _SUSPICIOUS_KEYWORDS if kw.lower() in script_block.lower())
```
> 스크립트 블록 내에 의심 키워드가 몇 개 포함되어 있는지 계산하여 위협 점수에 누적합니다.

```python
    if re.search(r'[A-Za-z0-9+/]{40,}={0,2}', script_block):
```
> 정규표현식을 사용하여 40자 이상의 Base64 인코딩 패턴(난독화)이 존재하는지 검사합니다.

```python
    decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
```
> 발견된 Base64 문자열을 디코딩하여 실제 숨겨진 명령어 내용을 복원합니다.

```python
    return {"score": score, "is_suspicious": score >= 2, "mitre": mitre_mapping}
```
> 최종 점수, 의심 여부(임계값 2 이상), MITRE ATT&CK 매핑 정보를 딕셔너리로 반환합니다.

---

## 5. `xgboost/train.py` (AI 머신러닝 학습 모델)

```python
cols_to_drop = ['record_id', 'time_created', 'source_dataset', 'source_file',
                'process_group_no', 'process_event_order',
                'process_guid', 'parent_process_guid']
```
> Data Leakage(데이터 누출)를 일으키는 컬럼들을 명시적으로 제거합니다. source_dataset은 레이블과 1:1 대응되고, process_guid는 실행마다 달라지는 UUID라 일반화가 불가능합니다. (2026-06-29 수정)

```python
rare_mask_cols = ['process_name', 'command_line', 'parent_process']
```
> 특정 공격 도구 이름을 암기하는 문제를 방지하기 위해 희귀값 마스킹을 적용할 컬럼 목록을 정의합니다.

```python
X[col] = X[col].astype(str).apply(lambda v: '__RARE__' if v in rare_vals else v)
```
> 빈도 5 미만의 희귀한 값(예: 특정 공격 도구 경로)을 '__RARE__' 토큰으로 치환하여 일반화합니다.

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
    X_raw[col] = le.fit_transform(X_raw[col])
```
> 문자열 데이터를 컴퓨터가 이해할 수 있는 숫자로 변환해주기 위한 라벨 인코더 객체를 생성하고 변환합니다.

```python
model = xgb.XGBClassifier(
    learning_rate=0.01,
    n_estimators=2000,
    max_depth=3,
    ...
)
```
> 최종 확정 하이퍼파라미터로 XGBoost 분류 모델을 초기화합니다. n=1000 vs n=2000 비교 실험 후 n=2000 채택. (2026-06-29 확정)

```python
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_scores = cross_val_score(model, X, y, cv=skf, scoring='accuracy')
```
> 계층적 5-Fold 교차검증을 수행하여 모델의 일반화 성능을 측정합니다. 데이터 불균형이 있어도 각 fold에 클래스 비율이 유지됩니다.

```python
model.save_model('xgboost_sysmon_model.json')
joblib.dump(encoders, 'label_encoders.pkl')
```
> 학습이 완벽하게 끝난 모델과 인코더를 추후 추론(inference)에 사용하기 위해 파일로 저장합니다.

---

## 6. `xgboost/threat_predictor.py` (실시간 위협도 판별 모듈)

```python
class ThreatPredictor:
```
> 학습된 XGBoost 모델을 로드하여 실시간으로 Sysmon 로그의 위협도를 판별하는 클래스를 선언합니다.

```python
    self.model = xgb.Booster()
    self.model.load_model(self.model_path)
```
> XGBoost 네이티브 Booster 객체를 생성하고, 저장된 모델 파일(.json)을 불러옵니다.

```python
    known_classes = set(encoder.classes_)
    df[col] = df[col].apply(lambda x: x if x in known_classes else 'Missing')
```
> 학습 시 보지 못한 새로운 카테고리 값이 들어오면 'Missing'으로 처리하여 LabelEncoder 에러를 방지합니다.

```python
    proba = self.model.predict(dmatrix)[0]
```
> 전처리된 로그 데이터를 XGBoost DMatrix 형식으로 변환 후 악성일 확률(0~1)을 예측합니다.

```python
    if proba < 0.25:   risk_label = 'Low'
    elif proba < 0.50: risk_label = 'Medium'
    elif proba < 0.75: risk_label = 'High'
    else:              risk_label = 'Critical'
```
> 예측 확률을 4단계(Low/Medium/High/Critical)로 분류하여 사람이 읽기 쉬운 위험도 레이블로 변환합니다.

---

## 7. `user_dashboard.py` (사용자 대시보드)

```python
import psutil
import datetime
```
> 실시간 프로세스 모니터링을 위해 psutil과 datetime 라이브러리를 추가로 불러옵니다. (2026-06-29 추가)

```python
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'xgboost'))
from threat_predictor import ThreatPredictor
_THREAT_PREDICTOR = ThreatPredictor()
```
> XGBoost 위협도 판별 모듈 경로를 시스템 경로에 추가하고, ThreatPredictor 객체를 전역으로 초기화합니다.

```python
from sysmon_collector import collect, apply_jonghan_policy, collect_fileless
```
> Sysmon 수집 함수, 정책 적용 함수, Fileless 탐지 함수를 수집기 모듈에서 가져옵니다.

```python
def collect_fileless_threats() -> tuple[int, int, str]:
```
> Fileless 위협을 탐지하고 XGBoost 판별 후 서버로 전송하는 함수를 선언합니다. (2026-06-29 추가)

```python
if st.button("🛡️ Fileless 공격 탐지 (PowerShell)", width="stretch"):
```
> 화면에 Fileless 공격 탐지 버튼 UI를 생성합니다. Event ID 4104 기반 탐지를 실행합니다.

```python
def get_process_list() -> pd.DataFrame:
    for proc in psutil.process_iter(['pid', 'name', 'status', 'cpu_percent', ...]):
```
> psutil을 통해 현재 실행 중인 모든 프로세스를 순회하며 정보를 수집하는 함수를 선언합니다. (2026-06-29 추가)

```python
is_suspicious = any(kw in name_lower for kw in _SUSPICIOUS_KEYWORDS)
```
> 프로세스 이름을 20개의 의심 키워드 목록과 대조하여 의심 여부를 불리언으로 판별합니다.

```python
st.column_config.ProgressColumn("CPU%", min_value=0, max_value=100, format="%.1f%%")
```
> CPU 사용률 컬럼을 숫자 대신 시각적 진행 바(Progress Bar)로 렌더링합니다.

```python
res = requests.post(f"{SERVER_URL}/logs", json={"logs": formatted})
```
> 수집된 로그 딕셔너리를 JSON 포맷으로 변환하여 FastAPI 백엔드 서버의 "/logs" 주소로 전송합니다.

```python
h = hashlib.sha256(data).hexdigest()
```
> 업로드된 파일 데이터의 고유한 지문(SHA256 해시값)을 수학적으로 계산하여 추출합니다.