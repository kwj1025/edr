# XGBoost 위협도 판별 - 유저 대시보드 통합 가이드

## 📋 개요

XGBoost 기반의 위협도 판별 모듈을 기존 EDR 유저 대시보드에 통합하여, **Sysmon 로그 수집 시 자동으로 위협도를 판별**하고 대시보드에 표시합니다.

## 📁 통합 구조

```
EDR/
├── xgboost/
│   ├── threat_predictor.py          ← 새로 추가 (위협도 판별 모듈)
│   ├── xgboost_sysmon_model.json    (학습된 모델)
│   ├── label_encoders.pkl           (레이블 인코더)
│   └── INTEGRATION_GUIDE.md         (이 파일)
│
├── user_dashboard.py                ← 수정 (XGBoost 통합)
└── ...
```

## 🔄 통합 흐름

```
Sysmon 로그 수집
    ↓
사용자 정책 적용 (apply_jonghan_policy)
    ↓
XGBoost 위협도 판별 ← 새로 추가됨
    ├─ XGBoost_위협도: 0~100 (%)
    └─ XGBoost_라벨: Low | Medium | High | Critical
    ↓
대시보드 표시
    ├─ 최근 탐지 위협 테이블에 위협도 표시
    └─ 서버에 전송
```

## 🆕 추가된 파일

### `threat_predictor.py` - 위협도 판별 모듈

```python
from xgboost.threat_predictor import ThreatPredictor

# 모듈 초기화
predictor = ThreatPredictor()

# 모델 상태 확인
if predictor.is_ready():
    print("✓ 모델 준비 완료")

# 개별 로그 위협도 예측
log = {'process_id': 1234, 'image': 'notepad.exe', ...}
result = predictor.predict(log)
# {
#     'prediction': 1,           # 0=정상, 1=악성
#     'probability': 0.92,       # 악성 확률 (0~1)
#     'risk_label': 'Critical',  # Low | Medium | High | Critical
#     'success': True
# }

# 여러 로그 일괄 예측
results = predictor.predict_batch(log_list)
```

## 🔧 수정된 파일

### `user_dashboard.py` - 대시보드 통합

**1. XGBoost 모듈 임포트**
```python
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'xgboost'))
try:
    from threat_predictor import ThreatPredictor
    _THREAT_PREDICTOR = ThreatPredictor()
    _PREDICTOR_READY = _THREAT_PREDICTOR.is_ready()
except Exception as e:
    _PREDICTOR_READY = False
```

**2. 위협도 추가 함수**
```python
def add_xgboost_threat_score(rows: list[dict]) -> list[dict]:
    """각 로그에 XGBoost 위협도 판별 결과 추가"""
    for row in rows:
        result = _THREAT_PREDICTOR.predict(row)
        row['XGBoost_위협도'] = result['probability'] * 100
        row['XGBoost_라벨'] = result['risk_label']
    return rows
```

**3. 수집 및 전송 함수 수정**
```python
def collect_and_send(max_records: int = 500):
    rows = sysmon_collector.collect(max_records=max_records)
    rows = sysmon_collector.apply_jonghan_policy(rows)
    
    # XGBoost 위협도 추가 ← 새로 추가됨
    rows = add_xgboost_threat_score(rows)
    
    st.session_state.sysmon_logs = pd.DataFrame(rows)
    sent, err = send_to_server(rows)
    return len(rows), sent, err
```

**4. 대시보드 테이블 표시 수정**
```python
display_cols = [c for c in
    ["로그 수신 날짜", "위험도", 
     "XGBoost_위협도",  # ← 새로 추가
     "XGBoost_라벨",    # ← 새로 추가
     "탐지 유형", "Tactic ID", "Technique Name", 
     "프로세스", "행위 내용", "상태"]
    if c in st.session_state.sysmon_logs.columns]
```

## 📊 위협도 점수 계산

XGBoost 모델이 예측한 악성 확률(0~1)을 백분율(0~100%)로 변환하고, 4단계로 분류합니다:

| 범위 | 라벨 | 색상 | 의미 |
|------|------|------|------|
| 0-25% | **Low** | 🟢 | 정상에 가까운 행위 |
| 25-50% | **Medium** | 🟡 | 의심 수준의 행위 |
| 50-75% | **High** | 🔶 | 위험한 행위 |
| 75-100% | **Critical** | 🔴 | 매우 위험한 행위 |

## 🚀 사용 방법

### 1. 대시보드 실행
```bash
streamlit run user_dashboard.py
```

### 2. Sysmon 로그 수집
- 대시보드 우측 상단 **"🔍 Sysmon 로그 수집"** 버튼 클릭
- 자동으로 로그 수집 → XGBoost 판별 → 표시

### 3. 위협도 확인
- **"최근 탐지 위협"** 테이블에서 다음 컬럼 확인:
  - `XGBoost_위협도`: 위협도 점수 (0~100%)
  - `XGBoost_라벨`: 위협 수준 (Low/Medium/High/Critical)

## ✅ 주요 기능

### 1. 자동 위협도 판별
- 로그 수집 시 자동으로 XGBoost 모델 실행
- 각 Sysmon 로그에 위협도 점수 부여

### 2. 오류 처리
- 모델 로드 실패 시 `-1` 반환 및 `Unknown` 라벨
- 학습 시 보지 못한 카테고리 자동 처리 (Missing 값으로 대체)
- 결측치 자동 채우기

### 3. 배치 예측
- 여러 로그를 효율적으로 처리
- 수치 안정성 보장

### 4. 모니터링 피드백
```
✅ 1000건 수집 완료 → 서버 전송됨 (✓ XGBoost 판별 완료)
```

## ⚙️ 요구사항

### Python 패키지
```
xgboost>=1.5.0
scikit-learn>=1.0.0
pandas>=1.3.0
streamlit>=1.0.0
pywin32  (Windows 환경에서만)
```

### 필수 파일
- `xgboost_sysmon_model.json` - 학습된 모델
- `label_encoders.pkl` - 레이블 인코더

### 환경
- Windows OS (Sysmon 수집 기능)
- Python 3.8+

## 🔍 디버깅

### 모델 로드 확인
```python
from xgboost.threat_predictor import ThreatPredictor
predictor = ThreatPredictor()
print(f"모델 준비: {predictor.is_ready()}")
print(f"피처 개수: {len(predictor.feature_names)}")
```

### 단일 로그 테스트
```python
sample_log = {
    'process_id': 1234,
    'parent_process_id': 4,
    'image': 'C:\\Windows\\System32\\notepad.exe',
    'command_line': 'notepad.exe',
    'user': 'SYSTEM',
    'parent_image': 'C:\\Windows\\System32\\explorer.exe'
}
result = predictor.predict(sample_log)
print(result)
```

### 로그 파일 확인
- **대시보드 터미널**에서 다음 메시지 확인:
  - `✓ 모델 로드 성공` - 모델 정상 로드됨
  - `✓ 인코더 로드 성공` - 인코더 정상 로드됨
  - `⚠️ XGBoost 위협도 추가 오류` - 위협도 추가 실패

## 📈 성능 지표

학습 데이터 기준:
- **정확도(Accuracy)**: 99.94%
- **정밀도(Precision)**: 99.87%
- **재현율(Recall)**: 99.86%
- **F1-Score**: 99.86%

## 🛠️ 향후 개선 사항

1. **백엔드 통합**
   - `/api/threat-predict` 엔드포인트 추가
   - 모델 API 서버화

2. **모니터링 대시보드**
   - 위협도 분포 차트 추가
   - 시간별 위협도 트렌드 그래프

3. **모델 갱신**
   - 정기적인 재학습 파이프라인
   - A/B 테스트 프레임워크

4. **성능 최적화**
   - 배치 예측 처리 최적화
   - 캐싱 메커니즘 추가

## 📝 라이선스 및 기여

이 통합 가이드는 EDR 프로젝트의 일부입니다.

---

**작성일**: 2026-05-31  
**최종 수정일**: 2026-05-31  
**버전**: 1.0
