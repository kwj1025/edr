# XGBoost 학습 모델 개선 사항 (2026-05-23)

**작성일:** 2026-05-23 16:03:01

## 1. 개선 배경

기존 XGBoost 모델에서 과적합(Overfitting) 위험이 있었으므로, 이를 강하게 방지하고 더욱 견고한 모델을 구축하기 위해 `train.py`를 완전히 재작성하였습니다.

## 2. 과적합 방지 개선사항

### 2.1 하이퍼파라미터 최적화

| 파라미터 | 이전 값 | 개선된 값 | 설명 |
|---------|--------|---------|------|
| learning_rate | 0.05 | **0.01** | 학습률을 5배 낮춰 천천히 학습 (안정성↑) |
| n_estimators | 1000 | **2000** | 많은 반복을 통해 early_stopping에서 최적 시점 찾음 |
| max_depth | 5 | **3** | 트리 깊이를 제한하여 모델 단순화 |
| min_child_weight | - | **5** | 리프 노드의 최소 인스턴스 수 설정 |
| reg_alpha | 1.0 | **2.0** | L1 정규화 2배 강화 |
| reg_lambda | 1.0 | **2.0** | L2 정규화 2배 강화 |
| subsample | 0.8 | **0.7** | 각 트리마다 70%의 샘플만 사용 |
| colsample_bytree | 0.8 | **0.7** | 각 트리마다 70%의 피처만 사용 |
| colsample_bylevel | - | **0.7** | 각 분할 레벨마다 70%의 피처 사용 |
| gamma | - | **1.0** | 분할에 필요한 최소 손실 감소량 설정 |
| early_stopping_rounds | 50 | **100** | 검증 성능 개선이 100번 연속 없으면 중단 |

### 2.2 모델 안정성 강화

| 개선 항목 | 내용 |
|---------|------|
| **5-Fold Cross-Validation** | 전체 데이터를 5번 검증하여 모델 일반화 성능 측정 |
| **Stratified Split** | 클래스 불균형 보정하여 안정적인 분할 |
| **Train/Val/Test 3분할** | Train (60%), Validation (20%), Test (20%) |
| **상세 성능 평가** | Accuracy, Precision, Recall, F1-Score 각각 측정 |
| **과적합 갭 분석** | Train - Validation 정확도 차이로 과적합 정도 감지 |

## 3. 코드 구조 개선

### 3.1 추가된 함수

```python
def train_xgboost_with_validation(X_train, y_train, X_val, y_val):
    # 검증 세트를 이용한 얼리 스탑으로 과적합 방지
    
def evaluate_model(model, X_train, y_train, X_val, y_val, X_test, y_test, target_encoder=None):
    # Train/Val/Test 각 세트에서 상세 성능 평가
    
def cross_validate_model(X, y):
    # 5-Fold Cross-Validation으로 모델 안정성 검증
```

### 3.2 상세한 성능 지표

- **Train 세트**: 모델이 학습한 데이터에 대한 성능
- **Validation 세트**: 학습 중 검증에 사용한 데이터 성능
- **Test 세트**: 학습에 전혀 사용하지 않은 독립적 테스트 데이터 성능

### 3.3 과적합 판정 기준

```
Train - Val Gap (정확도 차이):
  - 0.0 ~ 0.1  : ✅ 과적합 없음 (정상)
  - 0.1 ~ 0.2  : ⚠️  약간의 과적합 신호
  - 0.2 이상   : ⚠️  과적합 신호 (추가 정규화 필요)
```

## 4. 학습 프로세스 흐름

```
1. 데이터 로드 (정상 + 악성)
   ↓
2. 데이터 전처리 (인코딩, 결측치 처리)
   ↓
3. 5-Fold Cross-Validation
   ↓
4. Train/Val/Test 분할
   ↓
5. XGBoost 학습 (검증 세트로 Early Stopping)
   ↓
6. 성능 평가 (3개 세트 각각)
   ↓
7. 모델 저장 (JSON + 인코더 PKL)
```

## 5. 실행 방법

```bash
cd xgboost
python train.py
```

## 6. 기대효과

- **과적합 방지**: 여러 정규화 기법으로 모델 일반화 성능 ↑
- **모델 안정성**: Cross-Validation으로 다양한 데이터셋에서 일관된 성능 확보
- **신뢰할 수 있는 평가**: Train/Val/Test 분리로 정확한 성능 측정
- **자동 최적화**: Early Stopping으로 최적 시점에서 학습 중단

## 7. 파일 목록

- `train.py` - 개선된 학습 스크립트 (2026-05-23 재작성)
- `xgboost_sysmon_model.json` - 저장된 모델
- `label_encoders.pkl` - 저장된 인코더
