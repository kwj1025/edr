# XGBoost Model Training Report

## 1. 개요
XGBoost 모델을 사용하여 정상 시스템 로그와 악성 시스템 로그 데이터셋에 대한 학습을 성공적으로 완료했습니다. 최신 `train.py` 실행 결과, 과적합을 방지하고 매우 높은 수준의 정확도를 달성했습니다.

## 2. 데이터셋 정보
- **정상 로그:** `C:\EDR\Dataset\train\train_normal.json` (17,266건)
- **악성 로그:** `C:\EDR\Dataset\train\train_malicious.json` (21,259건)
- **총 데이터 크기:** 38,525건
- **데이터 분할:**
  - Train: 23,115건 (60.0%)
  - Validation: 7,705건 (20.0%)
  - Test: 7,705건 (20.0%)

## 3. 학습 결과 및 성능 지표
5-Fold 교차 검증(Cross-Validation)을 통해 모델의 안정성을 확인하였고, 각 데이터 분할에서의 성능을 평가했습니다.

### 5-Fold Cross-Validation (교차 검증)
- **CV Scores:** `[0.9983, 0.9977, 0.9988, 0.9982, 0.9992]`
- **Mean CV Accuracy:** **0.9984** (± 0.0005)

### Train / Validation / Test 지표 비교
과적합 검증을 위해 Train, Validation, Test 셋 모두에서 지표를 측정하였습니다. 결과적으로 모델에 과적합(Overfitting) 없이 일관된 성능을 보였습니다.

| 지표 | Train Set | Validation Set | Test Set |
| --- | --- | --- | --- |
| **Accuracy (정확도)** | 0.9993 | 0.9996 | 0.9994 |
| **Precision (정밀도)** | 0.9993 | 0.9996 | 0.9994 |
| **Recall (재현율)** | 0.9993 | 0.9996 | 0.9994 |
| **F1-Score (F1-점수)**| 0.9993 | 0.9996 | 0.9994 |

### Test Data 분류 리포트 (Classification Report)
```text
              precision    recall  f1-score   support

    정상 (0)       1.00      1.00      1.00      3453
    악성 (1)       1.00      1.00      1.00      4252

    accuracy                           1.00      7705
   macro avg       1.00      1.00      1.00      7705
weighted avg       1.00      1.00      1.00      7705
```

## 4. 저장 파일
- **학습 모델:** `xgboost_sysmon_model.json`
- **라벨 인코더:** `label_encoders.pkl`

모든 학습 과정이 문제 없이 성공적으로 완료되었습니다.
