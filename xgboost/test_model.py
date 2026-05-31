import pandas as pd
import xgboost as xgb
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix
import joblib
import os
import warnings
import numpy as np
from datetime import datetime

warnings.filterwarnings('ignore')

def load_test_data(test_normal_path, test_malicious_path):
    print("테스트용 정상 및 악성 데이터를 로드합니다...")

    df_normal = pd.DataFrame()
    df_malicious = pd.DataFrame()

    if os.path.exists(test_normal_path):
        print(f"[{test_normal_path}] 로드 중...")
        df_normal = pd.read_json(test_normal_path)
        print(f"테스트 정상 데이터 크기: {df_normal.shape}")
    else:
        print(f"[오류] 테스트 정상 데이터 파일이 없습니다: {test_normal_path}")

    if os.path.exists(test_malicious_path):
        print(f"[{test_malicious_path}] 로드 중...")
        df_malicious = pd.read_json(test_malicious_path)
        print(f"테스트 악성 데이터 크기: {df_malicious.shape}")
    else:
        print(f"[오류] 테스트 악성 데이터 파일이 없습니다: {test_malicious_path}")

    df_combined = pd.concat([df_normal, df_malicious], ignore_index=True)
    print(f"[완료] 테스트 데이터 병합 (총 크기: {df_combined.shape})\n")
    return df_combined


def preprocess_test_data(df, encoders, target_col):
    print("테스트 데이터 전처리를 수행합니다...")

    if df.empty:
        return pd.DataFrame(), pd.Series()

    if target_col not in df.columns:
        print(f"[오류] 타겟 컬럼 '{target_col}'이 테스트 데이터에 없습니다!")
        return pd.DataFrame(), pd.Series()

    y_raw = df[target_col]
    X_raw = df.drop(columns=[target_col])

    cols_to_drop = ['record_id', 'time_created']
    for col in cols_to_drop:
        if col in X_raw.columns:
            X_raw = X_raw.drop(columns=[col])

    for col in X_raw.columns:
        if not pd.api.types.is_numeric_dtype(X_raw[col]):
            X_raw[col] = X_raw[col].astype(str).fillna('Missing')
            if col in encoders:
                le = encoders[col]
                X_raw[col] = X_raw[col].map(lambda x: le.transform([x])[0] if x in le.classes_ else 0)
            else:
                X_raw[col] = 0
            X_raw[col] = X_raw[col].astype(int)
        else:
            X_raw[col] = X_raw[col].fillna(0)

    target_encoder = encoders.get('__TARGET__')
    if target_encoder:
        y_raw = y_raw.astype(str).fillna('Missing')
        y = pd.Series(target_encoder.transform(y_raw), name=target_col)
    else:
        y = y_raw.fillna(0).astype(int)

    print("[완료] 테스트 데이터 전처리 완료!\n")
    return X_raw, y


def test_model(model, X_test, y_test, target_encoder=None):
    print("\n" + "="*70)
    print("[결과] 테스트 데이터셋 평가 결과")
    print("="*70 + "\n")

    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
    recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)
    f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)

    print(f"[전체 성능 지표]")
    print(f"  정확도(Accuracy):  {accuracy:.4f}")
    print(f"  정밀도(Precision): {precision:.4f}")
    print(f"  재현율(Recall):    {recall:.4f}")
    print(f"  F1-스코어:         {f1:.4f}")

    print(f"\n[상세 분류 리포트]")
    target_names = None
    if target_encoder:
        target_names = [str(c) for c in target_encoder.classes_]
    else:
        target_names = ['정상 (0)', '악성 (1)']
    print(classification_report(y_test, y_pred, target_names=target_names))

    print(f"[혼동 행렬]")
    cm = confusion_matrix(y_test, y_pred)
    print(cm)
    print()

    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'confusion_matrix': cm,
        'predictions': y_pred,
        'probabilities': y_pred_proba
    }


def save_test_results(results, test_log_path):
    print(f"테스트 결과를 저장합니다: {test_log_path}")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    markdown_content = f"""# XGBoost 모델 테스트 결과 로그

**테스트 실행 시간:** {timestamp}

## 1. 테스트 개요

학습된 XGBoost 모델을 테스트 데이터(정상 + 악성)로 평가했습니다.

## 2. 테스트 데이터 정보

- 정상 테스트 데이터: `../Dataset/test/test_normal.json`
- 악성 테스트 데이터: `../Dataset/test/test_malicious.json`

## 3. 성능 평가 결과

### 3.1 전체 성능 지표

| 지표 | 값 |
|-----|-----|
| Accuracy | {results['accuracy']:.4f} |
| Precision | {results['precision']:.4f} |
| Recall | {results['recall']:.4f} |
| F1-Score | {results['f1']:.4f} |

### 3.2 결과 해석

- **Accuracy**: 전체 테스트 샘플 중 올바르게 분류된 비율
- **Precision**: 악성으로 예측한 것 중 실제 악성의 비율
- **Recall**: 실제 악성 샘플 중 올바르게 탐지된 비율
- **F1-Score**: Precision과 Recall의 조화 평균

### 3.3 혼동 행렬 (Confusion Matrix)

```
{results['confusion_matrix']}
```

## 4. 결론

모델은 테스트 데이터에서 **{results['accuracy']:.2%}**의 정확도를 보였습니다.

## 5. 다음 단계

- 성능이 만족스럽지 않은 경우: 하이퍼파라미터 튜닝 권장
- 성능이 충분한 경우: 모델 배포 및 실시간 추론 단계 진행

---

**생성일**: {timestamp}
"""

    with open(test_log_path, 'w', encoding='utf-8') as f:
        f.write(markdown_content)

    print("[완료] 테스트 결과 파일이 저장되었습니다!\n")


def main():
    model_path = 'xgboost_sysmon_model.json'
    encoder_path = 'label_encoders.pkl'
    base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    test_normal_path = os.path.join(base_path, 'Dataset', 'test', 'test_normal.json')
    test_malicious_path = os.path.join(base_path, 'Dataset', 'test', 'test_malicious.json')
    target_column = 'label'
    test_log_path = 'test_results.md'

    print("="*70)
    print("[설정] 학습된 XGBoost 모델을 로드합니다...")
    print("="*70 + "\n")

    if not os.path.exists(model_path):
        print(f"[오류] 모델 파일이 없습니다: {model_path}")
        print("먼저 train.py로 모델을 학습시켜 주세요.")
        return

    model = xgb.XGBClassifier()
    model.load_model(model_path)
    print(f"[완료] 모델 로드 완료: {model_path}\n")

    if not os.path.exists(encoder_path):
        print(f"[오류] 인코더 파일이 없습니다: {encoder_path}")
        return

    encoders = joblib.load(encoder_path)
    print(f"[완료] 인코더 로드 완료: {encoder_path}\n")

    df_test = load_test_data(test_normal_path, test_malicious_path)
    if df_test.empty:
        print("[오류] 테스트 데이터를 로드할 수 없습니다.")
        return

    X_test, y_test = preprocess_test_data(df_test, encoders, target_column)
    if X_test.empty or y_test.empty:
        print("[오류] 테스트 데이터를 전처리할 수 없습니다.")
        return

    print(f"[완료] 테스트 데이터 준비 완료: {X_test.shape[0]} 건\n")

    target_encoder = encoders.get('__TARGET__')
    results = test_model(model, X_test, y_test, target_encoder)

    save_test_results(results, test_log_path)

    print("="*70)
    print("[완료] 테스트 종료!")
    print("="*70)

if __name__ == "__main__":
    main()