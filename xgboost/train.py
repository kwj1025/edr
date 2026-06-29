import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import os
import joblib
import warnings
import numpy as np

warnings.filterwarnings('ignore')

def load_and_combine_data(normal_path, malicious_path):
    print("정상 데이터와 악성 데이터를 로드합니다...")

    df_normal = pd.DataFrame()
    df_malicious = pd.DataFrame()

    if os.path.exists(normal_path):
        print(f"[{normal_path}] 로드 중...")
        df_normal = pd.read_json(normal_path)
        print(f"정상 데이터 크기: {df_normal.shape}")
    else:
        print(f"[오류] 정상 데이터 파일이 없습니다: {normal_path}")

    if os.path.exists(malicious_path):
        print(f"[{malicious_path}] 로드 중...")
        df_malicious = pd.read_json(malicious_path)
        print(f"악성 데이터 크기: {df_malicious.shape}")
    else:
        print(f"[오류] 악성 데이터 파일이 없습니다: {malicious_path}")

    df_combined = pd.concat([df_normal, df_malicious], ignore_index=True)
    print(f"[완료] 데이터 병합 완료 (총 크기: {df_combined.shape})\n")

    return df_combined


def preprocess_data(df, target_col):
    print("데이터 전처리를 수행합니다...")

    if df.empty:
        return pd.DataFrame(), pd.Series(), {}

    if target_col not in df.columns:
        print(f"[오류] 타겟 컬럼 '{target_col}'이 데이터셋에 없습니다!")
        return pd.DataFrame(), pd.Series(), {}

    y_raw = df[target_col]
    X_raw = df.drop(columns=[target_col])

    encoders = {}

    # ================================================================
    # 누출(Leakage) 컬럼 제거
    # - source_dataset / source_file : 데이터 출처 → 레이블과 1:1 대응
    # - record_id / time_created     : 식별자 / 타임스탬프 → 추론 시 무의미
    # - process_group_no / process_event_order : 데이터셋 구성 순서
    # - process_guid / parent_process_guid : 실행마다 달라지는 UUID
    # ================================================================
    cols_to_drop = [
        'record_id', 'time_created',
        'source_dataset', 'source_file',
        'process_group_no', 'process_event_order',
        'process_guid', 'parent_process_guid',
    ]
    for col in cols_to_drop:
        if col in X_raw.columns:
            X_raw = X_raw.drop(columns=[col])

    # ================================================================
    # 희귀값 마스킹 (빈도 < 5 인 값 → '__RARE__')
    # process_name, command_line 은 특정 공격 도구 이름을 그대로 암기하는
    # 문제가 있으므로, 학습 데이터에서 드물게 등장하는 값은 일반화 처리
    # ================================================================
    rare_mask_cols = ['process_name', 'command_line', 'parent_process']
    for col in rare_mask_cols:
        if col in X_raw.columns:
            freq = X_raw[col].astype(str).value_counts()
            rare_vals = set(freq[freq < 5].index)
            X_raw[col] = X_raw[col].astype(str).apply(
                lambda v: '__RARE__' if v in rare_vals else v
            )

    for col in X_raw.columns:
        if not pd.api.types.is_numeric_dtype(X_raw[col]):
            X_raw[col] = X_raw[col].astype(str).fillna('Missing')
            le = LabelEncoder()
            X_raw[col] = le.fit_transform(X_raw[col])
            X_raw[col] = X_raw[col].astype(int)
            encoders[col] = le
        else:
            X_raw[col] = X_raw[col].fillna(0)

    target_encoder = None
    if y_raw.dtype == 'object' or str(y_raw.dtype) == 'category':
        y_raw = y_raw.astype(str).fillna('Missing')
        target_encoder = LabelEncoder()
        y = pd.Series(target_encoder.fit_transform(y_raw), name=target_col)
        encoders['__TARGET__'] = target_encoder
    else:
        y = y_raw.fillna(0).astype(int)

    print("[완료] 전처리 완료!\n")
    return X_raw, y, encoders


def train_xgboost_with_validation(X_train, y_train, X_val, y_val):
    print("[설정] XGBoost 모델 학습을 시작합니다...\n")

    num_classes = len(y_train.unique())
    objective = 'binary:logistic' if num_classes == 2 else 'multi:softprob'
    eval_metric = 'logloss' if num_classes == 2 else 'mlogloss'

    scale_pos_weight = 1
    if num_classes == 2:
        pos = int((y_train == 1).sum())
        neg = int((y_train == 0).sum())
        if pos > 0:
            scale_pos_weight = neg / pos

    model = xgb.XGBClassifier(
        learning_rate=0.01,
        n_estimators=2000,      # [확정] n=1000 vs n=2000 비교 실험 후 n=2000 채택
        max_depth=3,             # [확정] max_depth=3 (Gap 최소, 과적합 없음)
        min_child_weight=5,
        reg_alpha=2.0,
        reg_lambda=2.0,
        subsample=0.7,
        colsample_bytree=0.7,
        colsample_bylevel=0.7,
        gamma=1.0,
        scale_pos_weight=scale_pos_weight,
        use_label_encoder=False,
        random_state=42,
        objective=objective,
        eval_metric=eval_metric,
        verbosity=0,
        tree_method='hist',
    )

    model.fit(X_train, y_train)
    print("[완료] 모델 학습 완료!\n")
    return model


def evaluate_model(model, X_train, y_train, X_val, y_val, X_test, y_test, target_encoder=None):
    print("\n" + "="*70)
    print("[결과] 모델 성능 평가")
    print("="*70)

    y_pred_train = model.predict(X_train)
    train_acc = accuracy_score(y_train, y_pred_train)
    train_prec = precision_score(y_train, y_pred_train, average='weighted', zero_division=0)
    train_recall = recall_score(y_train, y_pred_train, average='weighted', zero_division=0)
    train_f1 = f1_score(y_train, y_pred_train, average='weighted', zero_division=0)

    y_pred_val = model.predict(X_val)
    val_acc = accuracy_score(y_val, y_pred_val)
    val_prec = precision_score(y_val, y_pred_val, average='weighted', zero_division=0)
    val_recall = recall_score(y_val, y_pred_val, average='weighted', zero_division=0)
    val_f1 = f1_score(y_val, y_pred_val, average='weighted', zero_division=0)

    y_pred_test = model.predict(X_test)
    test_acc = accuracy_score(y_test, y_pred_test)
    test_prec = precision_score(y_test, y_pred_test, average='weighted', zero_division=0)
    test_recall = recall_score(y_test, y_pred_test, average='weighted', zero_division=0)
    test_f1 = f1_score(y_test, y_pred_test, average='weighted', zero_division=0)

    print("\n[Train 세트 성능]")
    print(f"  정확도(Accuracy):  {train_acc:.4f}")
    print(f"  정밀도(Precision): {train_prec:.4f}")
    print(f"  재현율(Recall):    {train_recall:.4f}")
    print(f"  F1-스코어:         {train_f1:.4f}")

    print("\n[Validation 세트 성능]")
    print(f"  정확도(Accuracy):  {val_acc:.4f}")
    print(f"  정밀도(Precision): {val_prec:.4f}")
    print(f"  재현율(Recall):    {val_recall:.4f}")
    print(f"  F1-스코어:         {val_f1:.4f}")

    print("\n[Test 세트 성능]")
    print(f"  정확도(Accuracy):  {test_acc:.4f}")
    print(f"  정밀도(Precision): {test_prec:.4f}")
    print(f"  재현율(Recall):    {test_recall:.4f}")
    print(f"  F1-스코어:         {test_f1:.4f}")

    gap = train_acc - val_acc
    print(f"\n[과적합 분석]")
    print(f"  Train - Val Gap: {gap:.4f}")
    if gap <= 0.1:
        print("  [OK] 과적합 없음")
    elif gap <= 0.2:
        print("  [경고] 약간의 과적합 신호")
    else:
        print("  [경고] 과적합 신호 감지")

    print("\n[Test 세트 - 상세 분류 리포트]")
    target_names = None
    if target_encoder:
        target_names = [str(c) for c in target_encoder.classes_]
    else:
        target_names = ['정상 (0)', '악성 (1)']
    print(classification_report(y_test, y_pred_test, target_names=target_names))

    return {
        'train_acc': train_acc, 'val_acc': val_acc, 'test_acc': test_acc,
        'train_prec': train_prec, 'val_prec': val_prec, 'test_prec': test_prec,
        'train_recall': train_recall, 'val_recall': val_recall, 'test_recall': test_recall,
        'train_f1': train_f1, 'val_f1': val_f1, 'test_f1': test_f1
    }


def cross_validate_model(X, y):
    print("\n" + "="*70)
    print("[검증] 5-Fold 교차검증 실행 중...")
    print("="*70 + "\n")

    num_classes = len(y.unique())
    objective = 'binary:logistic' if num_classes == 2 else 'multi:softprob'
    eval_metric = 'logloss' if num_classes == 2 else 'mlogloss'

    scale_pos_weight = 1
    if num_classes == 2:
        pos = int((y == 1).sum())
        neg = int((y == 0).sum())
        if pos > 0:
            scale_pos_weight = neg / pos

    model = xgb.XGBClassifier(
        learning_rate=0.01,
        n_estimators=2000,      # [확정] n=1000 vs n=2000 비교 실험 후 n=2000 채택
        max_depth=3,             # [확정] max_depth=3 (Gap 최소, 과적합 없음)
        min_child_weight=5,
        reg_alpha=2.0,
        reg_lambda=2.0,
        subsample=0.7,
        colsample_bytree=0.7,
        scale_pos_weight=scale_pos_weight,
        random_state=42,
        objective=objective,
        eval_metric=eval_metric,
        verbosity=0
    )

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(model, X, y, cv=skf, scoring='accuracy')

    print(f"CV Scores: {cv_scores}")
    print(f"Mean CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})\n")


def main():
    base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    normal_data_path = os.path.join(base_path, 'Dataset', 'train', 'train_normal.json')
    malicious_data_path = os.path.join(base_path, 'Dataset', 'train', 'train_malicious.json')
    target_column = 'label'
    model_save_path = 'xgboost_sysmon_model.json'

    df = load_and_combine_data(normal_data_path, malicious_data_path)
    if df.empty:
        return

    X, y, encoders = preprocess_data(df, target_col=target_column)
    if X.empty or y.empty:
        return

    cross_validate_model(X, y)

    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp, test_size=0.25, stratify=y_temp, random_state=42
    )
    print(f"[완료] 데이터 분할 완료:")
    print(f"   Train: {X_train.shape[0]} 건 ({X_train.shape[0]/len(X)*100:.1f}%)")
    print(f"   Val:   {X_val.shape[0]} 건 ({X_val.shape[0]/len(X)*100:.1f}%)")
    print(f"   Test:  {X_test.shape[0]} 건 ({X_test.shape[0]/len(X)*100:.1f}%)\n")

    model = train_xgboost_with_validation(X_train, y_train, X_val, y_val)

    target_encoder = encoders.get('__TARGET__')
    metrics = evaluate_model(model, X_train, y_train, X_val, y_val, X_test, y_test, target_encoder)

    model.save_model(model_save_path)
    joblib.dump(encoders, 'label_encoders.pkl')

    print(f"\n[저장] 모델 저장 완료!")
    print(f"   - 모델 파일: {model_save_path}")
    print(f"   - 인코더 파일: label_encoders.pkl")
    print("\n" + "="*70)
    print("[완료] 학습 종료!")
    print("="*70)

if __name__ == "__main__":
    main()
