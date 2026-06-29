"""
max_depth=3 고정 / n_estimators=1000 vs 2000 비교 스크립트
"""
import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.preprocessing import LabelEncoder
import os, joblib, warnings, numpy as np

warnings.filterwarnings('ignore')

# ────────────────────────────────────────────────
# 데이터 로드 & 전처리 (train.py 와 동일 로직)
# ────────────────────────────────────────────────
BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

def load_and_preprocess():
    normal   = pd.read_json(os.path.join(BASE, 'Dataset', 'train', 'train_normal.json'))
    malicious= pd.read_json(os.path.join(BASE, 'Dataset', 'train', 'train_malicious.json'))
    df = pd.concat([normal, malicious], ignore_index=True)

    y = df['label'].astype(int)
    X = df.drop(columns=['label'])

    # 누출 컬럼 제거
    drop_cols = ['record_id','time_created','source_dataset','source_file',
                 'process_group_no','process_event_order',
                 'process_guid','parent_process_guid']
    X = X.drop(columns=[c for c in drop_cols if c in X.columns])

    # 희귀값 마스킹
    for col in ['process_name','command_line','parent_process']:
        if col in X.columns:
            freq = X[col].astype(str).value_counts()
            rare = set(freq[freq < 5].index)
            X[col] = X[col].astype(str).apply(lambda v: '__RARE__' if v in rare else v)

    # 인코딩
    encoders = {}
    for col in X.columns:
        if not pd.api.types.is_numeric_dtype(X[col]):
            X[col] = X[col].astype(str).fillna('Missing')
            le = LabelEncoder()
            X[col] = le.fit_transform(X[col]).astype(int)
            encoders[col] = le
        else:
            X[col] = X[col].fillna(0)

    return X, y, encoders


def run_experiment(X, y, n_estimators, max_depth=3):
    label = f"max_depth={max_depth}, n_estimators={n_estimators}"
    print(f"\n{'='*65}")
    print(f"  실험: {label}")
    print(f"{'='*65}")

    # 클래스 불균형 보정
    pos = int((y == 1).sum()); neg = int((y == 0).sum())
    spw = neg / pos if pos > 0 else 1

    model_cfg = dict(
        learning_rate=0.01,
        n_estimators=n_estimators,
        max_depth=max_depth,
        min_child_weight=5,
        reg_alpha=2.0,
        reg_lambda=2.0,
        subsample=0.7,
        colsample_bytree=0.7,
        colsample_bylevel=0.7,
        gamma=1.0,
        scale_pos_weight=spw,
        use_label_encoder=False,
        random_state=42,
        objective='binary:logistic',
        eval_metric='logloss',
        verbosity=0,
        tree_method='hist',
    )

    # 5-Fold CV
    print("  [1/2] 5-Fold CV 실행 중...")
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(xgb.XGBClassifier(**model_cfg), X, y, cv=skf, scoring='accuracy')
    print(f"        CV Mean: {cv_scores.mean():.4f}  Std: {cv_scores.std():.4f}")

    # Train / Val / Test 분할 후 최종 학습
    print("  [2/2] Train/Val/Test 학습 및 평가 중...")
    X_tmp, X_test, y_tmp, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    X_train, X_val, y_train, y_val = train_test_split(X_tmp, y_tmp, test_size=0.25, stratify=y_tmp, random_state=42)

    model = xgb.XGBClassifier(**model_cfg)
    model.fit(X_train, y_train)

    def metrics(yt, yp):
        return {
            'acc' : accuracy_score(yt, yp),
            'prec': precision_score(yt, yp, average='weighted', zero_division=0),
            'rec' : recall_score(yt, yp, average='weighted', zero_division=0),
            'f1'  : f1_score(yt, yp, average='weighted', zero_division=0),
        }

    tr = metrics(y_train, model.predict(X_train))
    va = metrics(y_val,   model.predict(X_val))
    te = metrics(y_test,  model.predict(X_test))
    gap = tr['acc'] - va['acc']

    print(f"\n  {'세트':<10} {'Accuracy':>9} {'Precision':>10} {'Recall':>8} {'F1':>8}")
    print(f"  {'-'*47}")
    print(f"  {'Train':<10} {tr['acc']:>9.4f} {tr['prec']:>10.4f} {tr['rec']:>8.4f} {tr['f1']:>8.4f}")
    print(f"  {'Val':<10} {va['acc']:>9.4f} {va['prec']:>10.4f} {va['rec']:>8.4f} {va['f1']:>8.4f}")
    print(f"  {'Test':<10} {te['acc']:>9.4f} {te['prec']:>10.4f} {te['rec']:>8.4f} {te['f1']:>8.4f}")
    print(f"\n  Train-Val Gap : {gap:+.4f}  {'[OK] 과적합 없음' if abs(gap) <= 0.05 else '[경고] 과적합 의심'}")
    print(f"  5-Fold CV     : {cv_scores.mean():.4f} +/- {cv_scores.std():.4f}")

    return {
        'label'     : label,
        'n'         : n_estimators,
        'cv_mean'   : cv_scores.mean(),
        'cv_std'    : cv_scores.std(),
        'train_acc' : tr['acc'],
        'val_acc'   : va['acc'],
        'test_acc'  : te['acc'],
        'test_f1'   : te['f1'],
        'gap'       : gap,
        'model'     : model,
    }


# ────────────────────────────────────────────────
# 메인
# ────────────────────────────────────────────────
print("\n데이터 로드 및 전처리 중...")
X, y, encoders = load_and_preprocess()
print(f"데이터 준비 완료: {X.shape[0]}행 x {X.shape[1]}열")

results = []
for n in [1000, 2000]:
    r = run_experiment(X, y, n_estimators=n, max_depth=3)
    results.append(r)

# ────────────────────────────────────────────────
# 최종 비교표
# ────────────────────────────────────────────────
print(f"\n\n{'='*65}")
print("  최종 비교 결과 (max_depth=3)")
print(f"{'='*65}")
print(f"  {'구분':<25} {'n=1000':>10} {'n=2000':>10} {'승자':>8}")
print(f"  {'-'*55}")

def winner(v1, v2, higher_better=True):
    if higher_better:
        return 'n=1000' if v1 > v2 else ('n=2000' if v2 > v1 else '동일')
    else:
        return 'n=1000' if v1 < v2 else ('n=2000' if v2 < v1 else '동일')

r0, r1 = results[0], results[1]

rows = [
    ('5-Fold CV',         r0['cv_mean'],   r1['cv_mean'],   True),
    ('Train Accuracy',    r0['train_acc'], r1['train_acc'], True),
    ('Val Accuracy',      r0['val_acc'],   r1['val_acc'],   True),
    ('Test Accuracy',     r0['test_acc'],  r1['test_acc'],  True),
    ('Test F1',           r0['test_f1'],   r1['test_f1'],   True),
    ('Train-Val Gap(절대값)', abs(r0['gap']), abs(r1['gap']), False),
]

for name, v0, v1, hb in rows:
    w = winner(v0, v1, hb)
    print(f"  {name:<25} {v0:>10.4f} {v1:>10.4f} {w:>8}")

print(f"\n  권장: {'n=1000' if r0['test_acc'] >= r1['test_acc'] else 'n=2000'}"
      f" (Test Acc {max(r0['test_acc'], r1['test_acc']):.4f})")

# ────────────────────────────────────────────────
# 더 좋은 모델을 최종 저장
# ────────────────────────────────────────────────
best = r0 if r0['test_acc'] >= r1['test_acc'] else r1
best['model'].save_model(os.path.join(os.path.dirname(__file__), 'xgboost_sysmon_model.json'))
joblib.dump(encoders, os.path.join(os.path.dirname(__file__), 'label_encoders.pkl'))
print(f"\n  최종 모델 저장 완료: {best['label']}")
print(f"{'='*65}\n")
