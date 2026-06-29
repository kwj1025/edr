import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.feature_selection import mutual_info_classif

normal = pd.read_json(r'C:\EDR\Dataset\train\train_normal.json')
malicious = pd.read_json(r'C:\EDR\Dataset\train\train_malicious.json')
df = pd.concat([normal, malicious], ignore_index=True)

drop_cols = ['record_id','time_created','source_dataset','source_file',
             'process_group_no','process_event_order','label']
X = df.drop(columns=[c for c in drop_cols if c in df.columns])
y = df['label']

print("=== 남은 피처 목록 ===")
print(list(X.columns))
print()

X_enc = X.copy()
for col in X_enc.columns:
    if not pd.api.types.is_numeric_dtype(X_enc[col]):
        X_enc[col] = X_enc[col].astype(str).fillna('Missing')
        le = LabelEncoder()
        X_enc[col] = le.fit_transform(X_enc[col])
    else:
        X_enc[col] = X_enc[col].fillna(0)

mi = mutual_info_classif(X_enc, y, random_state=42)
mi_series = pd.Series(mi, index=X_enc.columns).sort_values(ascending=False)
print("=== 피처별 Mutual Information (label과의 정보량) ===")
print(mi_series.round(4).to_string())
print()

# process_name 분리 분석
normal_procs = set(normal['process_name'].dropna().unique())
malicious_procs = set(malicious['process_name'].dropna().unique())
only_malicious = malicious_procs - normal_procs
only_normal = normal_procs - malicious_procs
total_malicious_rows = len(malicious)
only_mal_rows = malicious[malicious['process_name'].isin(only_malicious)].shape[0]

print(f"process_name 고유값 (정상): {len(normal_procs)}개")
print(f"process_name 고유값 (악성): {len(malicious_procs)}개")
print(f"양쪽 모두 존재하는 process_name: {len(normal_procs & malicious_procs)}개")
print(f"악성에만 있는 process_name이 악성 레코드에서 차지하는 비율: {only_mal_rows/total_malicious_rows*100:.1f}%")
print()
print("악성에만 존재하는 process_name 예시 (5개):")
for p in list(only_malicious)[:5]:
    print(f"  {p}")
