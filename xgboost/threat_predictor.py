"""
위협도 판별 모듈

학습된 XGBoost 모델을 로드하여 Sysmon 로그의 위협도를 예측합니다.
LabelEncoder에 없는 값이 들어와도 오류가 나지 않도록 안전하게 처리합니다.
"""

import os
import warnings

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.preprocessing import LabelEncoder

warnings.filterwarnings("ignore")


class ThreatPredictor:
    """XGBoost 모델을 이용한 위협도 판별"""

    def __init__(self, model_path=None, encoders_path=None):
        self.model = None
        self.encoders = {}
        self.feature_names = []

        if model_path is None:
            model_path = os.path.join(
                os.path.dirname(__file__),
                "xgboost_sysmon_model.json",
            )

        if encoders_path is None:
            encoders_path = os.path.join(
                os.path.dirname(__file__),
                "label_encoders.pkl",
            )

        self.model_path = model_path
        self.encoders_path = encoders_path

        self._load_model()

    def _load_model(self):
        """학습된 모델과 인코더 로드"""
        try:
            if not os.path.exists(self.model_path):
                raise FileNotFoundError(
                    f"모델 파일을 찾을 수 없습니다: {self.model_path}"
                )

            self.model = xgb.Booster()
            self.model.load_model(self.model_path)
            self.feature_names = self.model.feature_names or []

            print(f"[OK] 모델 로드 성공: {self.model_path}")
            print(f"[OK] 모델 feature 개수: {len(self.feature_names)}")

        except Exception as e:
            print(f"[FAIL] 모델 로드 실패: {e}")
            self.model = None
            return

        try:
            if os.path.exists(self.encoders_path):
                self.encoders = joblib.load(self.encoders_path)
                print(f"[OK] 인코더 로드 성공: {self.encoders_path}")
                print(f"[OK] 인코더 컬럼 수: {len(self.encoders)}")
            else:
                print(f"[WARN] 인코더 파일을 찾을 수 없습니다: {self.encoders_path}")
                self.encoders = {}

        except Exception as e:
            print(f"[FAIL] 인코더 로드 실패: {e}")
            self.encoders = {}

    def is_ready(self):
        """모델이 준비되었는지 확인"""
        return self.model is not None

    def _safe_encode_value(self, encoder, value):
        """
        LabelEncoder 안전 변환.

        학습 때 본 값이면 그대로 변환하고,
        못 본 값이면 Missing 또는 빈 문자열로 변환하고,
        그것도 없으면 0으로 처리합니다.
        """
        try:
            if value is None:
                value = ""

            value = str(value)
            known_classes = set(str(x) for x in encoder.classes_)

            if value in known_classes:
                return int(encoder.transform([value])[0])

            if "Missing" in known_classes:
                return int(encoder.transform(["Missing"])[0])

            if "" in known_classes:
                return int(encoder.transform([""])[0])

            if "unknown" in known_classes:
                return int(encoder.transform(["unknown"])[0])

            if "unknown.exe" in known_classes:
                return int(encoder.transform(["unknown.exe"])[0])

            return 0

        except Exception:
            return 0

    def preprocess_log(self, log_dict):
        """
        Sysmon 로그를 전처리하여 모델 입력 형식으로 변환합니다.

        Args:
            log_dict: 원본 Sysmon 로그 딕셔너리

        Returns:
            pd.DataFrame: 전처리된 데이터
        """
        try:
            df = pd.DataFrame([log_dict])

            cols_to_drop = [
                "record_id",
                "time_created",
                "label",
                "risk_score",
                "recv_time",
                "gen_time",
                "host_ip",
                "os_name",
                "rule_level",
                "risk",
                "detect_type",
                "tactic_id",
                "tactic_name",
                "technique_id",
                "technique_name",
                "action_desc",
                "status",
                "ai_score",
                "ai_risk",
            ]

            for col in cols_to_drop:
                if col in df.columns:
                    df = df.drop(columns=[col])

            # 학습 feature 기준으로 누락 컬럼 생성
            for col in self.feature_names:
                if col not in df.columns:
                    df[col] = 0

            # feature_names가 있으면 그 컬럼만 사용
            if self.feature_names:
                df = df[self.feature_names]

            # 컬럼별 전처리
            for col in df.columns:
                if col in self.encoders and col != "__TARGET__":
                    encoder = self.encoders[col]

                    df[col] = df[col].apply(
                        lambda x: self._safe_encode_value(encoder, x)
                    )

                else:
                    if pd.api.types.is_numeric_dtype(df[col]):
                        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)
                    else:
                        # 인코더가 없는 문자열 컬럼은 안전하게 임시 숫자화
                        df[col] = df[col].fillna("").astype(str)

                        le = LabelEncoder()

                        try:
                            df[col] = le.fit_transform(df[col])
                        except Exception:
                            df[col] = 0

            # 최종적으로 전부 숫자형 보장
            for col in df.columns:
                df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

            return df

        except Exception as e:
            print(f"[FAIL] 전처리 실패: {e}")
            return None

    def predict(self, log_dict, return_probability=True):
        """
        Sysmon 로그의 위협도 예측

        Returns:
            dict:
            {
                'prediction': 0 or 1,
                'probability': 0.0~1.0,
                'risk_label': 'Low' | 'Medium' | 'High' | 'Critical',
                'success': True/False
            }
        """
        if not self.is_ready():
            return {
                "prediction": -1,
                "probability": 0.0,
                "risk_label": "Unknown",
                "success": False,
                "error": "모델이 준비되지 않았습니다",
            }

        try:
            X = self.preprocess_log(log_dict)

            if X is None or X.empty:
                return {
                    "prediction": -1,
                    "probability": 0.0,
                    "risk_label": "Unknown",
                    "success": False,
                    "error": "전처리 실패",
                }

            dmatrix = xgb.DMatrix(X)
            proba = float(self.model.predict(dmatrix)[0])

            if np.isnan(proba) or np.isinf(proba):
                proba = 0.0

            proba = max(0.0, min(1.0, proba))
            prediction = 1 if proba >= 0.5 else 0

            if proba < 0.25:
                risk_label = "Low"
            elif proba < 0.50:
                risk_label = "Medium"
            elif proba < 0.75:
                risk_label = "High"
            else:
                risk_label = "Critical"

            return {
                "prediction": prediction,
                "probability": proba,
                "risk_label": risk_label,
                "success": True,
            }

        except Exception as e:
            print(f"[FAIL] 예측 실패: {e}")

            return {
                "prediction": -1,
                "probability": 0.0,
                "risk_label": "Unknown",
                "success": False,
                "error": str(e),
            }

    def predict_batch(self, log_list):
        """여러 Sysmon 로그의 위협도 일괄 예측"""
        results = []

        for log in log_list:
            result = self.predict(log)
            results.append(result)

        return results


if __name__ == "__main__":
    predictor = ThreatPredictor()

    if predictor.is_ready():
        sample_log = {
            "event_id": 1,
            "process_id": 1234,
            "parent_process_id": 4,
            "image": r"C:\Windows\System32\notepad.exe",
            "process_name": "notepad.exe",
            "command_line": "notepad.exe",
            "user": "SYSTEM",
            "parent_image": r"C:\Windows\System32\explorer.exe",
            "destination_ip": "",
            "destination_port": "",
            "source_ip": "",
            "source_port": "",
            "query_name": "",
        }

        result = predictor.predict(sample_log)
        print("\n예측 결과:", result)

    else:
        print("모델을 로드할 수 없습니다.")