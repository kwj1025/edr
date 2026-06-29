"""
위협도 판별 모듈
학습된 XGBoost 모델을 로드하여 Sysmon 로그의 위협도를 예측합니다.
"""

import os
import pandas as pd
import xgboost as xgb
import joblib
import numpy as np
from sklearn.preprocessing import LabelEncoder
import warnings

warnings.filterwarnings('ignore')

class ThreatPredictor:
    """XGBoost 모델을 이용한 위협도 판별"""
    
    def __init__(self, model_path=None, encoders_path=None):
        """
        모듈 초기화
        
        Args:
            model_path: XGBoost 모델 파일 경로
            encoders_path: LabelEncoder 딕셔너리 저장 파일 경로
        """
        self.model = None
        self.encoders = {}
        self.feature_names = []
        
        # 기본 경로 설정
        if model_path is None:
            model_path = os.path.join(os.path.dirname(__file__), 'xgboost_sysmon_model.json')
        if encoders_path is None:
            encoders_path = os.path.join(os.path.dirname(__file__), 'label_encoders.pkl')
        
        self.model_path = model_path
        self.encoders_path = encoders_path
        self._load_model()
    
    def _load_model(self):
        """학습된 모델과 인코더 로드"""
        try:
            if not os.path.exists(self.model_path):
                raise FileNotFoundError(f"모델 파일을 찾을 수 없습니다: {self.model_path}")
            
            self.model = xgb.Booster()
            self.model.load_model(self.model_path)
            self.feature_names = self.model.feature_names
            print(f"[OK] 모델 로드 성공: {self.model_path}")
            
        except Exception as e:
            print(f"[FAIL] 모델 로드 실패: {e}")
            self.model = None
            return
        
        try:
            if os.path.exists(self.encoders_path):
                self.encoders = joblib.load(self.encoders_path)
                print(f"[OK] 인코더 로드 성공: {self.encoders_path}")
            else:
                print(f"[WARN] 인코더 파일을 찾을 수 없습니다: {self.encoders_path}")
        except Exception as e:
            print(f"[FAIL] 인코더 로드 실패: {e}")
    
    def is_ready(self):
        """모델이 준비되었는지 확인"""
        return self.model is not None
    
    def preprocess_log(self, log_dict):
        """
        Sysmon 로그를 전처리하여 모델 입력 형식으로 변환
        
        Args:
            log_dict: 원본 Sysmon 로그 딕셔너리
            
        Returns:
            pd.DataFrame: 전처리된 데이터
        """
        try:
            # 로그를 DataFrame으로 변환
            df = pd.DataFrame([log_dict])
            
            # 드롭할 컬럼들
            cols_to_drop = ['record_id', 'time_created', 'label', 'risk_score']
            for col in cols_to_drop:
                if col in df.columns:
                    df = df.drop(columns=[col])
            
            # 인코딩 처리
            for col in df.columns:
                if col in self.encoders and col != '__TARGET__':
                    encoder = self.encoders[col]
                    try:
                        df[col] = df[col].astype(str).fillna('Missing')
                        # 학습 시 보지 못한 카테고리 처리
                        known_classes = set(encoder.classes_)
                        df[col] = df[col].apply(
                            lambda x: x if x in known_classes else 'Missing'
                        )
                        df[col] = encoder.transform(df[col])
                    except Exception as e:
                        print(f"[WARN] 컬럼 {col} 인코딩 실패: {e}")
                        df[col] = 0
                elif not pd.api.types.is_numeric_dtype(df[col]):
                    # 인코더가 없는 경우 수치형으로 변환
                    df[col] = df[col].astype(str).fillna('Missing')
                    le = LabelEncoder()
                    try:
                        df[col] = le.fit_transform(df[col])
                    except Exception as e:
                        print(f"[WARN] 컬럼 {col} 변환 실패: {e}")
                        df[col] = 0
                else:
                    # 수치형 컬럼 결측치 처리
                    df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
            
            # 모델 입력 특성과 맞추기
            for col in self.feature_names:
                if col not in df.columns:
                    df[col] = 0
            
            df = df[self.feature_names]
            return df
            
        except Exception as e:
            print(f"[FAIL] 전처리 실패: {e}")
            return None
    
    def predict(self, log_dict, return_probability=True):
        """
        Sysmon 로그의 위협도 예측
        
        Args:
            log_dict: Sysmon 로그 딕셔너리
            return_probability: 확률값 반환 여부
            
        Returns:
            dict: {
                'prediction': 0 or 1 (0=정상, 1=악성),
                'probability': 0.0~1.0 (악성 확률),
                'risk_label': 'Low' | 'Medium' | 'High' | 'Critical',
                'success': True/False
            }
        """
        if not self.is_ready():
            return {
                'prediction': -1,
                'probability': 0.0,
                'risk_label': 'Unknown',
                'success': False,
                'error': '모델이 준비되지 않았습니다'
            }
        
        try:
            # 전처리
            X = self.preprocess_log(log_dict)
            if X is None or X.empty:
                return {
                    'prediction': -1,
                    'probability': 0.0,
                    'risk_label': 'Unknown',
                    'success': False,
                    'error': '전처리 실패'
                }
            
            # 예측
            dmatrix = xgb.DMatrix(X)
            proba = self.model.predict(dmatrix)[0]  # 악성일 확률
            prediction = 1 if proba >= 0.5 else 0
            
            # 위협도 라벨 결정
            if proba < 0.25:
                risk_label = 'Low'
            elif proba < 0.50:
                risk_label = 'Medium'
            elif proba < 0.75:
                risk_label = 'High'
            else:
                risk_label = 'Critical'
            
            return {
                'prediction': prediction,
                'probability': float(proba),
                'risk_label': risk_label,
                'success': True
            }
            
        except Exception as e:
            print(f"[FAIL] 예측 실패: {e}")
            return {
                'prediction': -1,
                'probability': 0.0,
                'risk_label': 'Unknown',
                'success': False,
                'error': str(e)
            }
    
    def predict_batch(self, log_list):
        """
        여러 Sysmon 로그의 위협도 일괄 예측
        
        Args:
            log_list: Sysmon 로그 딕셔너리 리스트
            
        Returns:
            list: 예측 결과 리스트
        """
        results = []
        for log in log_list:
            result = self.predict(log)
            results.append(result)
        return results


if __name__ == "__main__":
    # 테스트 예시
    predictor = ThreatPredictor()
    
    if predictor.is_ready():
        # 샘플 로그로 테스트
        sample_log = {
            'process_id': 1234,
            'parent_process_id': 4,
            'image': 'C:\\Windows\\System32\\notepad.exe',
            'command_line': 'notepad.exe',
            'user': 'SYSTEM',
            'parent_image': 'C:\\Windows\\System32\\explorer.exe'
        }
        
        result = predictor.predict(sample_log)
        print(f"\n예측 결과: {result}")
    else:
        print("모델을 로드할 수 없습니다.")
