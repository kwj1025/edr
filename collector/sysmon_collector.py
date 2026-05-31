"""
sysmon_collector.py
───────────────────
PowerShell Get-WinEvent 방식으로 Sysmon 이벤트 수집.
수집 대상 Event ID: 1(프로세스 생성), 3(네트워크 연결), 5(프로세스 종료), 22(DNS 쿼리)
"""

from __future__ import annotations
import subprocess
import json
import platform
from datetime import datetime

SYSMON_CHANNEL   = "Microsoft-Windows-Sysmon/Operational"
TARGET_EVENT_IDS = {1, 3, 5, 22}

_MITRE_MAP = {
    1:  {"Tactic ID": "TA0002", "Tactic Name": "Execution",
         "Technique ID": "T1059",
         "Technique Name": "Command and Scripting Interpreter",
         "탐지 유형": "의심"},
    3:  {"Tactic ID": "TA0011", "Tactic Name": "Command and Control",
         "Technique ID": "T1071",
         "Technique Name": "Application Layer Protocol",
         "탐지 유형": "의심"},
    5:  {"Tactic ID": "TA0005", "Tactic Name": "Defense Evasion",
         "Technique ID": "T1070",
         "Technique Name": "Indicator Removal",
         "탐지 유형": "정상"},
    22: {"Tactic ID": "TA0011", "Tactic Name": "Command and Control",
         "Technique ID": "T1071.004",
         "Technique Name": "DNS",
         "탐지 유형": "의심"},
}

_RISK_MAP = {1: "M", 3: "M", 5: "L", 22: "L"}


def is_available() -> bool:
    return platform.system() == "Windows"


def _get_field(message: str, field: str) -> str:
    """Message 텍스트에서 특정 필드 값 추출."""
    for line in message.splitlines():
        if line.strip().startswith(field + ":"):
            return line.split(":", 1)[-1].strip()
    return ""


def _build_행위내용(event_id: int, msg: str) -> str:
    if event_id == 1:
        proc   = _get_field(msg, "Image").replace("\\", "/").split("/")[-1]
        parent = _get_field(msg, "ParentImage").replace("\\", "/").split("/")[-1]
        cmd    = _get_field(msg, "CommandLine")[:80]
        return f"[ID:1] {proc} 프로세스 생성 (부모: {parent}) | CMD: {cmd}"
    if event_id == 3:
        proc  = _get_field(msg, "Image").replace("\\", "/").split("/")[-1]
        dst   = _get_field(msg, "DestinationIp")
        port  = _get_field(msg, "DestinationPort")
        proto = _get_field(msg, "Protocol")
        return f"[ID:3] {proc} 네트워크 연결 → {dst}:{port} ({proto})"
    if event_id == 5:
        proc = _get_field(msg, "Image").replace("\\", "/").split("/")[-1]
        pid  = _get_field(msg, "ProcessId")
        return f"[ID:5] {proc} 프로세스 종료 (PID: {pid})"
    if event_id == 22:
        proc  = _get_field(msg, "Image").replace("\\", "/").split("/")[-1]
        query = _get_field(msg, "QueryName")
        return f"[ID:22] {proc} DNS 쿼리: {query}"
    return "알 수 없는 이벤트"


def collect(max_records: int = 500) -> list[dict]:
    if not is_available():
        raise RuntimeError("Windows 환경에서만 수집 가능합니다.")

    ids_filter = ",".join(str(i) for i in TARGET_EVENT_IDS)

    ps_script = f"""
$events = Get-WinEvent -LogName '{SYSMON_CHANNEL}' -MaxEvents {max_records} |
    Where-Object {{ {" -or ".join(f"$_.Id -eq {i}" for i in TARGET_EVENT_IDS)} }}

$result = @()
foreach ($e in $events) {{
    $result += [PSCustomObject]@{{
        Id          = $e.Id
        TimeCreated = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        Message     = $e.Message
    }}
}}
$result | ConvertTo-Json -Depth 3
"""

    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )

        if proc.returncode != 0 or not proc.stdout.strip():
            return []

        raw = proc.stdout.strip()

        # 단일 객체면 리스트로 감싸기
        if raw.startswith("{"):
            raw = f"[{raw}]"

        events_json = json.loads(raw)

    except Exception:
        return []

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows    = []

    for ev in events_json:
        event_id = int(ev.get("Id", 0))
        if event_id not in TARGET_EVENT_IDS:
            continue

        msg      = ev.get("Message", "")
        gen_time = ev.get("TimeCreated", now_str)
        mitre    = _MITRE_MAP[event_id]
        risk     = _RISK_MAP[event_id]

        proc_image = _get_field(msg, "Image")
        proc_name  = proc_image.replace("\\", "/").split("/")[-1] or "unknown.exe"

        rows.append({
            "로그 수신 날짜": now_str,
            "로그 생성 날짜": gen_time,
            "호스트 IP 주소": "localhost",
            "운영체제":       platform.platform(),
            "룰 레벨":        "중요" if risk in ("H", "High") else "일반",
            "위험도":         risk,
            "탐지 유형":      mitre["탐지 유형"],
            "Tactic ID":      mitre["Tactic ID"],
            "Tactic Name":    mitre["Tactic Name"],
            "Technique ID":   mitre["Technique ID"],
            "Technique Name": mitre["Technique Name"],
            "행위 내용":      _build_행위내용(event_id, msg),
            "프로세스":       proc_name,
            "상태":           "신규",
            "EventID":        event_id,
            "CommandLine":    _get_field(msg, "CommandLine"),
            "DestinationIp":  _get_field(msg, "DestinationIp"),
            "DestinationPort":_get_field(msg, "DestinationPort"),
            "QueryName":      _get_field(msg, "QueryName"),
        })

    return rows
# ==================================================================
# ⚖️ [김종한 담당] EDR 위협 가중치 판별 시스템 (ID 1, 3, 5, 22)
# ==================================================================
def evaluate_threat_level(log_data: dict) -> dict:
    score = 0
    event_id = log_data.get("EventID", 0)
    process_name = log_data.get("프로세스", "").lower()
    cmd_line = log_data.get("CommandLine", "").lower()
    dest_port = str(log_data.get("DestinationPort", ""))

    # --- [Step 1] 이벤트별 기본 점수 및 유형 설정 ---
    if event_id == 1:
        score += 10
        log_data["탐지 유형"] = "프로세스 실행"
    elif event_id == 3:
        score += 30
        log_data["탐지 유형"] = "네트워크 활동"
    elif event_id == 5:
        score += 5
        log_data["탐지 유형"] = "프로세스 종료"
    elif event_id == 22:
        score += 10
        log_data["탐지 유형"] = "DNS 질의"

    # --- [Step 2] 가중치 부여 (위험 행위 탐지) ---
    # 1. 위험 도구 실행 가중치 (ID 1 연관)
    danger_tools = ["powershell", "cmd.exe", "certutil", "bitsadmin", "schtasks", "reg.exe"]
    if any(tool in process_name for tool in danger_tools):
        score += 40
        log_data["탐지 유형"] = "위험 도구 실행 탐지"

    # 2. 비표준 포트 통신 가중치 (ID 3 연관)
    if event_id == 3 and dest_port not in ["80", "443", ""]:
        score += 20
        log_data["탐지 유형"] = "비표준 포트 통신 탐지"

    # 3. 보안 프로그램 강제 종료 가중치 (ID 5 연관 - 가장 치명적)
    security_apps = ["v3", "alyac", "msmpeng", "defender", "edr", "agent"]
    if event_id == 5 and any(app in process_name for app in security_apps):
        score += 60
        log_data["탐지 유형"] = "🚨 보안 서비스 무력화 의심"

    # --- [Step 3] 최종 등급 판정 ---
    log_data["위험점수"] = score

    if score >= 80:
        log_data["상태"], log_data["위험도"] = "🚨 악성", "High"
    elif score >= 40:
        log_data["상태"], log_data["위험도"] = "⚠️ 의심", "Medium"
    else:
        log_data["상태"], log_data["위험도"] = "✅ 정상", "Low"

    log_data["조치내용"] = f"종합 위험 점수 {score}점 산출"
    return log_data

def apply_jonghan_policy(collected_logs: list[dict]) -> list[dict]:
    """수집된 로그에 종한님의 가중치 법을 일괄 적용"""
    return [evaluate_threat_level(log) for log in collected_logs]