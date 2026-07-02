import json
import platform
import socket
import subprocess
import sys
import time
import ipaddress
from datetime import datetime
from pathlib import Path

import requests


# ============================================================
# 기본 설정
# ============================================================

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
TARGET_EVENT_IDS = [1, 3, 5, 22]

API_URL = "http://127.0.0.1:8000/logs"
POLL_INTERVAL = 3

BASE_DIR = Path(__file__).resolve().parent.parent
STATE_FILE = Path(__file__).resolve().parent / "collector_state.json"
ALERT_LOG_FILE = Path(__file__).resolve().parent / "alert_logs.jsonl"

XGBOOST_DIR = BASE_DIR / "xgboost"
sys.path.insert(0, str(XGBOOST_DIR))


# ============================================================
# XGBoost 모델 로드
# ============================================================

try:
    from threat_predictor import ThreatPredictor

    THREAT_PREDICTOR = ThreatPredictor()
    PREDICTOR_READY = THREAT_PREDICTOR.is_ready()

    if PREDICTOR_READY:
        print("[XGBoost] 모델 로드 성공")
    else:
        print("[XGBoost] 모델 준비 안 됨")

except Exception as e:
    THREAT_PREDICTOR = None
    PREDICTOR_READY = False
    print("[XGBoost] 로드 실패:", e)


# ============================================================
# MITRE 기본 매핑
# ============================================================

MITRE_MAP = {
    1: {
        "risk": "Medium",
        "detect_type": "프로세스 실행",
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
    },
    3: {
        "risk": "Medium",
        "detect_type": "네트워크 연결",
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
    },
    5: {
        "risk": "Low",
        "detect_type": "프로세스 종료",
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "technique_id": "T1070",
        "technique_name": "Indicator Removal",
    },
    22: {
        "risk": "Low",
        "detect_type": "DNS 요청",
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
        "technique_id": "T1071.004",
        "technique_name": "DNS",
    },
}


# ============================================================
# 상태 파일 관리
# ============================================================

def load_last_record_id():
    if not STATE_FILE.exists():
        return 0

    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return int(data.get("last_record_id", 0))
    except Exception:
        return 0


def save_last_record_id(record_id):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump({"last_record_id": record_id}, f, ensure_ascii=False, indent=2)


# ============================================================
# 공통 유틸
# ============================================================

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


def get_field(message, field_name):
    if not message:
        return ""

    target = field_name + ":"

    for line in message.splitlines():
        line = line.strip()

        if line.startswith(target):
            return line.split(":", 1)[1].strip()

    return ""


def get_process_name(image_path):
    if not image_path:
        return "unknown.exe"

    image_path = image_path.replace("\\", "/")
    return image_path.split("/")[-1] or "unknown.exe"


def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


def safe_int(value, default=0):
    try:
        if value is None or value == "":
            return default

        return int(str(value))
    except Exception:
        return default


# ============================================================
# 행위 설명 생성
# ============================================================

def make_action_desc(event_id, message):
    image = get_field(message, "Image")
    process_name = get_process_name(image)

    if event_id == 1:
        command_line = get_field(message, "CommandLine")
        parent_image = get_field(message, "ParentImage")
        parent_name = get_process_name(parent_image)

        return (
            "[ID:1] "
            + process_name
            + " 프로세스 실행"
            + " | 부모: "
            + parent_name
            + " | CMD: "
            + command_line[:120]
        )

    if event_id == 3:
        dst_ip = get_field(message, "DestinationIp")
        dst_port = get_field(message, "DestinationPort")
        protocol = get_field(message, "Protocol")

        return (
            "[ID:3] "
            + process_name
            + " 네트워크 연결 -> "
            + dst_ip
            + ":"
            + dst_port
            + " "
            + protocol
        )

    if event_id == 5:
        process_id = get_field(message, "ProcessId")

        return "[ID:5] " + process_name + " 프로세스 종료 | PID: " + process_id

    if event_id == 22:
        query_name = get_field(message, "QueryName")

        return "[ID:22] " + process_name + " DNS 요청 | " + query_name

    return "Sysmon 이벤트"


# ============================================================
# 규칙 기반 위험도 계산
# ============================================================

def calculate_rule_score(log):
    score = 0
    reasons = []

    event_id = int(log.get("event_id") or 0)
    process_name = str(log.get("process_name") or "").lower()
    command_line = str(log.get("command_line") or "").lower()
    destination_ip = str(log.get("destination_ip") or "")
    destination_port = str(log.get("destination_port") or "")
    query_name = str(log.get("query_name") or "").lower()

    if event_id == 1:
        score += 10
    elif event_id == 3:
        score += 25
    elif event_id == 5:
        score += 5
    elif event_id == 22:
        score += 10

    danger_tools = [
        "powershell",
        "cmd.exe",
        "wscript",
        "cscript",
        "mshta",
        "rundll32",
        "regsvr32",
        "certutil",
        "bitsadmin",
        "schtasks",
        "net.exe",
        "wmic",
        "reg.exe",
    ]

    if any(tool in process_name for tool in danger_tools):
        score += 35
        reasons.append("위험 도구 실행")

    suspicious_keywords = [
        "-enc",
        "encodedcommand",
        "bypass",
        "hidden",
        "downloadstring",
        "invoke-webrequest",
        "iwr ",
        "iex",
        "frombase64string",
        "new-object net.webclient",
    ]

    if any(keyword in command_line for keyword in suspicious_keywords):
        score += 35
        reasons.append("의심 명령어 사용")

    if event_id == 3 and destination_port not in ["", "80", "443", "53"]:
        score += 20
        reasons.append("비표준 포트 통신")

    if event_id == 3 and destination_ip and not is_private_ip(destination_ip):
        score += 15
        reasons.append("외부 IP 통신")

    suspicious_domains = [
        ".top",
        ".xyz",
        ".ru",
        "duckdns",
        "no-ip",
        "pastebin",
        "raw.githubusercontent",
    ]

    if event_id == 22 and any(domain in query_name for domain in suspicious_domains):
        score += 25
        reasons.append("의심 DNS 요청")

    security_processes = [
        "msmpeng",
        "defender",
        "v3",
        "alyac",
        "edr",
        "agent",
        "security",
    ]

    if event_id == 5 and any(name in process_name for name in security_processes):
        score += 60
        reasons.append("보안 프로세스 종료 의심")

    if score >= 75:
        risk = "High"
        rule_level = "중요"
        status = "알림"
    elif score >= 40:
        risk = "Medium"
        rule_level = "주의"
        status = "의심"
    else:
        risk = "Low"
        rule_level = "일반"
        status = "신규"

    log["rule_score"] = score
    log["risk"] = risk
    log["rule_level"] = rule_level
    log["status"] = status
    log["alert_reason"] = ", ".join(reasons) if reasons else "특이사항 없음"

    return log


# ============================================================
# XGBoost 입력 생성
# ============================================================

def make_xgboost_input(log):
    """
    DB 저장용 로그 전체를 모델에 넣지 않고,
    XGBoost 모델이 학습 예시에서 사용한 형태에 가까운 필드만 넣습니다.
    """
    return {
        "event_id": safe_int(log.get("event_id"), 0),
        "process_id": safe_int(log.get("process_id"), 0),
        "parent_process_id": safe_int(log.get("parent_process_id"), 0),
        "image": log.get("image", ""),
        "process_name": log.get("process_name", ""),
        "command_line": log.get("command_line", ""),
        "user": log.get("user", ""),
        "parent_image": log.get("parent_image", ""),
        "destination_ip": log.get("destination_ip", ""),
        "destination_port": safe_int(log.get("destination_port"), 0),
        "source_ip": log.get("source_ip", ""),
        "source_port": safe_int(log.get("source_port"), 0),
        "query_name": log.get("query_name", ""),
    }


def add_xgboost_prediction(logs):
    if not logs:
        return logs

    if not PREDICTOR_READY or THREAT_PREDICTOR is None:
        for log in logs:
            log["ai_score"] = None
            log["ai_risk"] = "Unknown"

        return logs

    for log in logs:
        try:
            xgb_input = make_xgboost_input(log)
            result = THREAT_PREDICTOR.predict(xgb_input)

            if result.get("success"):
                probability = float(result.get("probability", 0.0))
                log["ai_score"] = round(probability * 100, 2)
                log["ai_risk"] = result.get("risk_label", "Unknown")
            else:
                log["ai_score"] = None
                log["ai_risk"] = "Unknown"

        except Exception as e:
            print("[XGBoost 예측 실패]", e)
            log["ai_score"] = None
            log["ai_risk"] = "Unknown"

    return logs


# ============================================================
# 알람 정책
# ============================================================

def apply_alert_policy(logs):
    """
    AI가 과탐지할 수 있으므로 AI Critical만으로 무조건 알림 처리하지 않습니다.

    알림 조건:
    1. 규칙 기반 risk가 High
    2. 규칙 기반 risk가 Medium 이상이고 AI도 High/Critical
    3. 규칙 기반 risk가 Medium 이상이고 AI 점수가 90점 이상
    """
    for log in logs:
        risk = str(log.get("risk") or "")
        ai_risk = str(log.get("ai_risk") or "")
        ai_score = log.get("ai_score")

        is_alert = False
        alert_reasons = []

        if risk == "High":
            is_alert = True
            alert_reasons.append("규칙 기반 High 위험도")

        if risk in ["Medium", "High"] and ai_risk in ["High", "Critical"]:
            is_alert = True
            alert_reasons.append("규칙 기반 위험도와 AI 위험도 동시 탐지")

        try:
            if (
                risk in ["Medium", "High"]
                and ai_score is not None
                and float(ai_score) >= 90
            ):
                is_alert = True
                alert_reasons.append("AI 점수 90점 이상")
        except Exception:
            pass

        if is_alert:
            log["status"] = "알림"
            log["rule_level"] = "중요"

            reason_text = " / ".join(alert_reasons)

            if reason_text and not str(log.get("action_desc", "")).startswith("[ALERT]"):
                log["action_desc"] = (
                    "[ALERT] "
                    + reason_text
                    + " | "
                    + str(log.get("action_desc"))
                )

        else:
            if risk == "Medium":
                log["status"] = "의심"
                log["rule_level"] = "주의"
            else:
                log["status"] = "신규"
                log["rule_level"] = "일반"

    return logs


# ============================================================
# 알람 출력 및 파일 저장
# ============================================================

def notify_alerts(logs):
    alerts = [log for log in logs if log.get("status") == "알림"]

    if not alerts:
        return

    try:
        import winsound

        winsound.MessageBeep(winsound.MB_ICONHAND)
    except Exception:
        pass

    print("\n" + "=" * 70)
    print("[실시간 알람] 위험 이벤트 감지:", len(alerts), "건")
    print("=" * 70)

    with open(ALERT_LOG_FILE, "a", encoding="utf-8") as f:
        for log in alerts:
            alert_data = {
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "event_id": log.get("event_id"),
                "process_name": log.get("process_name"),
                "risk": log.get("risk"),
                "ai_score": log.get("ai_score"),
                "ai_risk": log.get("ai_risk"),
                "reason": log.get("alert_reason"),
                "action_desc": log.get("action_desc"),
            }

            print("EventID:", alert_data["event_id"])
            print("Process:", alert_data["process_name"])
            print("Risk:", alert_data["risk"])
            print("AI:", str(alert_data["ai_score"]) + " / " + str(alert_data["ai_risk"]))
            print("Reason:", alert_data["reason"])
            print("Action:", alert_data["action_desc"])
            print("-" * 70)

            f.write(json.dumps(alert_data, ensure_ascii=False) + "\n")

    print("=" * 70 + "\n")


# ============================================================
# PowerShell로 Sysmon 이벤트 조회
# ============================================================

def run_powershell_get_events(max_records=100):
    ps_script = """
$events = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents """ + str(max_records) + """ |
    Where-Object { $_.Id -eq 1 -or $_.Id -eq 3 -or $_.Id -eq 5 -or $_.Id -eq 22 }

$result = @()

foreach ($e in $events) {
    $result += [PSCustomObject]@{
        Id = $e.Id
        RecordId = $e.RecordId
        TimeCreated = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        Message = $e.Message
    }
}

$result | ConvertTo-Json -Depth 5
"""

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )

        if result.returncode != 0:
            print("[PowerShell 오류]")
            print(result.stderr)
            return []

        output = result.stdout.strip()

        if output == "":
            return []

        data = json.loads(output)

        if data is None:
            return []

        if isinstance(data, dict):
            data = [data]

        if not isinstance(data, list):
            return []

        return data

    except Exception as e:
        print("[Sysmon 로그 조회 실패]", e)
        return []


# ============================================================
# 최근 Sysmon 로그 수집
# ============================================================

def collect_recent_logs():
    events = run_powershell_get_events(100)

    logs = []
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    host_ip = get_local_ip()
    os_name = platform.platform()

    for event in events:
        try:
            event_id = int(event.get("Id", 0))
            record_id = int(event.get("RecordId", 0))
        except Exception:
            continue

        if event_id not in TARGET_EVENT_IDS:
            continue

        message = event.get("Message", "")
        gen_time = event.get("TimeCreated", now_str)

        image = get_field(message, "Image")
        process_name = get_process_name(image)

        parent_image = get_field(message, "ParentImage")
        parent_process_id = get_field(message, "ParentProcessId")

        mitre = MITRE_MAP.get(event_id, {})

        log = {
            "recv_time": now_str,
            "gen_time": gen_time,
            "host_ip": host_ip,
            "os_name": os_name,
            "rule_level": "일반",
            "risk": mitre.get("risk", "Low"),
            "detect_type": mitre.get("detect_type", "기타"),
            "tactic_id": mitre.get("tactic_id"),
            "tactic_name": mitre.get("tactic_name"),
            "technique_id": mitre.get("technique_id"),
            "technique_name": mitre.get("technique_name"),
            "action_desc": make_action_desc(event_id, message),
            "process_name": process_name,
            "event_id": event_id,
            "command_line": get_field(message, "CommandLine"),
            "destination_ip": get_field(message, "DestinationIp"),
            "destination_port": get_field(message, "DestinationPort"),
            "query_name": get_field(message, "QueryName"),
            "status": "신규",
            "_record_id": record_id,

            # XGBoost 입력용 내부 필드
            "process_id": get_field(message, "ProcessId"),
            "parent_process_id": parent_process_id,
            "image": image,
            "user": get_field(message, "User"),
            "parent_image": parent_image,
            "source_ip": get_field(message, "SourceIp"),
            "source_port": get_field(message, "SourcePort"),
        }

        log = calculate_rule_score(log)
        logs.append(log)

    return logs


# ============================================================
# FastAPI 전송
# ============================================================

def send_logs_to_fastapi(logs):
    if len(logs) == 0:
        return True

    clean_logs = []

    for log in logs:
        copied = dict(log)

        # 내부 상태 필드 제거
        copied.pop("_record_id", None)
        copied.pop("rule_score", None)
        copied.pop("alert_reason", None)

        # XGBoost 입력용 내부 필드 제거
        copied.pop("process_id", None)
        copied.pop("parent_process_id", None)
        copied.pop("image", None)
        copied.pop("user", None)
        copied.pop("parent_image", None)
        copied.pop("source_ip", None)
        copied.pop("source_port", None)

        clean_logs.append(copied)

    payload = {
        "logs": clean_logs
    }

    try:
        response = requests.post(API_URL, json=payload, timeout=10)

        if response.status_code == 200 or response.status_code == 201:
            print("[전송 성공] " + str(len(clean_logs)) + "건")
            return True

        print("[전송 실패] " + str(response.status_code))
        print(response.text)
        return False

    except Exception as e:
        print("[FastAPI 연결 실패]", e)
        return False


# ============================================================
# 메인 루프
# ============================================================

def main():
    print("Sysmon 실시간 로그 이벤트 수집 및 알람 기능 시작")
    print("수집 대상 Event ID:", TARGET_EVENT_IDS)
    print("수집 주기:", str(POLL_INTERVAL) + "초")
    print("FastAPI 주소:", API_URL)
    print("상태 파일:", STATE_FILE)
    print("알람 로그 파일:", ALERT_LOG_FILE)
    print("-" * 70)

    if platform.system() != "Windows":
        print("이 수집기는 Windows에서만 실행 가능합니다.")
        return

    last_record_id = load_last_record_id()
    print("마지막 처리 RecordId:", last_record_id)

    while True:
        try:
            logs = collect_recent_logs()
            logs.sort(key=lambda x: x.get("_record_id", 0))

            new_logs = []

            for log in logs:
                record_id = log.get("_record_id", 0)

                if record_id > last_record_id:
                    new_logs.append(log)

            if len(new_logs) == 0:
                print("새 Sysmon 로그 없음")

            else:
                new_logs = add_xgboost_prediction(new_logs)
                new_logs = apply_alert_policy(new_logs)

                notify_alerts(new_logs)

                success = send_logs_to_fastapi(new_logs)

                if success:
                    max_record_id = max(log.get("_record_id", 0) for log in new_logs)
                    last_record_id = max_record_id
                    save_last_record_id(last_record_id)

                    for log in new_logs:
                        print(
                            "[수집/전송] "
                            + "RecordId="
                            + str(log.get("_record_id"))
                            + " | EventID="
                            + str(log.get("event_id"))
                            + " | Process="
                            + str(log.get("process_name"))
                            + " | Risk="
                            + str(log.get("risk"))
                            + " | AI="
                            + str(log.get("ai_score"))
                            + "/"
                            + str(log.get("ai_risk"))
                            + " | Status="
                            + str(log.get("status"))
                        )

        except KeyboardInterrupt:
            print("수집기를 종료합니다.")
            break

        except Exception as e:
            print("[수집 중 오류]", e)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()