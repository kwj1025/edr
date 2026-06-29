"""
agent.py - EDR 에이전트 (사용자 PC에서 실행)
Sysmon 로그를 수집해 서버로 전송하고, 위협 탐지 시 자동 대응한다.
"""

import time
import socket
import requests

from collector.sysmon_collector import collect, apply_jonghan_policy
from response import response_by_risk

SERVER_URL   = "http://localhost:8000"
INTERVAL_SEC = 10   # 수집 주기 (초)
MAX_RECORDS  = 100  # 1회 최대 수집 건수

HOST_IP = socket.gethostbyname(socket.gethostname())


def _to_server_payload(log: dict) -> dict:
    return {
        "recv_time":        log.get("로그 수신 날짜"),
        "gen_time":         log.get("로그 생성 날짜"),
        "host_ip":          HOST_IP,
        "os_name":          log.get("운영체제"),
        "rule_level":       log.get("룰 레벨"),
        "risk":             log.get("위험도"),
        "detect_type":      log.get("탐지 유형"),
        "tactic_id":        log.get("Tactic ID"),
        "tactic_name":      log.get("Tactic Name"),
        "technique_id":     log.get("Technique ID"),
        "technique_name":   log.get("Technique Name"),
        "action_desc":      log.get("행위 내용"),
        "process_name":     log.get("프로세스"),
        "event_id":         log.get("EventID"),
        "command_line":     log.get("CommandLine"),
        "destination_ip":   log.get("DestinationIp"),
        "destination_port": log.get("DestinationPort"),
        "query_name":       log.get("QueryName"),
        "status":           log.get("상태", "신규"),
    }


def send_logs(logs: list[dict]) -> bool:
    try:
        payload = {"logs": [_to_server_payload(l) for l in logs]}
        r = requests.post(f"{SERVER_URL}/logs", json=payload, timeout=10)
        return r.status_code == 200
    except Exception:
        return False


def run_response(logs: list[dict]):
    for log in logs:
        risk = log.get("위험도", "Low")
        if risk == "Low":
            continue
        response_by_risk(
            risk_level      = risk,
            process_path    = log.get("CommandLine", "").split()[0] if log.get("CommandLine") else None,
            destination_ip  = log.get("DestinationIp") or None,
        )


def main():
    print(f"[EDR Agent] 시작 — 서버: {SERVER_URL} / 호스트: {HOST_IP}")
    while True:
        try:
            logs = collect(max_records=MAX_RECORDS)
            if logs:
                logs = apply_jonghan_policy(logs)
                ok   = send_logs(logs)
                run_response(logs)
                print(f"[{time.strftime('%H:%M:%S')}] {len(logs)}건 전송 {'성공' if ok else '실패'}")
            else:
                print(f"[{time.strftime('%H:%M:%S')}] 수집된 로그 없음")
        except Exception as e:
            print(f"[오류] {e}")

        time.sleep(INTERVAL_SEC)


if __name__ == "__main__":
    main()
