"""
서버에서 수집된 Sysmon 로그를 Dataset 형식으로 변환
normal: risk=L  → label 0
malicious: risk=M or H → label 1
"""
import requests
import json
import os

SERVER_URL = "http://localhost:8000"
OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))


def fetch_logs(limit: int = 10000) -> list[dict]:
    res = requests.get(f"{SERVER_URL}/logs?limit={limit}", timeout=10)
    res.raise_for_status()
    return res.json()


def convert(log: dict, idx: int) -> dict:
    risk = (log.get("risk") or "Low").lower()
    label = 0 if risk == "low" else 1
    return {
        "record_id": idx,
        "time_created": log.get("gen_time"),
        "event_id": log.get("event_id"),
        "provider_name": "Microsoft-Windows-Sysmon",
        "process_name": log.get("process_name"),
        "command_line": log.get("command_line"),
        "parent_process": None,
        "destination_ip": log.get("destination_ip"),
        "destination_port": log.get("destination_port"),
        "query_name": log.get("query_name"),
        "process_guid": None,
        "parent_process_guid": None,
        "process_id": None,
        "parent_process_id": None,
        "source_dataset": "collected",
        "source_file": f"live_collection/{log.get('host_ip')}",
        "label": label,
        "process_group_no": None,
        "process_event_order": None,
    }


def main():
    print("서버에서 로그 가져오는 중...")
    logs = fetch_logs()
    print(f"총 {len(logs)}건 수집됨")

    normal = []
    malicious = []

    for i, log in enumerate(logs):
        converted = convert(log, i)
        if converted["label"] == 0:
            normal.append(converted)
        else:
            malicious.append(converted)

    print(f"정상: {len(normal)}건 / 악성: {len(malicious)}건")

    normal_path    = os.path.join(OUTPUT_DIR, "collected_normal.json")
    malicious_path = os.path.join(OUTPUT_DIR, "collected_malicious.json")

    with open(normal_path, "w", encoding="utf-8") as f:
        json.dump(normal, f, ensure_ascii=False, indent=2, default=str)
    with open(malicious_path, "w", encoding="utf-8") as f:
        json.dump(malicious, f, ensure_ascii=False, indent=2, default=str)

    print(f"저장 완료:\n  {normal_path}\n  {malicious_path}")


if __name__ == "__main__":
    main()
