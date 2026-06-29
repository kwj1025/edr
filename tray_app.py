"""
tray_app.py - EDR 시스템 트레이 앱
트레이 아이콘으로 에이전트 시작/중지, 대시보드 열기를 제공한다.
"""

import threading
import subprocess
import shutil
import tempfile
import webbrowser
import time
import socket
import sys
import os
import tkinter as tk
from tkinter import simpledialog

import pystray
from PIL import Image, ImageDraw
import requests

from collector.sysmon_collector import collect, apply_jonghan_policy
from response import response_by_risk

def _ask_server_ip() -> str:
    root = tk.Tk()
    root.withdraw()
    ip = simpledialog.askstring(
        "서버 연결",
        "서버 IP 주소를 입력하세요:\n(예: 192.168.0.10)",
    )
    root.destroy()
    if not ip or not ip.strip():
        sys.exit(0)
    return ip.strip()

SERVER_URL      = f"http://{_ask_server_ip()}:8000"
DASHBOARD_PORT  = 8500
INTERVAL_SEC    = 10
MAX_RECORDS     = 100
HOST_IP         = socket.gethostbyname(socket.gethostname())

_agent_running     = False
_agent_thread      = None
_dashboard_started = False



# ── 아이콘 생성 (파란 방패 모양) ─────────────────────────────────────
def _make_icon(active: bool) -> Image.Image:
    size  = 64
    img   = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw  = ImageDraw.Draw(img)
    color = (0, 120, 215) if active else (120, 120, 120)
    # 방패 외곽
    draw.polygon(
        [(size//2, 4), (size-6, 16), (size-6, 38), (size//2, 60), (6, 38), (6, 16)],
        fill=color,
    )
    # 가운데 흰 글자 E
    draw.text((22, 20), "E", fill="white")
    return img


# ── 에이전트 루프 ─────────────────────────────────────────────────────
def _to_payload(log: dict) -> dict:
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


def _agent_loop():
    global _agent_running
    while _agent_running:
        try:
            logs = collect(max_records=MAX_RECORDS)
            if logs:
                logs = apply_jonghan_policy(logs)
                requests.post(
                    f"{SERVER_URL}/logs",
                    json={"logs": [_to_payload(l) for l in logs]},
                    timeout=10,
                )
                for log in logs:
                    risk = log.get("위험도", "Low")
                    if risk != "Low":
                        response_by_risk(
                            risk_level     = risk,
                            process_path   = (log.get("CommandLine") or "").split()[0] or None,
                            destination_ip = log.get("DestinationIp") or None,
                        )
        except Exception:
            pass
        time.sleep(INTERVAL_SEC)


# ── 트레이 메뉴 콜백 ─────────────────────────────────────────────────
def _start_agent(icon, item):
    global _agent_running, _agent_thread
    if _agent_running:
        return
    _agent_running = True
    _agent_thread  = threading.Thread(target=_agent_loop, daemon=True)
    _agent_thread.start()
    icon.icon  = _make_icon(True)
    icon.title = "EDR Agent — 실행 중"
    _update_menu(icon)


def _stop_agent(icon, item):
    global _agent_running
    _agent_running = False
    icon.icon  = _make_icon(False)
    icon.title = "EDR Agent — 중지됨"
    _update_menu(icon)


def _open_dashboard(icon, item):
    global _dashboard_started

    if not _dashboard_started:
        if getattr(sys, "frozen", False):
            # exe 실행 시: dashboards + collector를 임시폴더에 꺼내고 시스템 Python으로 실행
            root_dst = os.path.join(tempfile.gettempdir(), "edr_root")
            if os.path.exists(root_dst):
                shutil.rmtree(root_dst)
            os.makedirs(root_dst)
            shutil.copytree(os.path.join(sys._MEIPASS, "dashboards"),
                            os.path.join(root_dst, "dashboards"))
            shutil.copytree(os.path.join(sys._MEIPASS, "collector"),
                            os.path.join(root_dst, "collector"))
            dashboard = os.path.join(root_dst, "dashboards", "user_dashboard.py")
            python = shutil.which("python") or shutil.which("python3") or "python"
        else:
            base = os.path.dirname(os.path.abspath(__file__))
            dashboard = os.path.join(base, "dashboards", "user_dashboard.py")
            python = sys.executable

        # 별도 프로세스로 실행 (스레드에서 실행 시 signal 핸들러 오류 발생)
        subprocess.Popen(
            [python, "-m", "streamlit", "run", dashboard,
             "--server.port", str(DASHBOARD_PORT),
             "--server.headless", "true"],
            creationflags=subprocess.CREATE_NO_WINDOW,
        )

        _dashboard_started = True
        time.sleep(2)

    webbrowser.open(f"http://localhost:{DASHBOARD_PORT}")


def _quit_app(icon, item):
    global _agent_running
    _agent_running = False
    icon.stop()


def _update_menu(icon):
    icon.menu = pystray.Menu(
        pystray.MenuItem(
            "에이전트 시작",
            _start_agent,
            enabled=lambda item: not _agent_running,
        ),
        pystray.MenuItem(
            "에이전트 중지",
            _stop_agent,
            enabled=lambda item: _agent_running,
        ),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("대시보드 열기", _open_dashboard),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("종료", _quit_app),
    )


# ── Sysmon 시작 ──────────────────────────────────────────────────────
def _start_sysmon():
    try:
        subprocess.run(
            ["sc", "start", "Sysmon64"],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except Exception:
        pass


# ── 진입점 ────────────────────────────────────────────────────────────
def main():
    _start_sysmon()
    icon = pystray.Icon(
        name  = "EDR Agent",
        icon  = _make_icon(False),
        title = "EDR Agent — 중지됨",
    )
    _update_menu(icon)
    icon.run()


def _require_admin():
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit(0)

if __name__ == "__main__":
    _require_admin()
    main()
