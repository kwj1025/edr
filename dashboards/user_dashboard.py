import base64
import hashlib
import json
import platform
import subprocess
import time
from datetime import datetime

import altair as alt
import pandas as pd
import requests
import streamlit as st


# ==================================================================
# 설정
# ==================================================================

API_KEY = "여기에_본인_VirusTotal_API_KEY_입력"
HEADERS = {"accept": "application/json", "x-apikey": API_KEY}

SERVER_URL = "http://localhost:8000"
TARGET_IDS_LABEL = "Event ID 1 · 3 · 5 · 22"

AUTO_REFRESH_SECONDS = 7

INITIAL_LOAD_LIMIT = 500
NEW_LOG_LIMIT = 200
DISPLAY_MAX_ROWS = 1000

MAX_ACCUM_COUNT = 10000
CHART_RESET_SECONDS = 600

ALERT_COOLDOWN_SECONDS = 180
CRITICAL_SCORE_THRESHOLD = 90.0


# ==================================================================
# 페이지 설정
# ==================================================================

st.set_page_config(
    page_title="EDR User Dashboard",
    layout="wide",
)


# ==================================================================
# Windows 알림 / 알림음
# ==================================================================

try:
    from plyer import notification
    _PLYER_OK = True
except Exception:
    notification = None
    _PLYER_OK = False


try:
    import winsound
    _WINSOUND_OK = True
except Exception:
    winsound = None
    _WINSOUND_OK = False


# ==================================================================
# 사용자 IP
# ==================================================================

def get_local_ip():
    try:
        import socket

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip

    except Exception:
        return "127.0.0.1"


LOCAL_HOST_IP = get_local_ip()


# ==================================================================
# session_state 초기화
# ==================================================================

def init_state():
    defaults = {
        "initial_loaded": False,
        "last_log_id": 0,
        "display_logs": pd.DataFrame(),
        "latest_logs": pd.DataFrame(),
        "accum_cycle_logs": pd.DataFrame(),
        "chart_cycle_logs": pd.DataFrame(),
        "alert_history": [],
        "alerted_keys": set(),
        "last_alert_time": 0.0,
        "last_refresh_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "chart_reset_time": pd.Timestamp.now(),
        "accum_reset_time": pd.Timestamp.now(),
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


init_state()


# ==================================================================
# CSS
# ==================================================================

st.markdown(
    """
<style>
@font-face {
    font-family: 'NanumSquareRound';
    src: url('https://cdn.jsdelivr.net/gh/projectnoonnu/noonfonts_two@1.0/NanumSquareRound.woff') format('woff');
}

h1,h2,h3,h4,p,label,.stMarkdown,.stText {
    font-family: 'NanumSquareRound', sans-serif !important;
}

div[data-testid="stMetricValue"] {
    font-family: 'NanumSquareRound', sans-serif !important;
    font-size: 1.6rem !important;
}

div[data-testid="stMetricLabel"] {
    font-family: 'NanumSquareRound', sans-serif !important;
    font-size: 0.8rem !important;
}

h2 {
    font-size: 1.4rem !important;
    margin-bottom: 0px !important;
}

h3 {
    font-size: 1.1rem !important;
}

h4 {
    font-size: 0.9rem !important;
}

.stApp {
    background: linear-gradient(135deg, #1e2233 0%, #0d1017 100%) !important;
}

div[data-testid="stVerticalBlockBorderWrapper"],
div[data-testid="stContainer"] {
    background-color: transparent !important;
}

[data-stale="true"], [data-stale="true"] * {
    opacity: 1 !important;
    filter: none !important;
    transition: none !important;
}

[data-testid="stAppViewContainer"],
[data-testid="stAppViewBlockContainer"],
div[data-testid="stVerticalBlock"],
.element-container,
.stChart,
canvas,
div[data-testid="stDataFrame"] {
    opacity: 1 !important;
    filter: none !important;
    transition: none !important;
}

div[data-testid="stStatusWidget"] {
    display: none !important;
}
</style>
""",
    unsafe_allow_html=True,
)


# ==================================================================
# 서버 응답 변환
# ==================================================================

def normalize_log_df(data):
    if not data:
        return pd.DataFrame()

    df = pd.DataFrame(data)

    df = df.rename(
        columns={
            "id": "ID",
            "recv_time": "로그 수신 날짜",
            "gen_time": "로그 생성 날짜",
            "host_ip": "호스트 IP 주소",
            "os_name": "운영체제",
            "rule_level": "룰 레벨",
            "risk": "위험도",
            "ai_score": "AI 위험도 점수",
            "ai_risk": "AI 위험도",
            "detect_type": "탐지 유형",
            "tactic_id": "Tactic ID",
            "tactic_name": "Tactic Name",
            "technique_id": "Technique ID",
            "technique_name": "Technique Name",
            "action_desc": "행위 내용",
            "process_name": "프로세스",
            "event_id": "EventID",
            "command_line": "CommandLine",
            "destination_ip": "DestinationIp",
            "destination_port": "DestinationPort",
            "query_name": "QueryName",
            "status": "상태",
        }
    )

    for col in ["로그 수신 날짜", "로그 생성 날짜"]:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors="coerce")

    if "ID" in df.columns:
        df["ID"] = pd.to_numeric(df["ID"], errors="coerce").fillna(0).astype(int)

    if "AI 위험도 점수" in df.columns:
        df["AI 위험도 점수"] = pd.to_numeric(df["AI 위험도 점수"], errors="coerce").fillna(0)

    return df


# ==================================================================
# 서버 로그 조회
# ==================================================================

def fetch_initial_logs():
    """
    최초 1회만 최근 로그 일부 조회.
    기존 로그는 화면 표시용으로만 쓰고,
    누적 카운터/알림에는 넣지 않는다.
    """
    try:
        response = requests.get(
            f"{SERVER_URL}/logs",
            params={
                "host": LOCAL_HOST_IP,
                "limit": INITIAL_LOAD_LIMIT,
            },
            timeout=15,
        )
        response.raise_for_status()

        df = normalize_log_df(response.json())

        if df.empty:
            return pd.DataFrame(), ""

        if "ID" in df.columns:
            df = df.sort_values("ID", ascending=False)
            st.session_state.last_log_id = int(df["ID"].max())

        return df, ""

    except Exception as e:
        return pd.DataFrame(), str(e)


def fetch_new_logs():
    """
    마지막으로 본 ID 이후 새 로그만 조회.
    """
    try:
        response = requests.get(
            f"{SERVER_URL}/logs",
            params={
                "host": LOCAL_HOST_IP,
                "after_id": int(st.session_state.last_log_id),
                "limit": NEW_LOG_LIMIT,
            },
            timeout=8,
        )
        response.raise_for_status()

        df = normalize_log_df(response.json())

        if df.empty:
            return pd.DataFrame(), ""

        if "ID" in df.columns:
            df = df.sort_values("ID", ascending=True)
            st.session_state.last_log_id = max(
                int(st.session_state.last_log_id),
                int(df["ID"].max()),
            )

        return df, ""

    except Exception as e:
        return pd.DataFrame(), str(e)


# ==================================================================
# 로그 누적 관리
# ==================================================================

def maybe_reset_chart_logs():
    now = pd.Timestamp.now()

    if (now - st.session_state.chart_reset_time).total_seconds() >= CHART_RESET_SECONDS:
        st.session_state.chart_cycle_logs = pd.DataFrame()
        st.session_state.chart_reset_time = now
        st.toast("차트 데이터가 10분 경과로 초기화되었습니다.", icon="📊")


def append_new_logs(new_df):
    if new_df is None or new_df.empty:
        st.session_state.latest_logs = pd.DataFrame()
        return

    if "ID" in new_df.columns:
        st.session_state.latest_logs = new_df.sort_values("ID", ascending=False)
    else:
        st.session_state.latest_logs = new_df

    # 화면 표시용 로그
    if st.session_state.display_logs.empty:
        st.session_state.display_logs = new_df.copy()
    else:
        st.session_state.display_logs = pd.concat(
            [new_df, st.session_state.display_logs],
            ignore_index=True,
        )

    if "ID" in st.session_state.display_logs.columns:
        st.session_state.display_logs = (
            st.session_state.display_logs
            .drop_duplicates(subset=["ID"], keep="first")
            .sort_values("ID", ascending=False)
            .head(DISPLAY_MAX_ROWS)
        )

    # 누적 로그 수
    if st.session_state.accum_cycle_logs.empty:
        st.session_state.accum_cycle_logs = new_df.copy()
    else:
        st.session_state.accum_cycle_logs = pd.concat(
            [st.session_state.accum_cycle_logs, new_df],
            ignore_index=True,
        )

    if "ID" in st.session_state.accum_cycle_logs.columns:
        st.session_state.accum_cycle_logs = st.session_state.accum_cycle_logs.drop_duplicates(
            subset=["ID"],
            keep="first",
        )

    if len(st.session_state.accum_cycle_logs) >= MAX_ACCUM_COUNT:
        st.session_state.accum_cycle_logs = pd.DataFrame(columns=new_df.columns)
        st.session_state.accum_reset_time = pd.Timestamp.now()
        st.toast("누적 로그가 10,000개에 도달하여 초기화되었습니다.", icon="🔄")

    # 차트용 로그
    maybe_reset_chart_logs()

    if st.session_state.chart_cycle_logs.empty:
        st.session_state.chart_cycle_logs = new_df.copy()
    else:
        st.session_state.chart_cycle_logs = pd.concat(
            [st.session_state.chart_cycle_logs, new_df],
            ignore_index=True,
        )

    if "ID" in st.session_state.chart_cycle_logs.columns:
        st.session_state.chart_cycle_logs = st.session_state.chart_cycle_logs.drop_duplicates(
            subset=["ID"],
            keep="first",
        )


def update_logs_from_server():
    maybe_reset_chart_logs()

    if not st.session_state.initial_loaded:
        initial_df, err = fetch_initial_logs()

        st.session_state.initial_loaded = True

        if err:
            return err

        st.session_state.display_logs = initial_df
        st.session_state.latest_logs = pd.DataFrame()
        st.session_state.accum_cycle_logs = pd.DataFrame(columns=initial_df.columns)
        st.session_state.chart_cycle_logs = pd.DataFrame(columns=initial_df.columns)

        return ""

    new_df, err = fetch_new_logs()

    if err:
        return err

    append_new_logs(new_df)
    handle_critical_alerts(new_df)

    return ""


# ==================================================================
# 위험도 / 알림
# ==================================================================

def get_ai_score(row):
    try:
        return float(row.get("AI 위험도 점수") or 0)
    except Exception:
        return 0.0


def is_critical_alert_log(row):
    ai_risk = str(row.get("AI 위험도", ""))
    ai_score = get_ai_score(row)

    return ai_risk == "Critical" and ai_score >= CRITICAL_SCORE_THRESHOLD


def make_log_key(row):
    if "ID" in row:
        return str(row.get("ID"))

    values = [
        str(row.get("로그 수신 날짜", "")),
        str(row.get("로그 생성 날짜", "")),
        str(row.get("EventID", "")),
        str(row.get("프로세스", "")),
        str(row.get("행위 내용", "")),
    ]

    return "|".join(values)


def handle_critical_alerts(new_df):
    if new_df is None or new_df.empty:
        return

    critical_df = new_df[new_df.apply(is_critical_alert_log, axis=1)]

    if critical_df.empty:
        return

    new_critical_rows = []

    for _, row in critical_df.iterrows():
        key = make_log_key(row)

        if key in st.session_state.alerted_keys:
            continue

        st.session_state.alerted_keys.add(key)

        alert_item = {
            "시간": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ID": row.get("ID", ""),
            "로그 수신 날짜": str(row.get("로그 수신 날짜", "")),
            "위험도": row.get("위험도", ""),
            "AI 위험도 점수": row.get("AI 위험도 점수", ""),
            "AI 위험도": row.get("AI 위험도", ""),
            "탐지 유형": row.get("탐지 유형", ""),
            "EventID": row.get("EventID", ""),
            "프로세스": row.get("프로세스", ""),
            "행위 내용": row.get("행위 내용", ""),
            "상태": row.get("상태", ""),
        }

        st.session_state.alert_history.insert(0, alert_item)
        new_critical_rows.append(alert_item)

    if not new_critical_rows:
        return

    current_time = time.time()

    # 3분 안에는 알림창/소리 반복 실행하지 않음
    if (current_time - st.session_state.last_alert_time) < ALERT_COOLDOWN_SECONDS:
        return

    latest_alert = new_critical_rows[0]

    message = (
        "프로세스: "
        + str(latest_alert.get("프로세스", "알 수 없음"))
        + " / AI 점수: "
        + str(latest_alert.get("AI 위험도 점수", ""))
        + " / AI 위험도: "
        + str(latest_alert.get("AI 위험도", "Critical"))
    )

    # Streamlit 화면 오른쪽 아래 알림
    st.toast(
        "🚨 Critical 위협 감지! " + message,
        icon="🚨",
    )

    # Windows 바탕화면 오른쪽 아래 알림
    if _PLYER_OK:
        try:
            notification.notify(
                title="[EDR Critical 경보]",
                message=message,
                app_name="EDR 실시간 모니터링",
                timeout=7,
            )
        except Exception:
            pass

    # 알림음
    if _WINSOUND_OK:
        try:
            winsound.MessageBeep(winsound.MB_ICONHAND)
        except Exception:
            pass

    st.session_state.last_alert_time = current_time


def get_alert_history_df():
    history_df = pd.DataFrame(st.session_state.alert_history)

    db_df = st.session_state.display_logs

    if db_df is not None and not db_df.empty:
        temp_df = db_df.copy()

        alert_mask = pd.Series(False, index=temp_df.index)

        if "상태" in temp_df.columns:
            alert_mask = alert_mask | (temp_df["상태"] == "알림")

        if "AI 위험도" in temp_df.columns and "AI 위험도 점수" in temp_df.columns:
            score_series = pd.to_numeric(temp_df["AI 위험도 점수"], errors="coerce").fillna(0)
            alert_mask = alert_mask | (
                (temp_df["AI 위험도"] == "Critical")
                & (score_series >= CRITICAL_SCORE_THRESHOLD)
            )

        db_alert_df = temp_df[alert_mask].copy()

        cols = [
            "ID",
            "로그 수신 날짜",
            "위험도",
            "AI 위험도 점수",
            "AI 위험도",
            "탐지 유형",
            "EventID",
            "프로세스",
            "행위 내용",
            "상태",
        ]

        db_alert_df = db_alert_df[[c for c in cols if c in db_alert_df.columns]]

        if history_df.empty:
            result = db_alert_df
        else:
            result = pd.concat([history_df, db_alert_df], ignore_index=True)
    else:
        result = history_df

    if result.empty:
        return result

    if "ID" in result.columns:
        result = result.drop_duplicates(subset=["ID"], keep="first")

    return result


# ==================================================================
# Fileless 공격 탐지
# ==================================================================

def send_rows_to_server(rows):
    if not rows:
        return 0, ""

    try:
        response = requests.post(
            f"{SERVER_URL}/logs",
            json={"logs": rows},
            timeout=10,
        )
        response.raise_for_status()

        result = response.json()
        return result.get("저장된 건수", len(rows)), ""

    except Exception as e:
        return 0, str(e)


def run_powershell_fileless_scan(max_records=100):
    ps_script = """
$events = Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents """ + str(max_records) + """ -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -eq 4104 }

$result = @()

foreach ($e in $events) {
    $msg = $e.Message

    if (
        $msg -match "EncodedCommand" -or
        $msg -match "-enc" -or
        $msg -match "IEX" -or
        $msg -match "Invoke-Expression" -or
        $msg -match "DownloadString" -or
        $msg -match "Net.WebClient" -or
        $msg -match "FromBase64String" -or
        $msg -match "Invoke-WebRequest" -or
        $msg -match "Start-Process" -or
        $msg -match "Bypass"
    ) {
        $result += [PSCustomObject]@{
            Id = $e.Id
            RecordId = $e.RecordId
            TimeCreated = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            Message = $msg
        }
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
            return [], result.stderr

        output = result.stdout.strip()

        if output == "":
            return [], ""

        data = json.loads(output)

        if isinstance(data, dict):
            data = [data]

        if not isinstance(data, list):
            return [], ""

        return data, ""

    except Exception as e:
        return [], str(e)


def collect_fileless_threats():
    if platform.system() != "Windows":
        return 0, 0, "Windows 환경에서만 Fileless 탐지가 가능합니다."

    events, err = run_powershell_fileless_scan(max_records=100)

    if err:
        return 0, 0, err

    if not events:
        return 0, 0, ""

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    host_ip = LOCAL_HOST_IP
    os_name = platform.platform()

    rows_for_server = []

    for event in events:
        msg = str(event.get("Message", ""))
        gen_time = event.get("TimeCreated", now_str)
        short_msg = msg.replace("\n", " ")[:200]

        row = {
            "recv_time": now_str,
            "gen_time": gen_time,
            "host_ip": host_ip,
            "os_name": os_name,
            "rule_level": "중요",
            "risk": "High",
            "ai_risk": "Critical",
            "ai_score": 95.0,
            "detect_type": "Fileless 공격 탐지",
            "tactic_id": "TA0002",
            "tactic_name": "Execution",
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "action_desc": "[ALERT] Fileless 의심 PowerShell 스크립트 탐지 | " + short_msg,
            "process_name": "powershell.exe",
            "event_id": 4104,
            "command_line": short_msg,
            "destination_ip": "",
            "destination_port": "",
            "query_name": "",
            "status": "알림",
        }

        rows_for_server.append(row)

    sent, send_err = send_rows_to_server(rows_for_server)

    if send_err:
        return len(rows_for_server), sent, send_err

    return len(rows_for_server), sent, ""


# ==================================================================
# VirusTotal
# ==================================================================

def _fmt(stats, results):
    return {"stats": stats, "results": results}


def analyze_file_vt(uploaded_file):
    if API_KEY == "여기에_본인_VirusTotal_API_KEY_입력":
        st.warning("VirusTotal API_KEY를 먼저 입력해야 합니다.")
        return None

    data = uploaded_file.getvalue()
    h = hashlib.sha256(data).hexdigest()

    res = requests.get(
        f"https://www.virustotal.com/api/v3/files/{h}",
        headers=HEADERS,
        timeout=15,
    )

    if res.status_code == 200:
        d = res.json()["data"]["attributes"]
        return _fmt(d["last_analysis_stats"], d["last_analysis_results"])

    if res.status_code == 404:
        up = requests.post(
            "https://www.virustotal.com/api/v3/files",
            headers=HEADERS,
            files={"file": (uploaded_file.name, data)},
            timeout=30,
        )

        if up.status_code == 200:
            return _wait_vt(up.json()["data"]["id"])

    return None


def analyze_url_vt(target_url):
    if API_KEY == "여기에_본인_VirusTotal_API_KEY_입력":
        st.warning("VirusTotal API_KEY를 먼저 입력해야 합니다.")
        return None

    uid = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")

    res = requests.get(
        f"https://www.virustotal.com/api/v3/urls/{uid}",
        headers=HEADERS,
        timeout=15,
    )

    if res.status_code == 200:
        d = res.json()["data"]["attributes"]
        return _fmt(d["last_analysis_stats"], d["last_analysis_results"])

    if res.status_code == 404:
        pr = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=HEADERS,
            data={"url": target_url},
            timeout=15,
        )

        if pr.status_code == 200:
            return _wait_vt(pr.json()["data"]["id"])

    return None


def _wait_vt(analysis_id):
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

    with st.status("검사를 진행 중입니다...", expanded=True) as s:
        for _ in range(12):
            res = requests.get(url, headers=HEADERS, timeout=15)

            if res.status_code == 200:
                d = res.json()["data"]["attributes"]

                if d["status"] == "completed":
                    s.update(label="검사 완료", state="complete", expanded=False)
                    return _fmt(d["stats"], d["results"])

            time.sleep(10)

    return None


def render_vt_results(vt_data):
    stats = vt_data["stats"]
    malicious = stats.get("malicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    suspicious = stats.get("suspicious", 0)

    total = malicious + harmless + undetected + suspicious

    if malicious > 0:
        st.error(f"[위험] {total}개 중 {malicious}개 악성 탐지")
    else:
        st.success("[안전] 악성 내역 없음")

    rows = []

    for engine, detail in vt_data["results"].items():
        cat = detail.get("category", "undetected")

        label, order = {
            "malicious": ("악성", 1),
            "suspicious": ("의심", 2),
            "harmless": ("정상", 3),
        }.get(cat, ("미탐지", 4))

        rows.append(
            {
                "엔진": engine,
                "결과": label,
                "진단명": detail.get("result", ""),
                "_s": order,
            }
        )

    df = pd.DataFrame(rows).sort_values("_s").drop(columns=["_s"])

    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
        height=200,
    )


# ==================================================================
# 통계
# ==================================================================

def _calc_stats(df):
    if df is None or df.empty:
        return {
            "total": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "critical": 0,
            "alert": 0,
        }

    total = len(df)

    risk_col = "위험도" if "위험도" in df.columns else None
    ai_col = "AI 위험도" if "AI 위험도" in df.columns else None
    score_col = "AI 위험도 점수" if "AI 위험도 점수" in df.columns else None
    status_col = "상태" if "상태" in df.columns else None

    high_cnt = len(df[df[risk_col].isin(["H", "High", "높음"])]) if risk_col else 0
    med_cnt = len(df[df[risk_col].isin(["M", "Medium", "중간"])]) if risk_col else 0
    low_cnt = len(df[df[risk_col].isin(["L", "Low", "정상", "일반", "낮음"])]) if risk_col else 0
    alert_cnt = len(df[df[status_col] == "알림"]) if status_col else 0

    critical_cnt = 0

    if ai_col and score_col:
        score_series = pd.to_numeric(df[score_col], errors="coerce").fillna(0)
        critical_cnt = len(
            df[
                (df[ai_col] == "Critical")
                & (score_series >= CRITICAL_SCORE_THRESHOLD)
            ]
        )

    return {
        "total": total,
        "high": high_cnt,
        "medium": med_cnt,
        "low": low_cnt,
        "critical": critical_cnt,
        "alert": alert_cnt,
    }


# ==================================================================
# 알람 내역 팝업
# ==================================================================

@st.dialog("알람 발생 내역", width="large")
def show_alarm_history():
    alert_df = get_alert_history_df()

    if alert_df.empty:
        st.info("현재 표시 가능한 알람 내역이 없습니다.")
        return

    st.warning(f"알람 내역 {len(alert_df)}건")

    st.dataframe(
        alert_df,
        use_container_width=True,
        height=450,
        hide_index=True,
    )


# ==================================================================
# 상단 헤더
# ==================================================================

top_col1, top_col2, top_col3 = st.columns([3, 4, 3])

with top_col1:
    st.markdown("## EDR Analyzer (사용자)")

with top_col2:
    range_label = st.segmented_control(
        "조회 범위",
        ["최근 24시간", "최근 7일", "최근 14일", "최근 30일"],
        default="최근 24시간",
        label_visibility="collapsed",
    )

with top_col3:
    time_col, refresh_col = st.columns([5, 1])

    with time_col:
        st.html(
            """
        <div style="text-align:right;font-family:'NanumSquareRound',sans-serif;
                    color:#f3f4f6;padding-top:5px;">
          <span id="clock" style="font-size:0.95rem;font-weight:bold;
                text-shadow:0 1px 2px rgba(0,0,0,0.5);"></span>
        </div>
        <script>
        function updateClock(){
            const n=new Date();
            document.getElementById('clock').innerText=
                n.getFullYear()+'-'+String(n.getMonth()+1).padStart(2,'0')+'-'+
                String(n.getDate()).padStart(2,'0')+' '+
                String(n.getHours()).padStart(2,'0')+':'+
                String(n.getMinutes()).padStart(2,'0')+':'+
                String(n.getSeconds()).padStart(2,'0');
        }
        setInterval(updateClock,1000); updateClock();
        </script>
        """
        )

    with refresh_col:
        if st.button("↻", type="tertiary", help="데이터 새로고침"):
            st.session_state.last_refresh_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            st.rerun()

st.markdown("---")


# ==================================================================
# 서버 로그 갱신
# ==================================================================

load_err = update_logs_from_server()

display_df = st.session_state.display_logs.copy()

if not display_df.empty and "로그 수신 날짜" in display_df.columns:
    now = pd.Timestamp.now()

    if range_label == "최근 24시간":
        start = now - pd.Timedelta(days=1)
    elif range_label == "최근 7일":
        start = now - pd.Timedelta(days=7)
    elif range_label == "최근 14일":
        start = now - pd.Timedelta(days=14)
    else:
        start = now - pd.Timedelta(days=30)

    display_df = display_df[display_df["로그 수신 날짜"] >= start]


latest_stats = _calc_stats(st.session_state.latest_logs)
accum_stats = _calc_stats(st.session_state.accum_cycle_logs)
chart_stats = _calc_stats(st.session_state.chart_cycle_logs)


# ==================================================================
# 중앙 레이아웃
# ==================================================================

row1_col1, row1_col2 = st.columns([3, 7])

with row1_col1:
    with st.container(border=True):
        st.markdown("### 실시간 로그 수 (현재)")

        color_rt = "#ef4444" if latest_stats["critical"] > 0 or latest_stats["alert"] > 0 else "#10b981"

        st.markdown(
            f"<h1 style='color:{color_rt};font-size:2.0rem;margin-top:-10px;'>"
            f"{latest_stats['total']}</h1>",
            unsafe_allow_html=True,
        )

        c1, c2, c3 = st.columns(3)
        c1.metric("위험", latest_stats["high"])
        c2.metric("의심", latest_stats["medium"])
        c3.metric("정상", latest_stats["low"])

        st.markdown("---")

        st.markdown("### 누적된 로그 수")

        color_ac = "#ef4444" if accum_stats["critical"] > 0 or accum_stats["alert"] > 0 else "#10b981"

        st.markdown(
            f"<h1 style='color:{color_ac};font-size:2.0rem;margin-top:-10px;'>"
            f"{accum_stats['total']}</h1>",
            unsafe_allow_html=True,
        )

        c4, c5, c6 = st.columns(3)
        c4.metric("위험", accum_stats["high"])
        c5.metric("의심", accum_stats["medium"])
        c6.metric("정상", accum_stats["low"])

        st.caption(f"{MAX_ACCUM_COUNT:,}개 도달 시 자동 초기화")

        st.markdown("---")

        if st.button("알람 내역 보기", use_container_width=True):
            show_alarm_history()

with row1_col2:
    with st.container(border=True):
        st.markdown("### 최근 탐지 위협")

        if load_err:
            st.error(f"FastAPI 서버 연결 실패: {load_err}")

        elif not display_df.empty:
            display_cols = [
                c for c in [
                    "ID",
                    "로그 수신 날짜",
                    "위험도",
                    "AI 위험도 점수",
                    "AI 위험도",
                    "탐지 유형",
                    "EventID",
                    "Tactic ID",
                    "Technique Name",
                    "프로세스",
                    "행위 내용",
                    "상태",
                ]
                if c in display_df.columns
            ]

            table_df = display_df[display_cols].copy()

            if "ID" in table_df.columns:
                table_df = table_df.sort_values("ID", ascending=False)

            st.dataframe(
                table_df.head(100),
                use_container_width=True,
                hide_index=True,
                height=350,
            )

        else:
            st.info("수집된 로그가 없습니다. Sysmon 로그 수집 Agent를 실행하세요.")

        st.markdown("---")

        realtime_mode = st.toggle(
            "🔴 실시간 위협 감시 모드 (Agent 작동)",
            value=False,
        )

        if realtime_mode:
            st.success("Agent 작동 상태: 새 로그만 자동 조회 중")
        else:
            st.caption("Agent 작동 대기 중")

        st.caption("⚠️ Windows + Sysmon Agent 필요")

        st.markdown("---")

        if st.button(
            "🛡️ Fileless 공격 탐지 (PowerShell)",
            use_container_width=True,
            help="PowerShell Script Block Logging Event ID 4104 기반 Fileless 의심 행위 탐지",
        ):
            with st.spinner("Fileless 위협 탐지 중..."):
                collected, sent, err = collect_fileless_threats()

            if collected == 0:
                if err:
                    st.error(f"오류: {err}")
                else:
                    st.info("의심 Fileless 활동이 감지되지 않았습니다.")
            else:
                if err:
                    st.warning(f"{collected}건 탐지됨, 서버 전송 실패: {err}")
                else:
                    st.success(f"{sent}건 Fileless 위협 탐지 → 서버 전송 완료")
                    st.rerun()

        st.caption(f"수집 대상: {TARGET_IDS_LABEL}")


# ==================================================================
# 하단 레이아웃
# ==================================================================

row2_col1, row2_col2, row2_col3 = st.columns([3, 3, 4])

with row2_col1:
    with st.container(border=True):
        st.markdown("### 위험도별 현황")
        st.caption("차트 데이터는 10분마다 자동 초기화됩니다.")

        chart_df = st.session_state.chart_cycle_logs

        if not chart_df.empty and "위험도" in chart_df.columns:
            risk_df = chart_df["위험도"].fillna("Unknown").value_counts().reset_index()
            risk_df.columns = ["위험도", "건수"]

            risk_label_map = {
                "High": "높음",
                "Medium": "중간",
                "Low": "낮음",
                "Unknown": "미확인",
            }

            risk_df["위험도"] = risk_df["위험도"].map(risk_label_map).fillna(risk_df["위험도"])

            chart = (
                alt.Chart(risk_df)
                .mark_arc(innerRadius=40)
                .encode(
                    theta=alt.Theta("건수:Q", title="건수"),
                    color=alt.Color(
                        "위험도:N",
                        scale=alt.Scale(
                            domain=["높음", "중간", "낮음", "미확인"],
                            range=["#ef4444", "#f59e0b", "#3b82f6", "#6b7280"],
                        ),
                    ),
                    tooltip=["위험도", "건수"],
                )
                .properties(
                    height=220,
                    background="transparent",
                )
                .configure_view(strokeOpacity=0)
            )

            st.altair_chart(chart, use_container_width=True, theme=None)

        else:
            st.write("데이터가 없습니다.")

with row2_col2:
    with st.container(border=True):
        st.markdown("### 탐지 유형별 현황")
        st.caption("차트 데이터는 10분마다 자동 초기화됩니다.")

        chart_df = st.session_state.chart_cycle_logs

        if not chart_df.empty and "탐지 유형" in chart_df.columns:
            type_df = chart_df["탐지 유형"].fillna("기타").value_counts().reset_index()
            type_df.columns = ["유형", "건수"]

            chart = (
                alt.Chart(type_df)
                .mark_bar()
                .encode(
                    x=alt.X(
                        "건수:Q",
                        title="건수",
                        axis=alt.Axis(labelAngle=0),
                    ),
                    y=alt.Y(
                        "유형:N",
                        sort="-x",
                        title=None,
                        axis=alt.Axis(labelAngle=0),
                    ),
                    color=alt.Color("유형:N", legend=None),
                    tooltip=["유형", "건수"],
                )
                .properties(
                    height=220,
                    background="transparent",
                )
                .configure_view(strokeOpacity=0)
            )

            st.altair_chart(chart, use_container_width=True, theme=None)

        else:
            st.write("데이터가 없습니다.")

with row2_col3:
    with st.container(border=True):
        st.markdown("### 실시간 정밀 검사 (VirusTotal)")

        t1, t2 = st.tabs(["파일 업로드 검사", "URL 링크 검사"])

        with t1:
            f = st.file_uploader("검사할 파일 선택", label_visibility="collapsed")

            if f and st.button("정밀 분석 시작", key="f_btn", use_container_width=True):
                vt = analyze_file_vt(f)

                if vt:
                    render_vt_results(vt)
                else:
                    st.error("분석 중 에러가 발생했습니다.")

        with t2:
            u = st.text_input(
                "검사할 URL 입력",
                placeholder="https://example.com",
                label_visibility="collapsed",
            )

            if u and st.button("링크 분석 시작", key="u_btn", use_container_width=True):
                vt = analyze_url_vt(u)

                if vt:
                    render_vt_results(vt)
                else:
                    st.error("분석 중 에러가 발생했습니다.")


# ==================================================================
# 사이드바
# ==================================================================

st.sidebar.title("사용자 대시보드 설정")
st.sidebar.write("FastAPI 서버:", SERVER_URL)
st.sidebar.write("현재 사용자 IP:", LOCAL_HOST_IP)
st.sidebar.write("마지막 새로고침:", st.session_state.last_refresh_time)
st.sidebar.write("마지막 조회 ID:", st.session_state.last_log_id)
st.sidebar.write("초기 조회 개수:", f"{INITIAL_LOAD_LIMIT:,}개")
st.sidebar.write("새 로그 조회 개수:", f"{NEW_LOG_LIMIT:,}개")
st.sidebar.write("누적 로그 초기화 기준:", f"{MAX_ACCUM_COUNT:,}개")
st.sidebar.write("차트 초기화 주기:", "10분")
st.sidebar.write("Critical 알림 기준:", f"AI 점수 {CRITICAL_SCORE_THRESHOLD:.0f}점 이상 + Critical")
st.sidebar.write("알림 반복 제한:", "3분")


# ==================================================================
# 자동 새로고침
# ==================================================================

if realtime_mode:
    time.sleep(AUTO_REFRESH_SECONDS)
    st.session_state.last_refresh_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.rerun()