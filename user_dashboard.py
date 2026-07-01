import streamlit as st
import pandas as pd
import altair as alt
import requests
import subprocess
import json
import time
import platform
from datetime import datetime


# ============================================================
# 설정
# ============================================================

SERVER_URL = "http://127.0.0.1:8000"
AUTO_REFRESH_SECONDS = 5


st.set_page_config(
    page_title="EDR User Dashboard",
    layout="wide",
)


# ============================================================
# CSS
# ============================================================

st.markdown(
    """
<style>
    .stApp {
        background-color: #111827;
        color: #f9fafb;
    }

    div[data-testid="stMetric"] {
        background-color: #111827;
        border-radius: 10px;
    }

    .main-card {
        border: 1px solid #374151;
        border-radius: 10px;
        padding: 18px;
        background-color: #111827;
    }

    .info-box {
        background-color: #1e3a5f;
        color: #38bdf8;
        padding: 14px;
        border-radius: 8px;
        margin-bottom: 12px;
    }

    .warn-box {
        background-color: #4c1d1d;
        color: #f87171;
        padding: 14px;
        border-radius: 8px;
        margin-bottom: 12px;
    }

    .ok-box {
        background-color: #064e3b;
        color: #6ee7b7;
        padding: 14px;
        border-radius: 8px;
        margin-bottom: 12px;
    }
</style>
""",
    unsafe_allow_html=True,
)


# ============================================================
# 데이터 로드
# ============================================================

def load_logs_from_server(limit=1000):
    try:
        response = requests.get(f"{SERVER_URL}/logs?limit={limit}", timeout=5)
        response.raise_for_status()

        data = response.json()

        if not data:
            return pd.DataFrame(), ""

        df = pd.DataFrame(data)

        df = df.rename(
            columns={
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

        return df, ""

    except Exception as e:
        return pd.DataFrame(), str(e)


def send_rows_to_server(rows):
    if not rows:
        return 0, ""

    try:
        payload = {"logs": rows}
        response = requests.post(f"{SERVER_URL}/logs", json=payload, timeout=10)
        response.raise_for_status()

        result = response.json()
        return result.get("저장된 건수", len(rows)), ""

    except Exception as e:
        return 0, str(e)


# ============================================================
# Fileless 탐지
# ============================================================

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


def run_powershell_fileless_scan(max_records=100):
    """
    PowerShell Script Block Logging Event ID 4104 기반 Fileless 의심 행위 탐지.
    4104 로그가 없으면 빈 리스트가 나올 수 있음.
    """
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
    host_ip = get_local_ip()
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
            "ai_risk": "High",
            "ai_score": 90.0,
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


# ============================================================
# 통계 계산
# ============================================================

def calc_stats(df):
    if df.empty:
        return {
            "total": 0,
            "new": 0,
            "checking": 0,
            "hold": 0,
            "done": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "alert": 0,
        }

    status_col = "상태" if "상태" in df.columns else None
    risk_col = "위험도" if "위험도" in df.columns else None

    return {
        "total": len(df),
        "new": len(df[df[status_col] == "신규"]) if status_col else 0,
        "checking": len(df[df[status_col] == "의심"]) if status_col else 0,
        "hold": len(df[df[status_col] == "보류"]) if status_col else 0,
        "done": len(df[df[status_col] == "확인 완료"]) if status_col else 0,
        "high": len(df[df[risk_col] == "High"]) if risk_col else 0,
        "medium": len(df[df[risk_col] == "Medium"]) if risk_col else 0,
        "low": len(df[df[risk_col] == "Low"]) if risk_col else 0,
        "alert": len(df[df[status_col] == "알림"]) if status_col else 0,
    }


def filter_by_range(df, range_label):
    if df.empty or "로그 수신 날짜" not in df.columns:
        return df

    now = pd.Timestamp.now()

    if range_label == "최근 24시간":
        start = now - pd.Timedelta(days=1)
    elif range_label == "최근 7일":
        start = now - pd.Timedelta(days=7)
    elif range_label == "최근 14일":
        start = now - pd.Timedelta(days=14)
    else:
        start = now - pd.Timedelta(days=30)

    return df[df["로그 수신 날짜"] >= start]


# ============================================================
# 세션 상태
# ============================================================

if "auto_refresh" not in st.session_state:
    st.session_state.auto_refresh = True

if "last_refresh_time" not in st.session_state:
    st.session_state.last_refresh_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ============================================================
# 상단 헤더
# ============================================================

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
    refresh_col1, refresh_col2 = st.columns([4, 1])

    with refresh_col1:
        st.caption("마지막 새로고침")
        st.write(st.session_state.last_refresh_time)

    with refresh_col2:
        if st.button("↻", type="tertiary", help="데이터 새로고침"):
            st.session_state.last_refresh_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            st.rerun()


st.markdown("---")


# ============================================================
# 로그 불러오기
# ============================================================

raw_df, load_err = load_logs_from_server(limit=2000)

if not raw_df.empty:
    log_df = filter_by_range(raw_df, range_label)
else:
    log_df = raw_df

stats = calc_stats(log_df)


# ============================================================
# 중앙 레이아웃
# ============================================================

row1_col1, row1_col2 = st.columns([3, 7])

with row1_col1:
    with st.container(border=True):
        st.markdown("### 위험 현황")

        color = "#ef4444" if stats["alert"] > 0 else "#10b981"

        st.markdown(
            f"""
            <div style="font-size: 42px; font-weight: 800; color: {color};">
                {stats["alert"]}
            </div>
            """,
            unsafe_allow_html=True,
        )

        c1, c2 = st.columns(2)

        c1.metric("신규", stats["new"])
        c2.metric("의심", stats["checking"])
        c1.metric("High", stats["high"])
        c2.metric("Medium", stats["medium"])

        st.caption("실시간 수집기는 별도 터미널에서 자동 실행됩니다.")

with row1_col2:
    with st.container(border=True):
        st.markdown("### 최근 탐지 위협")

        if load_err:
            st.error(f"FastAPI 서버 연결 실패: {load_err}")

        elif not log_df.empty:
            display_cols = [
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

            display_cols = [c for c in display_cols if c in log_df.columns]

            display_df = log_df[display_cols].copy()

            if "로그 수신 날짜" in display_df.columns:
                display_df = display_df.sort_values("로그 수신 날짜", ascending=False)

            display_df = display_df.head(10)

            st.dataframe(
                display_df,
                use_container_width=True,
                hide_index=True,
                height=len(display_df) * 35 + 38,
            )

        else:
            st.info("수집된 로그가 없습니다. 실시간 수집기를 실행하면 자동으로 표시됩니다.")

        st.markdown(
            """
            <div class="ok-box">
                ✅ Sysmon 로그는 실시간 수집기가 자동으로 FastAPI 서버에 전송합니다.
                버튼을 누르지 않아도 새 로그가 DB에 저장되면 이 화면에 표시됩니다.
            </div>
            """,
            unsafe_allow_html=True,
        )

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


# ============================================================
# 하단 차트
# ============================================================

st.markdown("---")

row2_col1, row2_col2, row2_col3 = st.columns([3, 3, 4])

with row2_col1:
    with st.container(border=True):
        st.markdown("### 위험도별 현황")

        if log_df.empty or "위험도" not in log_df.columns:
            st.info("표시할 데이터가 없습니다.")
        else:
            risk_df = log_df["위험도"].value_counts().reset_index()
            risk_df.columns = ["위험도", "건수"]

            risk_label_map = {
                "High": "높음",
                "Medium": "중간",
                "Low": "낮음",
            }

            risk_df["위험도"] = risk_df["위험도"].map(risk_label_map).fillna(risk_df["위험도"])

            chart = (
                alt.Chart(risk_df)
                .mark_arc(innerRadius=50)
                .encode(
                    theta=alt.Theta("건수:Q", title="건수"),
                    color=alt.Color(
                        "위험도:N",
                        title="위험도",
                        scale=alt.Scale(
                            domain=["높음", "중간", "낮음"],
                            range=["#ef4444", "#f59e0b", "#3b82f6"],
                        ),
                    ),
                    tooltip=["위험도", "건수"],
                )
                .properties(height=220, background="rgba(0,0,0,0)")
            )

            st.altair_chart(chart, use_container_width=True)

with row2_col2:
    with st.container(border=True):
        st.markdown("### AI 위험도 현황")

        if log_df.empty or "AI 위험도" not in log_df.columns:
            st.info("표시할 데이터가 없습니다.")
        else:
            ai_df = log_df["AI 위험도"].fillna("Unknown").value_counts().reset_index()
            ai_df.columns = ["AI 위험도", "건수"]

            ai_label_map = {
                "Critical": "심각",
                "High": "높음",
                "Medium": "중간",
                "Low": "낮음",
                "Unknown": "미확인",
            }

            ai_df["AI 위험도"] = ai_df["AI 위험도"].map(ai_label_map).fillna(ai_df["AI 위험도"])

            chart = (
                alt.Chart(ai_df)
                .mark_bar()
                .encode(
                    x=alt.X(
                        "건수:Q",
                        title="건수",
                        axis=alt.Axis(labelAngle=0),
                    ),
                    y=alt.Y(
                        "AI 위험도:N",
                        title=None,
                        sort=["심각", "높음", "중간", "낮음", "미확인"],
                        axis=alt.Axis(labelAngle=0),
                    ),
                    tooltip=["AI 위험도", "건수"],
                )
                .properties(height=220, background="rgba(0,0,0,0)")
            )

            st.altair_chart(chart, use_container_width=True)

with row2_col3:
    with st.container(border=True):
        st.markdown("### 이벤트 유형별 현황")

        if log_df.empty or "탐지 유형" not in log_df.columns:
            st.info("표시할 데이터가 없습니다.")
        else:
            type_df = log_df["탐지 유형"].fillna("기타").value_counts().reset_index()
            type_df.columns = ["탐지 유형", "건수"]

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
                        "탐지 유형:N",
                        title=None,
                        sort="-x",
                        axis=alt.Axis(labelAngle=0),
                    ),
                    tooltip=["탐지 유형", "건수"],
                )
                .properties(height=220, background="rgba(0,0,0,0)")
            )

            st.altair_chart(chart, use_container_width=True)


# ============================================================
# 상세 로그 테이블
# ============================================================

st.markdown("---")

with st.container(border=True):
    st.markdown("### 전체 로그 상세")

    if log_df.empty:
        st.info("표시할 로그가 없습니다.")
    else:
        detail_cols = [
            "로그 수신 날짜",
            "로그 생성 날짜",
            "호스트 IP 주소",
            "운영체제",
            "룰 레벨",
            "위험도",
            "AI 위험도 점수",
            "AI 위험도",
            "탐지 유형",
            "EventID",
            "프로세스",
            "DestinationIp",
            "DestinationPort",
            "QueryName",
            "행위 내용",
            "상태",
        ]

        detail_cols = [c for c in detail_cols if c in log_df.columns]

        detail_df = log_df[detail_cols].copy()

        if "로그 수신 날짜" in detail_df.columns:
            detail_df = detail_df.sort_values("로그 수신 날짜", ascending=False)

        st.dataframe(
            detail_df,
            use_container_width=True,
            hide_index=True,
            height=350,
        )


# ============================================================
# 자동 새로고침
# ============================================================

st.sidebar.title("사용자 대시보드 설정")
st.sidebar.write("FastAPI 서버:", SERVER_URL)

st.session_state.auto_refresh = st.sidebar.toggle(
    "자동 새로고침",
    value=st.session_state.auto_refresh,
)

st.sidebar.caption(f"{AUTO_REFRESH_SECONDS}초마다 자동 새로고침")

if st.session_state.auto_refresh:
    time.sleep(AUTO_REFRESH_SECONDS)
    st.session_state.last_refresh_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.rerun()