import streamlit as st
import requests
import pandas as pd
import altair as alt
from datetime import datetime, timedelta


SERVER_URL = "http://localhost:8000"


st.set_page_config(
    page_title="ADMIN DASHBOARD",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# 데이터 로드
# ============================================================

def load_logs(limit=5000):
    try:
        response = requests.get(f"{SERVER_URL}/logs?limit={limit}", timeout=5)
        response.raise_for_status()

        data = response.json()
        df = pd.DataFrame(data)

        if df.empty:
            return df

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

        return df

    except Exception as e:
        st.error(f"FastAPI 서버 연결 실패: {e}")
        return pd.DataFrame()


def make_admin_table(df):
    show_cols = [
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
        "Tactic ID",
        "Tactic Name",
        "Technique ID",
        "Technique Name",
        "행위 내용",
        "프로세스",
        "DestinationIp",
        "DestinationPort",
        "QueryName",
        "상태",
    ]

    if df.empty:
        return pd.DataFrame(columns=show_cols)

    show_cols = [col for col in show_cols if col in df.columns]
    result = df[show_cols].copy()

    if "로그 수신 날짜" in result.columns:
        result = result.sort_values("로그 수신 날짜", ascending=False)

    return result


def make_time_chart_data(df):
    if df.empty or "로그 수신 날짜" not in df.columns:
        return pd.DataFrame(columns=["time", "count"])

    temp = df.dropna(subset=["로그 수신 날짜"]).copy()

    if temp.empty:
        return pd.DataFrame(columns=["time", "count"])

    temp["time"] = temp["로그 수신 날짜"].dt.floor("h")

    return (
        temp.groupby("time")
        .size()
        .reset_index(name="count")
        .sort_values("time")
    )


# ============================================================
# 사이드바
# ============================================================

st.sidebar.title("설정")

limit = st.sidebar.selectbox(
    "조회 로그 수",
    [100, 500, 1000, 5000],
    index=3,
)

auto_refresh = st.sidebar.toggle("자동 새로고침", value=False)

if auto_refresh:
    st.sidebar.info("자동 새로고침은 Streamlit 새로고침 기능으로 확인하세요.")

if st.sidebar.button("새로고침"):
    st.rerun()


# ============================================================
# 메인
# ============================================================

st.title("🛡️ ADMIN DASHBOARD")
st.caption("Sysmon 실시간 로그 이벤트 수집 및 알람 현황")

st.write("현재 시간:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

st.divider()

log_df = load_logs(limit=limit)

if log_df.empty:
    st.warning("수집된 로그가 없습니다.")
    st.info("먼저 FastAPI 서버와 실시간 수집기를 실행하세요.")
    st.code(
        """
uvicorn backend.server:app --reload
python collector/sysmon_collector.py
""",
        language="powershell",
    )
    st.stop()


# ============================================================
# 상단 지표
# ============================================================

total_count = len(log_df)

alert_count = 0
if "상태" in log_df.columns:
    alert_count = len(log_df[log_df["상태"] == "알림"])

high_count = 0
medium_count = 0
low_count = 0

if "위험도" in log_df.columns:
    high_count = len(log_df[log_df["위험도"] == "High"])
    medium_count = len(log_df[log_df["위험도"] == "Medium"])
    low_count = len(log_df[log_df["위험도"] == "Low"])

ai_high_count = 0
if "AI 위험도" in log_df.columns:
    ai_high_count = len(log_df[log_df["AI 위험도"].isin(["High", "Critical"])])

col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("전체 로그", f"{total_count:,}")
col2.metric("알람", f"{alert_count:,}")
col3.metric("High", f"{high_count:,}")
col4.metric("Medium", f"{medium_count:,}")
col5.metric("AI High/Critical", f"{ai_high_count:,}")

st.divider()


# ============================================================
# 알람 로그
# ============================================================

st.subheader("실시간 알람 로그")

if "상태" in log_df.columns:
    alert_df = log_df[log_df["상태"] == "알림"].copy()
else:
    alert_df = pd.DataFrame()

if alert_df.empty:
    st.info("현재 알람 로그가 없습니다.")
else:
    st.error(f"위험 알람 {len(alert_df):,}건 감지")
    st.dataframe(
        make_admin_table(alert_df),
        use_container_width=True,
        hide_index=True,
        height=300,
    )

st.divider()


# ============================================================
# 필터
# ============================================================

st.subheader("로그 조회")

col1, col2, col3 = st.columns(3)

with col1:
    start_date = st.date_input(
        "시작 날짜",
        value=datetime.now().date() - timedelta(days=1),
    )

with col2:
    end_date = st.date_input(
        "종료 날짜",
        value=datetime.now().date(),
    )

with col3:
    search_text = st.text_input(
        "검색어",
        placeholder="프로세스명, IP, DNS, 행위 내용 검색",
    )

filtered_df = log_df.copy()

if "로그 수신 날짜" in filtered_df.columns:
    start_datetime = pd.to_datetime(start_date)
    end_datetime = pd.to_datetime(end_date) + timedelta(days=1)

    filtered_df = filtered_df[
        (filtered_df["로그 수신 날짜"] >= start_datetime)
        & (filtered_df["로그 수신 날짜"] < end_datetime)
    ]

filter_col1, filter_col2, filter_col3 = st.columns(3)

with filter_col1:
    if "룰 레벨" in filtered_df.columns:
        level_options = sorted(filtered_df["룰 레벨"].dropna().unique().tolist())
    else:
        level_options = []

    selected_levels = st.multiselect(
        "룰 레벨",
        level_options,
        default=level_options,
    )

with filter_col2:
    if "위험도" in filtered_df.columns:
        risk_options = sorted(filtered_df["위험도"].dropna().unique().tolist())
    else:
        risk_options = []

    selected_risks = st.multiselect(
        "위험도",
        risk_options,
        default=risk_options,
    )

with filter_col3:
    if "AI 위험도" in filtered_df.columns:
        ai_options = sorted(filtered_df["AI 위험도"].dropna().unique().tolist())
    else:
        ai_options = []

    selected_ai_risks = st.multiselect(
        "AI 위험도",
        ai_options,
        default=ai_options,
    )

if selected_levels and "룰 레벨" in filtered_df.columns:
    filtered_df = filtered_df[filtered_df["룰 레벨"].isin(selected_levels)]

if selected_risks and "위험도" in filtered_df.columns:
    filtered_df = filtered_df[filtered_df["위험도"].isin(selected_risks)]

if selected_ai_risks and "AI 위험도" in filtered_df.columns:
    filtered_df = filtered_df[filtered_df["AI 위험도"].isin(selected_ai_risks)]

event_df = make_admin_table(filtered_df)

if search_text and not event_df.empty:
    mask = event_df.astype(str).apply(
        lambda x: x.str.contains(search_text, case=False, na=False)
    ).any(axis=1)

    event_df = event_df[mask]


# ============================================================
# 차트
# ============================================================

chart_data = make_time_chart_data(filtered_df)

st.subheader("시간대별 탐지 이벤트")

if chart_data.empty:
    st.info("차트로 표시할 로그가 없습니다.")
else:
    chart = (
        alt.Chart(chart_data)
        .mark_bar()
        .encode(
            x=alt.X("time:T", title="시간"),
            y=alt.Y("count:Q", title="탐지 수"),
            tooltip=[
                alt.Tooltip("time:T", title="시간"),
                alt.Tooltip("count:Q", title="탐지 수"),
            ],
        )
        .properties(height=300)
        .interactive()
    )

    st.altair_chart(chart, use_container_width=True)


# ============================================================
# 상세 테이블
# ============================================================

st.subheader("탐지 이벤트 상세 정보")

st.dataframe(
    event_df,
    use_container_width=True,
    hide_index=True,
    height=450,
)

if not event_df.empty:
    csv = event_df.to_csv(index=False).encode("utf-8-sig")

    st.download_button(
        label="현재 조회 로그 CSV 다운로드",
        data=csv,
        file_name="admin_filtered_logs.csv",
        mime="text/csv",
        use_container_width=True,
    )