import streamlit as st
import requests
import pandas as pd
import altair as alt
from datetime import datetime, timedelta
import os

# ==============================
# 기본 설정
# ==============================
st.set_page_config(
    page_title="ADMIN DASHBOARD",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)



# ==============================
# CSS
# ==============================        
st.markdown("""
<style>
@font-face {
    font-family: 'NanumSquareRound';
    src: url('https://cdn.jsdelivr.net/gh/projectnoonnu/noonfonts_two@1.0/NanumSquareRound.woff') format('woff');
}
h1,h2,h3,h4,p,label,.stMarkdown,.stText {
    font-family: 'NanumSquareRound', sans-serif !important;
}
.main-title {
    font-size: 28px;
    font-weight: bold;
    margin-bottom: 20px;
    color: #f3f4f6 !important;
}
.metric-card {
    background-color: rgba(59, 130, 246, 0.1);
    padding: 15px;
    border-radius: 8px;
    text-align: center;
    border: 1px solid rgba(59, 130, 246, 0.3);
}
.pc-card {
    background: linear-gradient(135deg, rgba(59, 130, 246, 0.15) 0%, rgba(99, 102, 241, 0.1) 100%);
    padding: 20px;
    border-radius: 10px;
    text-align: center;
    border: 1px solid rgba(59, 130, 246, 0.3);
    color: #f3f4f6;
}
.pc-card-value {
    font-size: 1.8rem;
    font-weight: bold;
    color: #3b82f6;
    margin: 10px 0;
}
.pc-card-label {
    font-size: 0.9rem;
    color: #d1d5db;
}
.circular-stat {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 25px 20px;
    background: linear-gradient(135deg, rgba(30, 34, 51, 0.6) 0%, rgba(13, 16, 23, 0.8) 100%);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 15px;
    position: relative;
    backdrop-filter: blur(10px);
}
.circular-progress {
    position: relative;
    width: 140px;
    height: 140px;
    margin-bottom: 15px;
}
.progress-svg {
    width: 100%;
    height: 100%;
    transform: rotate(-90deg);
}
.progress-circle {
    fill: none;
}
.progress-background {
    stroke: rgba(255, 255, 255, 0.1);
    stroke-width: 8;
}
.progress-fill {
    stroke-width: 8;
    stroke-linecap: round;
    transition: stroke-dashoffset 0.5s ease;
}
.progress-text {
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
}
.progress-value {
    font-size: 2.2rem;
    font-weight: bold;
    color: #f3f4f6;
    line-height: 1;
}
.progress-subtitle {
    font-size: 0.75rem;
    color: #9ca3af;
    margin-top: 2px;
}
.stat-label {
    font-size: 0.95rem;
    color: #d1d5db;
    font-weight: 500;
    letter-spacing: 0.5px;
}
.stat-sublabel {
    font-size: 0.8rem;
    color: #6b7280;
    margin-top: 5px;
}
.alert-high {
    background-color: rgba(239, 68, 68, 0.2);
    border: 1px solid rgba(239, 68, 68, 0.5);
    color: #fca5a5;
}
.alert-medium {
    background-color: rgba(245, 158, 11, 0.2);
    border: 1px solid rgba(245, 158, 11, 0.5);
    color: #fed7aa;
}
.alert-low {
    background-color: rgba(34, 197, 94, 0.2);
    border: 1px solid rgba(34, 197, 94, 0.5);
    color: #86efac;
}
[data-testid="stToolbar"], #MainMenu, footer, header { visibility: hidden !important; }
.stApp { background: linear-gradient(135deg, #1e2233 0%, #0d1017 100%) !important; }
.main { background-color: transparent !important; color: #d1d5db; }
div[data-testid="stVerticalBlockBorderWrapper"] {
    background-color: rgba(30, 34, 51, 0.4) !important;
    backdrop-filter: blur(8px);
    border-radius: 10px !important;
    border: 1px solid rgba(255,255,255,0.05) !important;
    box-shadow: 0 4px 20px rgba(0,0,0,0.3) !important;
}
h1,h2,h3,h4 { color: #f3f4f6 !important; }
div[data-testid="stMetricValue"] {
    font-family: 'NanumSquareRound', sans-serif !important;
    font-size: 1.6rem !important;
    color: #f3f4f6 !important;
}
div[data-testid="stMetricLabel"] {
    font-family: 'NanumSquareRound', sans-serif !important;
    font-size: 0.8rem !important;
    color: #d1d5db !important;
}
[data-testid="stSidebar"] {
    background: rgba(30, 34, 51, 0.6) !important;
    border-right: 1px solid rgba(255,255,255,0.05) !important;
}
.stDataframe {
    background-color: rgba(30, 34, 51, 0.4) !important;
}
</style>
""", unsafe_allow_html=True)


# ==============================
# logs.csv 읽기 함수
# ==============================
SERVER_URL = "http://localhost:8000"

def create_circular_gauge(value, max_value, label, color, unit=""):
    """원형 게이지 SVG 생성"""
    percentage = min(value / max_value * 100, 100) if max_value > 0 else 0
    circumference = 2 * 3.14159 * 45
    offset = circumference * (100 - percentage) / 100
    
    svg = f"""
    <div class="circular-stat">
        <div class="circular-progress">
            <svg class="progress-svg" viewBox="0 0 120 120">
                <circle class="progress-circle progress-background" cx="60" cy="60" r="45"/>
                <circle class="progress-circle progress-fill" cx="60" cy="60" r="45" 
                        style="stroke: {color}; stroke-dasharray: {circumference}; stroke-dashoffset: {offset};"/>
            </svg>
            <div class="progress-text">
                <div class="progress-value">{int(value)}</div>
                <div class="progress-subtitle">{unit}</div>
            </div>
        </div>
        <div class="stat-label">{label}</div>
    </div>
    """
    return svg

def load_logs() -> pd.DataFrame:
    try:
        res = requests.get(f"{SERVER_URL}/logs?limit=5000", timeout=5)
        res.raise_for_status()
        df = pd.DataFrame(res.json())

        if df.empty:
            return df

        # 영문 컬럼 → 한글 컬럼으로 변환
        df = df.rename(columns={
            "recv_time":        "로그 수신 날짜",
            "gen_time":         "로그 생성 날짜",
            "host_ip":          "호스트 IP 주소",
            "os_name":          "운영체제",
            "rule_level":       "룰 레벨",
            "risk":             "위험도",
            "detect_type":      "탐지 유형",
            "tactic_id":        "Tactic ID",
            "tactic_name":      "Tactic Name",
            "technique_id":     "Technique ID",
            "technique_name":   "Technique Name",
            "action_desc":      "행위 내용",
            "process_name":     "프로세스",
            "status":           "상태",
        })

        # 날짜 컬럼 변환
        for col in ["로그 수신 날짜", "로그 생성 날짜"]:
            if col in df.columns:
                df[col] = pd.to_datetime(df[col], errors="coerce")

        return df

    except Exception as e:
        st.error(f"서버 연결 실패: {e}")
        return pd.DataFrame()

# ==============================
# 차트용 데이터 생성
# ==============================
def make_chart_data(df):
    """
    logs.csv 데이터를 시간대별 탐지 이벤트 차트용 데이터로 변환.
    """

    if df.empty or "로그 수신 날짜" not in df.columns:
        return pd.DataFrame(columns=["time", "count"])

    temp = df.copy()
    temp = temp.dropna(subset=["로그 수신 날짜"])

    if temp.empty:
        return pd.DataFrame(columns=["time", "count"])

    temp["time"] = temp["로그 수신 날짜"].dt.floor("h")

    chart_data = (
        temp.groupby("time")
        .size()
        .reset_index(name="count")
        .sort_values("time")
    )

    return chart_data


# ==============================
# 관리자 화면용 테이블 컬럼 정리
# ==============================
def make_admin_table(df):
    """
    사용자 대시보드 logs.csv 컬럼을 관리자 화면에서 보기 좋게 정리.
    """

    if df.empty:
        return pd.DataFrame(columns=[
            "로그 수신 날짜",
            "로그 생성 날짜",
            "호스트 IP 주소",
            "운영체제",
            "룰 레벨",
            "위험도",
            "탐지 유형",
            "Tactic ID",
            "Tactic Name",
            "Technique ID",
            "Technique Name",
            "행위 내용",
            "프로세스",
            "상태"
        ])

    show_cols = [
        "로그 수신 날짜",
        "로그 생성 날짜",
        "호스트 IP 주소",
        "운영체제",
        "룰 레벨",
        "위험도",
        "탐지 유형",
        "Tactic ID",
        "Tactic Name",
        "Technique ID",
        "Technique Name",
        "행위 내용",
        "프로세스",
        "상태"
    ]

    # 실제 있는 컬럼만 표시
    show_cols = [col for col in show_cols if col in df.columns]

    result = df[show_cols].copy()

    if "로그 수신 날짜" in result.columns:
        result = result.sort_values("로그 수신 날짜", ascending=False)

    return result


# ==============================
# 데이터 불러오기
# ==============================
log_df = load_logs()


# ==============================
# 제목 영역
# ==============================
col1, col2 = st.columns([0.7, 0.3])

with col1:
    st.markdown('<div class="main-title">🛡️ ADMIN DASHBOARD</div>', unsafe_allow_html=True)

with col2:
    current_time = datetime.now().strftime("%Y년 %m월 %d일 %H:%M:%S")
    st.text(current_time)

st.divider()


# ==============================
# 관리 중인 PC 목록 섹션
# ==============================
st.markdown("### 📊 관리 중인 PC 현황")

if not log_df.empty and "호스트 IP 주소" in log_df.columns:
    # 호스트별 통계 계산
    pc_stats = []
    host_ips = log_df["호스트 IP 주소"].unique()
    
    for host_ip in host_ips:
        host_logs = log_df[log_df["호스트 IP 주소"] == host_ip]
        
        high_count = 0
        medium_count = 0
        low_count = 0
        
        if "위험도" in log_df.columns:
            high_count = len(host_logs[host_logs["위험도"] == "H"])
            medium_count = len(host_logs[host_logs["위험도"] == "M"])
            low_count = len(host_logs[host_logs["위험도"] == "L"])
        
        os_name = host_logs["운영체제"].iloc[0] if "운영체제" in log_df.columns else "Unknown"
        
        pc_stats.append({
            "host_ip": host_ip,
            "os_name": os_name,
            "total_events": len(host_logs),
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
        })
    
    # 실제 PC 데이터 표시
    if pc_stats:
        st.write("**수집된 PC 목록**")
        # 행 1: 최대 4개 PC
        cols = st.columns(min(4, len(pc_stats)))
        for idx, pc in enumerate(pc_stats[:4]):
            with cols[idx]:
                danger_percentage = (pc['high'] / (pc['total_events'] + 1)) * 100
                color = "#ef4444" if danger_percentage > 30 else "#f59e0b" if danger_percentage > 10 else "#3b82f6"
                st.markdown(
                    create_circular_gauge(pc['total_events'], max(100, pc['total_events'] * 1.2), 
                                        pc['host_ip'], color, "이벤트"),
                    unsafe_allow_html=True
                )
        
        # 행 2: 5번째 이상 PC
        if len(pc_stats) > 4:
            cols = st.columns(min(4, len(pc_stats) - 4))
            for idx, pc in enumerate(pc_stats[4:8]):
                with cols[idx]:
                    danger_percentage = (pc['high'] / (pc['total_events'] + 1)) * 100
                    color = "#ef4444" if danger_percentage > 30 else "#f59e0b" if danger_percentage > 10 else "#3b82f6"
                    st.markdown(
                        create_circular_gauge(pc['total_events'], max(100, pc['total_events'] * 1.2), 
                                            pc['host_ip'], color, "이벤트"),
                        unsafe_allow_html=True
                    )
        
        st.divider()

# 샘플 PC 데이터 (항상 표시)
st.write("**PC 현황**")
dummy_pcs = [
    {"ip": "192.168.1.101", "events": 45, "color": "#3b82f6", "label": "PC-001"},
    {"ip": "192.168.1.102", "events": 78, "color": "#f59e0b", "label": "PC-002"},
    {"ip": "192.168.1.103", "events": 23, "color": "#3b82f6", "label": "PC-003"},
    {"ip": "192.168.1.104", "events": 156, "color": "#ef4444", "label": "PC-004"},
]

cols = st.columns(4)
for idx, pc in enumerate(dummy_pcs):
    with cols[idx]:
        st.markdown(
            create_circular_gauge(pc['events'], 200, pc['label'], pc['color'], "이벤트"),
            unsafe_allow_html=True
        )

st.divider()


# ==============================
# 탭 구성
# ==============================
tab1, tab2, tab3 = st.tabs(["🔍 로그", "🌐 네트워크", "🖥️ 시스템"])


# ==============================
# TAB 1: 로그
# ==============================
with tab1:
    if log_df.empty:
        st.warning("수집된 로그가 없습니다.")
        st.info("각 PC에서 Sysmon 로그를 수집하면 자동으로 표시됩니다.")
    else:
        st.success(f"DB에서 로그 {len(log_df):,}건을 불러왔습니다.")

        # 날짜 범위 선택
        col1, col2, col3 = st.columns([0.3, 0.3, 0.4])

        with col1:
            start_date = st.date_input(
                "시작 날짜",
                value=datetime.now().date() - timedelta(days=1)
            )

        with col2:
            end_date = st.date_input(
                "종료 날짜",
                value=datetime.now().date()
            )

        with col3:
            st.write("")

        # 날짜 필터 적용
        filtered_df = log_df.copy()

        if not filtered_df.empty and "로그 수신 날짜" in filtered_df.columns:
            start_datetime = pd.to_datetime(start_date)
            end_datetime = pd.to_datetime(end_date) + timedelta(days=1)

            filtered_df = filtered_df[
                (filtered_df["로그 수신 날짜"] >= start_datetime) &
                (filtered_df["로그 수신 날짜"] < end_datetime)
            ]

        # 차트 데이터
        chart_data = make_chart_data(filtered_df)

        st.subheader("시간대별 탐지 이벤트")

        if chart_data.empty:
            st.info("차트로 표시할 로그가 없습니다.")
        else:
            bar_chart = alt.Chart(chart_data).mark_bar(color="#3b82f6").encode(
                x=alt.X(
                    "time:T",
                    title="시간",
                    axis=alt.Axis(format="%m-%d %H:%M", labelAngle=0, labelColor='white', titleColor='white')
                ),
                y=alt.Y(
                    "count:Q",
                    title="탐지",
                    axis=alt.Axis(labelColor='white', titleColor='white')
                ),
                tooltip=[
                    alt.Tooltip("time:T", title="시간"),
                    alt.Tooltip("count:Q", title="탐지 수")
                ]
            ).properties(
                height=300,
                background='rgba(0,0,0,0)'
            ).interactive().configure_view(
                strokeOpacity=0,
                fill='transparent'
            ).configure_axis(
                grid=False
            )

            st.altair_chart(bar_chart, use_container_width=True, theme=None)

        # 통계 메트릭
        total_count = len(filtered_df)

        if not filtered_df.empty and "룰 레벨" in filtered_df.columns:
            normal_count = len(filtered_df[filtered_df["룰 레벨"] == "일반"])
            warning_count = len(filtered_df[filtered_df["룰 레벨"] == "중요"])
        else:
            normal_count = 0
            warning_count = 0

        if not chart_data.empty:
            avg_count = chart_data["count"].mean()
            max_count = chart_data["count"].max()
        else:
            avg_count = 0
            max_count = 0

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric("총 탐지 이벤트", f"{total_count:,}")

        with col2:
            st.metric("일반 로그", f"{normal_count:,}")

        with col3:
            st.metric("중요 로그", f"{warning_count:,}")

        with col4:
            st.metric("최대 시간당 탐지", f"{max_count:,}")

        st.divider()

        # 이벤트 테이블
        st.subheader("탐지 이벤트 상세 정보")

        col1, col2 = st.columns([0.7, 0.3])

        with col1:
            search_text = st.text_input(
                "로그 검색",
                placeholder="프로세스명, IP, 행위 내용, Tactic Name 검색..."
            )

        with col2:
            if not filtered_df.empty and "룰 레벨" in filtered_df.columns:
                level_options = sorted(filtered_df["룰 레벨"].dropna().unique().tolist())
            else:
                level_options = ["일반", "중요"]

            status_filter = st.multiselect(
                "룰 레벨 필터",
                level_options,
                default=level_options
            )

        event_df = make_admin_table(filtered_df)

        # 검색 필터
        if search_text and not event_df.empty:
            mask = event_df.astype(str).apply(
                lambda x: x.str.contains(search_text, case=False, na=False)
            ).any(axis=1)

            event_df = event_df[mask]

        # 룰 레벨 필터
        if "룰 레벨" in event_df.columns and status_filter:
            event_df = event_df[event_df["룰 레벨"].isin(status_filter)]

        st.dataframe(
            event_df,
            use_container_width=True,
            hide_index=True,
            height=420
        )

        # CSV 다운로드
        if not event_df.empty:
            csv = event_df.to_csv(index=False).encode("utf-8-sig")

            st.download_button(
                label="📥 현재 조회 로그 CSV 다운로드",
                data=csv,
                file_name="admin_filtered_logs.csv",
                mime="text/csv",
                use_container_width=True
            )


# ==============================
# TAB 2: 네트워크
# ==============================
with tab2:
    st.subheader("네트워크")

    col1, col2 = st.columns(2)

    with col1:
        st.metric("의심 연결", "23", "+5")

    with col2:
        st.metric("차단된 연결", "45", "+12")

    st.divider()

    network_data = pd.DataFrame({
        "소스 IP": ["192.168.1.100", "192.168.1.105", "192.168.1.110", "10.0.0.50", "10.0.0.75"],
        "대상 IP": ["8.8.8.8", "1.1.1.1", "8.8.4.4", "203.0.113.45", "198.51.100.89"],
        "포트": [443, 53, 8080, 445, 3389],
        "프로토콜": ["TLS", "DNS", "HTTP", "SMB", "RDP"],
        "상태": ["차단", "허용", "차단", "허용", "차단"]
    })

    st.write("**네트워크 연결 기록**")
    st.dataframe(network_data, use_container_width=True, hide_index=True)


# ==============================
# TAB 3: 시스템
# ==============================
with tab3:
    st.subheader("시스템 로그 수집 및 파일")

    if not log_df.empty:
        total_logs = len(log_df)

        if "룰 레벨" in log_df.columns:
            suspect_logs = len(log_df[log_df["룰 레벨"] == "일반"])
            danger_logs = len(log_df[log_df["룰 레벨"] == "중요"])
        else:
            suspect_logs = 0
            danger_logs = 0
    else:
        total_logs = 0
        suspect_logs = 0
        danger_logs = 0

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("수집된 로그", f"{total_logs:,}", "")

    with col2:
        st.metric("일반 로그", f"{suspect_logs:,}", "")

    with col3:
        st.metric("중요 로그", f"{danger_logs:,}", "")

    st.divider()

    system_log_data = pd.DataFrame({
        "로그 유형": ["프로세스", "네트워크", "파일", "DLL", "명령어"],
        "수집 상태": ["연동 대기", "연동 대기", "연동 대기", "연동 대기", "연동 대기"],
        "설명": [
            "Sysmon 프로세스 생성 이벤트 연동 예정",
            "Sysmon 네트워크 접속 이벤트 연동 예정",
            "파일 생성 및 수정 이벤트 연동 예정",
            "DLL 로드 이벤트 연동 예정",
            "PowerShell 및 cmd 실행 이벤트 연동 예정"
        ]
    })

    st.write("**수집 모듈 상태**")
    st.dataframe(system_log_data, use_container_width=True, hide_index=True)


# ==============================
# 사이드바
# ==============================
st.sidebar.title("⚙️ 설정")
st.sidebar.divider()

time_range = st.sidebar.selectbox(
    "시간 범위",
    ["1시간", "6시간", "24시간", "7일", "30일", "사용자 정의"]
)

st.sidebar.divider()

st.sidebar.subheader("알림 설정")
auto_refresh = st.sidebar.toggle("자동 새로고침", value=False)

if auto_refresh:
    st.sidebar.info("자동 새로고침은 나중에 Sysmon 실시간 수집 기능과 연결하면 됩니다.")

st.sidebar.divider()

st.sidebar.subheader("내보내기")

if st.sidebar.button("📊 보고서 생성"):
    st.sidebar.success("보고서가 생성되었습니다!")

if st.sidebar.button("📥 데이터 내보내기 안내"):
    st.sidebar.info("로그 탭에서 현재 조회 로그를 CSV로 다운로드할 수 있습니다.")

st.sidebar.divider()

st.sidebar.info(
    "사용자 대시보드에서 생성한 logs.csv를 읽어 관리자 화면에 표시합니다."
)