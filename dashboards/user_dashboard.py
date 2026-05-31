import streamlit as st
import pandas as pd
import altair as alt
import hashlib
import requests
import base64
import time
import platform

# ==================================================================
# 설정
# ==================================================================
API_KEY          = "여기에_본인_VirusTotal_API_KEY_입력"
HEADERS          = {"accept": "application/json", "x-apikey": API_KEY}
SERVER_URL       = "http://localhost:8000"
TARGET_IDS_LABEL = "Event ID 1 · 3 · 5 · 22"

# ==================================================================
# Sysmon 수집기 임포트 + 가용 여부 체크
# ==================================================================
try:
    import win32evtlog  # type: ignore[import]
    import sys
    import os
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    from collector import sysmon_collector  # type: ignore[import]
    _WIN32_OK = True
except ImportError:
    sysmon_collector = None  # type: ignore[assignment]
    _WIN32_OK = False

# 실행 시점에 한 번만 체크
_SYSMON_READY: bool = _WIN32_OK and platform.system() == "Windows"

# ==================================================================
# session_state 초기화
# ==================================================================
if "sysmon_logs" not in st.session_state:
    st.session_state.sysmon_logs = pd.DataFrame()


# ==================================================================
# 서버 전송
# ==================================================================
def send_to_server(rows: list[dict]) -> tuple[int, str]:
    if not rows:
        return 0, ""

    formatted = [{
        "host_ip":          r.get("호스트 IP 주소", "192.168.0.10"),
        "gen_time":         r.get("로그 생성 날짜"),
        "os_name":          r.get("운영체제"),
        "rule_level":       r.get("룰 레벨"),
        "risk":             r.get("위험도"),
        "detect_type":      r.get("탐지 유형"),
        "tactic_id":        r.get("Tactic ID"),
        "tactic_name":      r.get("Tactic Name"),
        "technique_id":     r.get("Technique ID"),
        "technique_name":   r.get("Technique Name"),
        "action_desc":      r.get("행위 내용"),
        "process_name":     r.get("프로세스"),
        "event_id":         r.get("EventID"),
        "command_line":     r.get("CommandLine"),
        "destination_ip":   r.get("DestinationIp"),
        "destination_port": r.get("DestinationPort"),
        "query_name":       r.get("QueryName"),
        "status":           r.get("상태", "신규"),
    } for r in rows]

    try:
        res = requests.post(
            f"{SERVER_URL}/logs",
            json={"logs": formatted},
            timeout=10,
        )
        res.raise_for_status()
        return res.json()["저장된 건수"], ""
    except Exception as e:
        return 0, str(e)


# ==================================================================
# Sysmon 수집 → session_state → 서버 전송
# ==================================================================
def collect_and_send(max_records: int = 500) -> tuple[int, int, str]:
    """Returns (collected_count, sent_count, error)"""
    if not (_WIN32_OK and platform.system() == "Windows"):
        return 0, 0, "Windows + pywin32 환경에서만 수집 가능합니다. (pip install pywin32)"

    try:
        rows = sysmon_collector.collect(max_records=max_records)
        if not rows:
            return 0, 0, ""
        
        rows = sysmon_collector.apply_jonghan_policy(rows)   

        st.session_state.sysmon_logs = pd.DataFrame(rows)
        sent, err = send_to_server(rows)
        return len(rows), sent, err

    except Exception as e:
        return 0, 0, str(e)


# ==================================================================
# VirusTotal
# ==================================================================
def _fmt(stats, results):
    return {"stats": stats, "results": results}

def analyze_file_vt(uploaded_file):
    data = uploaded_file.getvalue()
    h    = hashlib.sha256(data).hexdigest()
    res  = requests.get(f"https://www.virustotal.com/api/v3/files/{h}", headers=HEADERS)
    if res.status_code == 200:
        d = res.json()["data"]["attributes"]
        return _fmt(d["last_analysis_stats"], d["last_analysis_results"])
    if res.status_code == 404:
        up = requests.post("https://www.virustotal.com/api/v3/files",
                           headers=HEADERS, files={"file": (uploaded_file.name, data)})
        if up.status_code == 200:
            return _wait_vt(up.json()["data"]["id"])
    return None

def analyze_url_vt(target_url):
    uid = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    res = requests.get(f"https://www.virustotal.com/api/v3/urls/{uid}", headers=HEADERS)
    if res.status_code == 200:
        d = res.json()["data"]["attributes"]
        return _fmt(d["last_analysis_stats"], d["last_analysis_results"])
    if res.status_code == 404:
        pr = requests.post("https://www.virustotal.com/api/v3/urls",
                           headers=HEADERS, data={"url": target_url})
        if pr.status_code == 200:
            return _wait_vt(pr.json()["data"]["id"])
    return None

def _wait_vt(analysis_id):
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    with st.status("검사를 진행 중입니다...", expanded=True) as s:
        for _ in range(12):
            res = requests.get(url, headers=HEADERS)
            if res.status_code == 200:
                d = res.json()["data"]["attributes"]
                if d["status"] == "completed":
                    s.update(label="검사 완료", state="complete", expanded=False)
                    return _fmt(d["stats"], d["results"])
            time.sleep(10)
    return None

def render_vt_results(vt_data):
    stats = vt_data["stats"]
    m     = stats["malicious"]
    total = m + stats["harmless"] + stats.get("undetected", 0)
    if m > 0:
        st.error(f"[위험] {total}개 중 {m}개 악성 탐지")
    else:
        st.success("[안전] 악성 내역 없음")
    rows = []
    for engine, detail in vt_data["results"].items():
        cat = detail.get("category", "undetected")
        label, order = {"malicious": ("악성", 1), "suspicious": ("의심", 2),
                        "harmless": ("정상", 3)}.get(cat, ("미탐지", 4))
        rows.append({"엔진": engine, "결과": label,
                     "진단명": detail.get("result", ""), "_s": order})
    df = pd.DataFrame(rows).sort_values("_s").drop(columns=["_s"])
    st.dataframe(df, width="stretch", hide_index=True, height=200)


# ==================================================================
# 통계 계산
# ==================================================================
def _calc_stats() -> dict:
    df = st.session_state.sysmon_logs
    if df.empty:
        return {"total": 0, "new": 0, "checking": 0, "hold": 0, "done": 0,
                "high": 0, "medium": 0, "low": 0,
                "malicious": 0, "suspicious": 0, "normal": 0}
    total      = len(df)
    risk_col   = "위험도"    if "위험도"    in df.columns else None
    status_col = "상태"      if "상태"      in df.columns else None
    type_col   = "탐지 유형" if "탐지 유형" in df.columns else None
    return {
        "total":      total,
        "new":        len(df[df[status_col] == "신규"])      if status_col else total,
        "checking":   len(df[df[status_col] == "확인 중"])   if status_col else 0,
        "hold":       len(df[df[status_col] == "보류"])      if status_col else 0,
        "done":       len(df[df[status_col] == "확인 완료"]) if status_col else 0,
        "high":       len(df[df[risk_col]   == "H"])         if risk_col else 0,
        "medium":     len(df[df[risk_col]   == "M"])         if risk_col else 0,
        "low":        len(df[df[risk_col]   == "L"])         if risk_col else 0,
        "malicious":  len(df[df[type_col]   == "악성"])      if type_col else 0,
        "suspicious": len(df[df[type_col]   == "의심"])      if type_col else 0,
        "normal":     len(df[df[type_col]   == "정상"])      if type_col else 0,
    }


# ==================================================================
# 페이지 설정 & CSS
# ==================================================================
st.set_page_config(page_title="EDR User Dashboard", layout="wide")

st.markdown("""
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
h2 { font-size: 1.4rem !important; margin-bottom: 0px !important; }
h3 { font-size: 1.1rem !important; }
h4 { font-size: 0.9rem !important; }
button[kind="tertiary"] p {
    font-size: 1.8rem !important; color: #3b82f6 !important;
    font-weight: 800 !important; margin-top: -5px !important;
}
button[kind="tertiary"]:hover p { color: #60a5fa !important; }
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
</style>
""", unsafe_allow_html=True)


# ==================================================================
# 상단 헤더
# ==================================================================
top_col1, top_col2, top_col3 = st.columns([3, 4, 3])

with top_col1:
    st.markdown("## EDR Analyzer (사용자)")

with top_col2:
    st.segmented_control(
        "조회 범위",
        ["최근 24시간", "최근 7일", "최근 14일", "최근 30일"],
        default="최근 24시간",
        label_visibility="collapsed",
    )

with top_col3:
    time_col, refresh_col = st.columns([5, 1])
    with time_col:
        st.html("""
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
        </script>""")
    with refresh_col:
        if st.button("↻", type="tertiary", help="데이터 새로고침"):
            st.rerun()

st.markdown("---")

stats = _calc_stats()

# ==================================================================
# 중앙 레이아웃
# ==================================================================
row1_col1, row1_col2 = st.columns([3, 7])

with row1_col1:
    with st.container(border=True):
        st.markdown("### 위험 현황")
        color = "#ef4444" if stats["total"] > 0 else "#10b981"
        st.markdown(
            f"<h1 style='color:{color};font-size:2.5rem;margin-top:-10px;'>"
            f"{stats['total']}</h1>",
            unsafe_allow_html=True,
        )
        c1, c2 = st.columns(2)
        c1.metric("신규",      stats["new"])
        c2.metric("확인 중",   stats["checking"])
        c1.metric("보류",      stats["hold"])
        c2.metric("확인 완료", stats["done"])

with row1_col2:
    with st.container(border=True):
        st.markdown("### 최근 탐지 위협")

        if not st.session_state.sysmon_logs.empty:
            display_cols = [c for c in
                ["로그 수신 날짜", "위험도", "탐지 유형", "Tactic ID", "Technique Name", "프로세스", "행위 내용", "상태"]
                if c in st.session_state.sysmon_logs.columns]
            display_df = st.session_state.sysmon_logs[display_cols].head(10)
            st.dataframe(display_df, width="stretch", hide_index=True,
                         height=len(display_df) * 35 + 38)
        else:
            st.info("수집된 로그가 없습니다. Sysmon 로그를 수집하세요.")

        if st.button(
            f"🔍 Sysmon 로그 수집 ({TARGET_IDS_LABEL})",
            width="stretch",
            help="Event ID 1·3·5·22 수집 → 대시보드 표시 + 서버 전송",
        ):
            with st.spinner("Sysmon 이벤트 수집 중…"):
                collected, sent, err = collect_and_send(max_records=500)
            if collected == 0:
                if err:
                    st.error(f"오류: {err}")
                else:
                    st.warning("수집된 이벤트가 없습니다. Sysmon이 실행 중인지 확인하세요.")
            else:
                if err:
                    st.warning(f"⚠️ {collected}건 수집됨, 서버 전송 실패: {err}")
                else:
                    st.success(f"✅ {sent}건 수집 완료 → 서버 전송됨")
                st.rerun()

        if not _SYSMON_READY:
            st.caption("⚠️ Windows + pywin32 필요  `pip install pywin32`")


# ==================================================================
# 하단 레이아웃 - 차트 배경 투명화 및 테두리 제거 (강력 조치)
# ==================================================================
row2_col1, row2_col2, row2_col3 = st.columns([3, 3, 4])

with row2_col1:
    with st.container(border=True):
        st.markdown("### 위험도별 현황")
        if not st.session_state.sysmon_logs.empty:
            risk_df = st.session_state.sysmon_logs['위험도'].value_counts().reset_index()
            risk_df.columns = ['위험도', '건수']
            
            chart = alt.Chart(risk_df).mark_arc(innerRadius=50).encode(
                theta="건수:Q",
                color=alt.Color("위험도:N", scale=alt.Scale(
                    domain=["High", "Medium", "Low"],
                    range=["#ef4444", "#f59e0b", "#3b82f6"]
                )),
                tooltip=["위험도", "건수"]
            ).properties(
                height=180,
                background='rgba(0,0,0,0)' # 👈 배경을 완전 투명(Alpha 0)으로 설정
            ).configure_view(
                strokeOpacity=0,           # 👈 차트 외곽선 제거
                fill='transparent'         # 👈 내부 채우기 투명
            ).configure_axis(
                grid=False                 # 👈 그리드 제거
            )
            # theme=None을 추가하여 스트림릿의 기본 테마 간섭을 차단합니다.
            st.altair_chart(chart, use_container_width=True, theme=None)
        else:
            st.write("데이터가 없습니다.")

with row2_col2:
    with st.container(border=True):
        st.markdown("### 탐지 유형별 현황")
        if not st.session_state.sysmon_logs.empty:
            type_df = st.session_state.sysmon_logs['탐지 유형'].value_counts().reset_index()
            type_df.columns = ['유형', '건수']
            
            chart = alt.Chart(type_df).mark_bar().encode(
                x=alt.X("건수:Q", title="건수"),
                y=alt.Y("유형:N", sort='-x', title=None),
                color=alt.Color("유형:N", legend=None),
                tooltip=["유형", "건수"]
            ).properties(
                height=180,
                background='rgba(0,0,0,0)' # 👈 배경을 완전 투명으로 설정
            ).configure_view(
                strokeOpacity=0,
                fill='transparent'
            ).configure_axis(
                labelColor='white',        # 👈 글자가 안 보일 수 있으니 흰색으로 설정
                titleColor='white'
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
            if f and st.button("정밀 분석 시작", key="f_btn", width="stretch"):
                vt = analyze_file_vt(f)
                render_vt_results(vt) if vt else st.error("분석 중 에러가 발생했습니다.")

        with t2:
            u = st.text_input("검사할 URL 입력", placeholder="https://example.com",
                              label_visibility="collapsed")
            if u and st.button("링크 분석 시작", key="u_btn", width="stretch"):
                vt = analyze_url_vt(u)
                render_vt_results(vt) if vt else st.error("분석 중 에러가 발생했습니다.")