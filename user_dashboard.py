import streamlit as st
import pandas as pd
import altair as alt
import hashlib
import requests
import base64
import time
import platform
import json
from response import response_by_risk
import sys
import os
import psutil
import datetime

# XGBoost 위협도 판별 임포트
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'xgboost'))
try:
    from threat_predictor import ThreatPredictor
    _THREAT_PREDICTOR = ThreatPredictor()
    _PREDICTOR_READY = _THREAT_PREDICTOR.is_ready()
except Exception as e:
    _THREAT_PREDICTOR = None
    _PREDICTOR_READY = False
    print(f"[WARN] 위협도 판별 모듈 로드 실패: {e}")

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
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'collector'))
try:
    import win32evtlog  # type: ignore[import]
    from sysmon_collector import collect, apply_jonghan_policy, collect_fileless
    _WIN32_OK = True
except ImportError as e:
    collect = None
    apply_jonghan_policy = None
    collect_fileless = None
    _WIN32_OK = False
    print(f"[WARN] Sysmon 수집기 임포트 실패: {e}")

# 실행 시점에 한 번만 체크
_SYSMON_READY: bool = _WIN32_OK and platform.system() == "Windows"

# ==================================================================
# session_state 초기화
# ==================================================================
if "sysmon_logs" not in st.session_state:
    st.session_state.sysmon_logs = pd.DataFrame()
    
# ==================================================================
# XGBoost 위협도 판별
# ==================================================================
def add_xgboost_threat_score(rows: list[dict]) -> list[dict]:
    """
    로그에 XGBoost 위협도 판별 결과 추가
    
    Args:
        rows: 원본 로그 리스트
        
    Returns:
        XGBoost 위협도 및 라벨이 추가된 로그 리스트
    """
    if not _PREDICTOR_READY or not rows:
        return rows
    
    try:
        for row in rows:
            if _THREAT_PREDICTOR:
                result = _THREAT_PREDICTOR.predict(row)
                if result['success']:
                    row['XGBoost_위협도'] = round(result['probability'] * 100, 2)
                    row['XGBoost_라벨'] = result['risk_label']
                else:
                    row['XGBoost_위협도'] = -1.0
                    row['XGBoost_라벨'] = 'Unknown'
            else:
                row['XGBoost_위협도'] = -1.0
                row['XGBoost_라벨'] = 'Unknown'
    except Exception as e:
        print(f"[WARN] XGBoost 위협도 추가 오류: {e}")
    
    return rows


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

    if not collect or not apply_jonghan_policy:
        return 0, 0, "Sysmon 수집기를 로드할 수 없습니다."

    try:
        rows = collect(max_records=max_records)
        if not rows:
            return 0, 0, ""
        
        rows = apply_jonghan_policy(rows)
        
        # XGBoost 위협도 추가
        rows = add_xgboost_threat_score(rows)

        st.session_state.sysmon_logs = pd.DataFrame(rows)
        sent, err = send_to_server(rows)
        return len(rows), sent, err

    except Exception as e:
        return 0, 0, str(e)


def collect_fileless_threats() -> tuple[int, int, str]:
    """Fileless 공격 탐지 및 서버 전송 (Returns: collected, sent, error)"""
    if not (_WIN32_OK and platform.system() == "Windows"):
        return 0, 0, "Windows 환경에서만 탐지 가능합니다. (pip install pywin32)"
    
    if not collect_fileless:
        return 0, 0, "Fileless 탐지 모듈을 로드할 수 없습니다."
    
    try:
        rows = collect_fileless(max_records=100)
        if not rows:
            return 0, 0, ""
        
        # XGBoost 위협도 추가 (가능하면)
        rows = add_xgboost_threat_score(rows)
        
        # 기존 로그에 추가
        if not st.session_state.sysmon_logs.empty:
            st.session_state.sysmon_logs = pd.concat(
                [st.session_state.sysmon_logs, pd.DataFrame(rows)],
                ignore_index=True
            )
        else:
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
                ["로그 수신 날짜", "위험도", "XGBoost_위협도", "XGBoost_라벨", "탐지 유형", "Tactic ID", "Technique Name", "프로세스", "행위 내용", "상태"]
                if c in st.session_state.sysmon_logs.columns]
            display_df = st.session_state.sysmon_logs[display_cols].head(10)
            st.dataframe(display_df, width="stretch", hide_index=True,
                         height=len(display_df) * 35 + 38)
        else:
            st.info("수집된 로그가 없습니다. Sysmon 로그를 수집하세요.")

        if st.button(
            f"🔍 Sysmon 로그 수집 ({TARGET_IDS_LABEL})",
            width="stretch",
            help="Event ID 1·3·5·22 수집 → XGBoost 위협도 판별 → 대시보드 표시 + 서버 전송",
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
                    threat_status = "✓ XGBoost 판별 완료" if _PREDICTOR_READY else "⚠️ XGBoost 미적용"
                    st.success(f"✅ {sent}건 수집 완료 → 서버 전송됨 ({threat_status})")
                st.rerun()
        
        # Fileless 공격 탐지 버튼
        if st.button(
            "🛡️ Fileless 공격 탐지 (PowerShell)",
            width="stretch",
            help="Event ID 4104 (PowerShell Script Logging) + 백그라운드 프로세스 모니터링",
        ):
            with st.spinner("Fileless 위협 탐지 중…"):
                collected, sent, err = collect_fileless_threats()
            if collected == 0:
                if err:
                    st.error(f"오류: {err}")
                else:
                    st.info("의심 Fileless 활동이 감지되지 않았습니다.")
            else:
                if err:
                    st.warning(f"⚠️ {collected}건 탐지됨, 서버 전송 실패: {err}")
                else:
                    threat_status = "✓ XGBoost 판별 완료" if _PREDICTOR_READY else "⚠️ XGBoost 미적용"
                    st.success(f"🚨 {sent}건 Fileless 위협 탐지 → 서버 전송됨 ({threat_status})")
                st.rerun()

        if not _SYSMON_READY:
            st.caption("⚠️ Windows + pywin32 필요  `pip install pywin32`")
        
        if not _PREDICTOR_READY:
            st.caption("⚠️ XGBoost 모델 로드 실패 - 위협도 판별 불가")


# ==================================================================
# 대응 결과 테이블
# ==================================================================

st.markdown("---")

with st.container(border=True):

    title_col, text_col, toggle_col = st.columns([7, 2, 1])

    if "auto_response" not in st.session_state:
        st.session_state.auto_response = True

    with title_col:
        st.markdown("### 대응 결과 현황")

    with toggle_col:
        st.toggle(
            "자동 대응 토글",
            key="auto_response",
            label_visibility="collapsed"
        )

    auto_response = st.session_state.auto_response

    with text_col:
        auto_text = "자동 대응 ON" if auto_response else "자동 대응 OFF"
        auto_color = "#10b981" if auto_response else "#ef4444"
        st.markdown(
            f"""
            <div style="
                text-align:right;
                font-weight:bold;
                color:{auto_color};
                margin-top:8px;
                font-size:16px;
            ">
                {auto_text}
            </div>
            """,
            unsafe_allow_html=True
        )

    if "response_results" not in st.session_state:
        st.session_state.response_results = []

    if "response_triggered" not in st.session_state:
        st.session_state.response_triggered = False

    if st.session_state.auto_response and not st.session_state.response_triggered:
        try:
            with open("test_data.json", "r") as f:
                test_data = json.load(f)

            for item in test_data:
                result = response_by_risk(
                    risk_level=item["risk_level"],
                    process_path=item["process_path"],
                    destination_ip=item["destination_ip"]
                )
                if result:
                    st.session_state.response_results.append(result)

            st.session_state.response_triggered = True

        except FileNotFoundError:
            #st.error("test_data.json 파일을 찾을 수 없습니다.")
            pass

    if st.session_state.response_results:
        response_df = pd.DataFrame(st.session_state.response_results)
    else:
        response_df = pd.DataFrame(columns=["대응 시간", "위험도", "프로세스 이름", "대응 방법", "차단된 IP", "대응 현황"])

    st.dataframe(response_df, width="stretch", hide_index=True, height=200)
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


# ==================================================================
# 실시간 프로세스 모니터링
# ==================================================================

# 의심 프로세스 키워드 목록 (fileless / 악성 가능성)
_SUSPICIOUS_KEYWORDS = [
    "powershell", "cmd", "wscript", "cscript", "mshta", "regsvr32",
    "rundll32", "certutil", "bitsadmin", "msiexec", "wmic",
    "schtasks", "at.exe", "net.exe", "netsh", "mimikatz",
    "psexec", "cobalt", "beacon", "empire", "metasploit"
]

def get_process_list() -> pd.DataFrame:
    """현재 실행 중인 프로세스 목록을 DataFrame으로 반환"""
    rows = []
    for proc in psutil.process_iter(['pid', 'name', 'status', 'cpu_percent',
                                      'memory_info', 'exe', 'username', 'create_time']):
        try:
            info = proc.info
            mem_mb = round(info['memory_info'].rss / 1024 / 1024, 1) if info['memory_info'] else 0
            exe_path = info['exe'] or ""
            name_lower = (info['name'] or "").lower()
            is_suspicious = any(kw in name_lower for kw in _SUSPICIOUS_KEYWORDS)

            try:
                create_dt = datetime.datetime.fromtimestamp(info['create_time']).strftime('%H:%M:%S')
            except Exception:
                create_dt = "-"

            rows.append({
                "PID":       info['pid'],
                "프로세스명": info['name'] or "-",
                "상태":      info['status'] or "-",
                "CPU%":      info['cpu_percent'],
                "메모리(MB)": mem_mb,
                "사용자":    info['username'] or "-",
                "시작 시간": create_dt,
                "실행 경로": exe_path,
                "의심 여부": "[의심]" if is_suspicious else "",
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    df = pd.DataFrame(rows)
    if not df.empty:
        df = df.sort_values("CPU%", ascending=False).reset_index(drop=True)
    return df


st.markdown("---")

with st.container(border=True):
    proc_title_col, proc_ctrl_col1, proc_ctrl_col2, proc_refresh_col = st.columns([4, 2, 2, 1])

    with proc_title_col:
        st.markdown("### 실시간 프로세스 모니터링")

    with proc_ctrl_col1:
        search_keyword = st.text_input(
            "프로세스 검색",
            placeholder="이름 또는 경로 검색...",
            label_visibility="collapsed",
            key="proc_search"
        )

    with proc_ctrl_col2:
        sort_by = st.selectbox(
            "정렬 기준",
            ["CPU%", "메모리(MB)", "PID", "프로세스명"],
            label_visibility="collapsed",
            key="proc_sort"
        )

    with proc_refresh_col:
        do_refresh = st.button("새로고침", key="proc_refresh_btn", use_container_width=True)

    # 프로세스 목록 로드
    if "proc_df" not in st.session_state or do_refresh:
        with st.spinner("프로세스 목록 수집 중..."):
            st.session_state.proc_df = get_process_list()

    proc_df = st.session_state.proc_df.copy()

    if not proc_df.empty:
        # 검색 필터
        if search_keyword:
            mask = (
                proc_df["프로세스명"].str.contains(search_keyword, case=False, na=False) |
                proc_df["실행 경로"].str.contains(search_keyword, case=False, na=False)
            )
            proc_df = proc_df[mask]

        # 정렬
        ascending = sort_by == "프로세스명"
        proc_df = proc_df.sort_values(sort_by, ascending=ascending).reset_index(drop=True)

        # 요약 지표
        total_proc    = len(st.session_state.proc_df)
        suspicious_cnt = len(st.session_state.proc_df[st.session_state.proc_df["의심 여부"] == "[의심]"])
        top_cpu_proc  = st.session_state.proc_df.iloc[0]["프로세스명"] if not st.session_state.proc_df.empty else "-"
        top_cpu_val   = st.session_state.proc_df.iloc[0]["CPU%"] if not st.session_state.proc_df.empty else 0

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("전체 프로세스", total_proc)
        m2.metric("의심 프로세스", suspicious_cnt,
                  delta=f"+{suspicious_cnt}" if suspicious_cnt > 0 else None,
                  delta_color="inverse")
        m3.metric("CPU 1위", top_cpu_proc)
        m4.metric("CPU%", f"{top_cpu_val:.1f}%")

        # 의심 프로세스 경고 배너
        if suspicious_cnt > 0:
            suspicious_names = ", ".join(
                st.session_state.proc_df[
                    st.session_state.proc_df["의심 여부"] == "[의심]"
                ]["프로세스명"].unique().tolist()[:10]
            )
            st.warning(f"의심 프로세스 {suspicious_cnt}건 탐지: {suspicious_names}")

        # 탭으로 전체/의심만 구분
        tab_all, tab_suspicious = st.tabs([f"전체 ({len(proc_df)})", f"의심 프로세스만 ({suspicious_cnt})"])

        with tab_all:
            st.dataframe(
                proc_df,
                width="stretch",
                hide_index=True,
                height=320,
                column_config={
                    "CPU%":       st.column_config.ProgressColumn("CPU%", min_value=0, max_value=100, format="%.1f%%"),
                    "메모리(MB)": st.column_config.NumberColumn("메모리(MB)", format="%.1f MB"),
                    "의심 여부":  st.column_config.TextColumn("의심"),
                }
            )

        with tab_suspicious:
            susp_df = proc_df[proc_df["의심 여부"] == "[의심]"]
            if susp_df.empty:
                st.success("현재 의심 프로세스가 없습니다.")
            else:
                st.dataframe(
                    susp_df,
                    width="stretch",
                    hide_index=True,
                    height=min(len(susp_df) * 38 + 40, 320),
                    column_config={
                        "CPU%":       st.column_config.ProgressColumn("CPU%", min_value=0, max_value=100, format="%.1f%%"),
                        "메모리(MB)": st.column_config.NumberColumn("메모리(MB)", format="%.1f MB"),
                    }
                )
    else:
        st.info("프로세스 정보를 불러올 수 없습니다.")

    st.caption(f"마지막 갱신: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  새로고침 버튼을 눌러 최신 상태를 반영하세요.")