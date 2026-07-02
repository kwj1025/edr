from datetime import datetime
from typing import List, Optional

from fastapi import Depends, FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.database import SysmonLog, get_db, init_db


app = FastAPI(title="EDR Backend API")


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# DB 초기화
# ============================================================

@app.on_event("startup")
def startup_event():
    init_db()


# ============================================================
# Pydantic 모델
# ============================================================

class LogItem(BaseModel):
    recv_time: Optional[str] = None
    gen_time: Optional[str] = None
    host_ip: str
    os_name: Optional[str] = None

    rule_level: Optional[str] = "일반"
    risk: Optional[str] = "Low"

    ai_risk: Optional[str] = None
    ai_score: Optional[float] = None

    detect_type: Optional[str] = None

    tactic_id: Optional[str] = None
    tactic_name: Optional[str] = None
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None

    action_desc: Optional[str] = None
    process_name: Optional[str] = None

    event_id: Optional[int] = None
    command_line: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[str] = None
    query_name: Optional[str] = None

    status: Optional[str] = "신규"


class LogBatch(BaseModel):
    logs: List[LogItem]


# ============================================================
# 유틸
# ============================================================

def _parse_dt(value: Optional[str]):
    if value is None:
        return None

    if isinstance(value, datetime):
        return value

    value = str(value).strip()

    if value == "":
        return None

    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(value, fmt)
        except Exception:
            pass

    return None


def _dt_to_str(value):
    if value is None:
        return None

    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")

    return str(value)


def log_to_dict(log: SysmonLog):
    return {
        "id": log.id,
        "recv_time": _dt_to_str(log.recv_time),
        "gen_time": _dt_to_str(log.gen_time),
        "host_ip": log.host_ip,
        "os_name": log.os_name,
        "rule_level": log.rule_level,
        "risk": log.risk,
        "ai_risk": getattr(log, "ai_risk", None),
        "ai_score": getattr(log, "ai_score", None),
        "detect_type": log.detect_type,
        "tactic_id": log.tactic_id,
        "tactic_name": log.tactic_name,
        "technique_id": log.technique_id,
        "technique_name": log.technique_name,
        "action_desc": log.action_desc,
        "process_name": log.process_name,
        "event_id": log.event_id,
        "command_line": log.command_line,
        "destination_ip": log.destination_ip,
        "destination_port": log.destination_port,
        "query_name": log.query_name,
        "status": log.status,
    }


# ============================================================
# 기본 확인
# ============================================================

@app.get("/")
def root():
    return {
        "message": "EDR Backend API is running",
        "docs": "/docs",
    }


# ============================================================
# 로그 저장
# ============================================================

@app.post("/logs")
def create_logs(batch: LogBatch, db: Session = Depends(get_db)):
    saved_count = 0

    for item in batch.logs:
        recv_time = _parse_dt(item.recv_time) or datetime.now()
        gen_time = _parse_dt(item.gen_time)

        log = SysmonLog(
            recv_time=recv_time,
            gen_time=gen_time,
            host_ip=item.host_ip,
            os_name=item.os_name,
            rule_level=item.rule_level,
            risk=item.risk,
            ai_risk=item.ai_risk,
            ai_score=item.ai_score,
            detect_type=item.detect_type,
            tactic_id=item.tactic_id,
            tactic_name=item.tactic_name,
            technique_id=item.technique_id,
            technique_name=item.technique_name,
            action_desc=item.action_desc,
            process_name=item.process_name,
            event_id=item.event_id,
            command_line=item.command_line,
            destination_ip=item.destination_ip,
            destination_port=item.destination_port,
            query_name=item.query_name,
            status=item.status,
        )

        db.add(log)
        saved_count += 1

    db.commit()

    return {
        "저장된 건수": saved_count,
    }


# ============================================================
# 로그 조회
# ============================================================

@app.get("/logs")
def get_logs(
    db: Session = Depends(get_db),
    host: Optional[str] = Query(None, description="host_ip 필터"),
    host_ip: Optional[str] = Query(None, description="host_ip 필터"),
    level: Optional[str] = Query(None, description="rule_level 필터"),
    risk: Optional[str] = Query(None, description="risk 필터"),
    status: Optional[str] = Query(None, description="status 필터"),
    after_id: Optional[int] = Query(None, description="이 id 이후의 새 로그만 조회"),
    limit: int = Query(500, ge=1, le=5000),
):
    query = db.query(SysmonLog)

    target_host = host or host_ip

    if target_host:
        query = query.filter(SysmonLog.host_ip == target_host)

    if level:
        query = query.filter(SysmonLog.rule_level == level)

    if risk:
        query = query.filter(SysmonLog.risk == risk)

    if status:
        query = query.filter(SysmonLog.status == status)

    if after_id is not None:
        query = query.filter(SysmonLog.id > after_id)
        query = query.order_by(SysmonLog.id.asc())
    else:
        query = query.order_by(SysmonLog.id.desc())

    logs = query.limit(limit).all()

    return [log_to_dict(log) for log in logs]


# ============================================================
# 전체 삭제
# ============================================================

@app.delete("/logs")
def delete_logs(db: Session = Depends(get_db)):
    deleted_count = db.query(SysmonLog).delete()
    db.commit()

    return {
        "삭제된 건수": deleted_count,
    }