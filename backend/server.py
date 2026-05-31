from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from backend.database import SysmonLog, get_db, init_db
import uvicorn


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="EDR 수집 서버", lifespan=lifespan)


class LogItem(BaseModel):
    recv_time:        Optional[str] = None
    gen_time:         Optional[str] = None
    host_ip:          str
    os_name:          Optional[str] = None
    rule_level:       Optional[str] = "일반"
    risk:             Optional[str] = "L"
    detect_type:      Optional[str] = None
    tactic_id:        Optional[str] = None
    tactic_name:      Optional[str] = None
    technique_id:     Optional[str] = None
    technique_name:   Optional[str] = None
    action_desc:      Optional[str] = None
    process_name:     Optional[str] = None
    event_id:         Optional[int] = None
    command_line:     Optional[str] = None
    destination_ip:   Optional[str] = None
    destination_port: Optional[str] = None
    query_name:       Optional[str] = None
    status:           Optional[str] = "신규"


class LogBatch(BaseModel):
    logs: List[LogItem]


@app.post("/logs")
def receive_logs(batch: LogBatch, db: Session = Depends(get_db)):
    for item in batch.logs:
        log = SysmonLog(
            recv_time        = datetime.now(),
            gen_time         = _parse_dt(item.gen_time),
            host_ip          = item.host_ip,
            os_name          = item.os_name,
            rule_level       = item.rule_level,
            risk             = item.risk,
            detect_type      = item.detect_type,
            tactic_id        = item.tactic_id,
            tactic_name      = item.tactic_name,
            technique_id     = item.technique_id,
            technique_name   = item.technique_name,
            action_desc      = item.action_desc,
            process_name     = item.process_name,
            event_id         = item.event_id,
            command_line     = item.command_line,
            destination_ip   = item.destination_ip,
            destination_port = item.destination_port,
            query_name       = item.query_name,
            status           = item.status,
        )
        db.add(log)
    db.commit()
    return {"저장된 건수": len(batch.logs)}

@app.get("/logs")
def get_logs(
    host:  Optional[str] = None,
    level: Optional[str] = None,
    limit: int = 1000,
    db:    Session = Depends(get_db)
):
    query = db.query(SysmonLog).order_by(SysmonLog.recv_time.desc())
    if host:
        query = query.filter(SysmonLog.host_ip == host)
    if level:
        query = query.filter(SysmonLog.rule_level == level)

    rows = query.limit(limit).all()

    # SQLAlchemy 객체 → 딕셔너리 변환
    return [
        {c.name: getattr(row, c.name) for c in row.__table__.columns}
        for row in rows
    ]

@app.delete("/logs")
def delete_logs(db: Session = Depends(get_db)):
    deleted = db.query(SysmonLog).delete()
    db.commit()
    return {"삭제된 건수": deleted}


def _parse_dt(dt_str):
    if not dt_str:
        return None
    try:
        return datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)