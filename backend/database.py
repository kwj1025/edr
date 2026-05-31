from sqlalchemy import (
    create_engine, Column, Integer, String,
    DateTime, Text, Float
)
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

DATABASE_URL = "postgresql://edr_use:0000@localhost:5432/edr_db"

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


class SysmonLog(Base):
    __tablename__ = "sysmon_logs"

    id               = Column(Integer, primary_key=True, autoincrement=True)
    recv_time        = Column(DateTime, default=datetime.now)
    gen_time         = Column(DateTime, nullable=True)
    host_ip          = Column(String(50))
    os_name          = Column(String(100))
    rule_level       = Column(String(20))
    risk             = Column(String(10))
    ai_risk          = Column(String(10),  nullable=True)
    detect_type      = Column(String(20))
    tactic_id        = Column(String(20))
    tactic_name      = Column(String(100))
    technique_id     = Column(String(20))
    technique_name   = Column(String(100))
    action_desc      = Column(Text)
    process_name     = Column(String(200))
    event_id         = Column(Integer)
    command_line     = Column(Text,        nullable=True)
    destination_ip   = Column(String(50),  nullable=True)
    destination_port = Column(String(10),  nullable=True)
    query_name       = Column(String(500), nullable=True)
    status           = Column(String(20),  default="신규")
    ai_score         = Column(Float,       nullable=True)


def init_db():
    Base.metadata.create_all(engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()