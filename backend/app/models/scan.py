# JADE Ultimate Security Platform - Scan Model

from sqlalchemy import Column, String, Boolean, DateTime, Integer, Float, JSON, func, Enum
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from uuid import uuid4
from app.core.database import Base
import enum

class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class ScanType(str, enum.Enum):
    NETWORK = "network"
    WEB = "web"
    VULNERABILITY = "vulnerability"
    PORT = "port"
    COMPREHENSIVE = "comprehensive"

class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_id = Column(String(64), unique=True, nullable=False, index=True)
    user_id = Column(PG_UUID(as_uuid=True), nullable=False, index=True)
    scan_type = Column(Enum(ScanType), nullable=False)
    target = Column(String(255), nullable=False)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    results = Column(JSON, default=dict)
    ai_analysis = Column(JSON, default=dict)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    completed_at = Column(DateTime, nullable=True)
    duration = Column(Float, default=0.0)
    
    def add_ai_analysis(self, analysis: dict, model: str):
        """Add AI analysis to scan results"""
        if not self.ai_analysis:
            self.ai_analysis = {}
        self.ai_analysis[model] = {
            "analysis": analysis,
            "timestamp": func.now()
        }
    
    def __repr__(self):
        return f"<Scan(id='{self.scan_id}', type='{self.scan_type}', status='{self.status}')>"