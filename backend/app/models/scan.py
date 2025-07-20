# JADE Ultimate Security Platform - Scan Model

from sqlalchemy import Column, String, Boolean, DateTime, Integer, ForeignKey, JSON, Enum, func
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from uuid import uuid4
import datetime
from app.core.database import Base

import enum

class ScanType(str, enum.Enum):
    network = "network"
    vulnerability = "vulnerability"
    web_application = "web_application"
    port_scan = "port_scan"
    comprehensive = "comprehensive"

class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class Scan(Base):
    __tablename__ = "scans"
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_id = Column(String(32), unique=True, nullable=False, index=True)
    user_id = Column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    name = Column(String(128), nullable=True)
    description = Column(String(512), nullable=True)
    scan_type = Column(Enum(ScanType), nullable=False)
    target = Column(String(256), nullable=False)
    target_type = Column(String(64), nullable=True)
    scan_config = Column(JSON, default=dict)
    scan_options = Column(JSON, default=dict)
    priority = Column(String(16), default="medium")
    ai_analysis_enabled = Column(Boolean, default=False)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    progress = Column(Integer, default=0)
    progress_message = Column(String(256), nullable=True)
    scheduled_at = Column(DateTime, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    error_messages = Column(JSON, default=list)
    executive_report = Column(String, nullable=True)
    technical_report = Column(String, nullable=True)
    compliance_report = Column(String, nullable=True)
    critical_findings = Column(Integer, default=0)
    high_findings = Column(Integer, default=0)
    medium_findings = Column(Integer, default=0)
    low_findings = Column(Integer, default=0)
    info_findings = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)
    risk_score = Column(Integer, default=0)
    network_data = Column(JSON, default=dict)
    service_data = Column(JSON, default=dict)
    technical_data = Column(JSON, default=dict)

    vulnerabilities = relationship("Vulnerability", back_populates="scan")

    def generate_scan_id(self):
        self.scan_id = uuid4().hex[:16]

    def start_scan(self):
        self.status = ScanStatus.RUNNING
        self.started_at = datetime.datetime.now(datetime.timezone.utc)

    def complete_scan(self, success=True):
        self.status = ScanStatus.COMPLETED if success else ScanStatus.FAILED
        self.completed_at = datetime.datetime.now(datetime.timezone.utc)

    def update_progress(self, percent: int, message: str = None):
        self.progress = percent
        self.progress_message = message

    def calculate_risk_score(self):
        # Example formula: weighted sum (customize as needed)
        self.risk_score = self.critical_findings * 10 + self.high_findings * 7 + self.medium_findings * 4 + self.low_findings * 1

    def add_ai_analysis(self, analysis: dict, model: str):
        if not self.technical_report:
            self.technical_report = ""
        self.technical_report += f"\n\nAI Analysis by {model}:\n{analysis}"

class ScanTemplate(Base):
    __tablename__ = "scan_templates"
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    name = Column(String(128), unique=True, nullable=False)
    description = Column(String(512), nullable=True)
    scan_type = Column(Enum(ScanType), nullable=False)
    config = Column(JSON, default=dict)
    is_default = Column(Boolean, default=False)
    is_public = Column(Boolean, default=True)
    usage_count = Column(Integer, default=0)