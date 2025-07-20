# JADE Ultimate Security Platform - Alert Model

from sqlalchemy import Column, String, Boolean, DateTime, Integer, ForeignKey, JSON, func
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import relationship
from uuid import uuid4
from app.core.database import Base

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    user_id = Column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    scan_id = Column(PG_UUID(as_uuid=True), ForeignKey("scans.id"), nullable=True)
    vulnerability_id = Column(PG_UUID(as_uuid=True), ForeignKey("vulnerabilities.id"), nullable=True)
    type = Column(String(64), nullable=False)
    severity = Column(String(16), nullable=False)
    message = Column(String(512), nullable=False)
    data = Column(JSON, default=dict)
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime, default=func.now())

    # Relationships, if needed
    # user = relationship("User")
    # scan = relationship("Scan")
    # vulnerability = relationship("Vulnerability")