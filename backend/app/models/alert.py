# JADE Ultimate Security Platform - Alert Model

from sqlalchemy import Column, String, Boolean, DateTime, JSON, func, Enum
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from uuid import uuid4
from app.core.database import Base
import enum

class AlertType(str, enum.Enum):
    SECURITY = "security"
    SYSTEM = "system"
    COMPLIANCE = "compliance"
    PERFORMANCE = "performance"

class AlertStatus(str, enum.Enum):
    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    alert_type = Column(Enum(AlertType), nullable=False)
    title = Column(String(255), nullable=False)
    message = Column(String, nullable=False)
    status = Column(Enum(AlertStatus), default=AlertStatus.ACTIVE)
    metadata = Column(JSON, default=dict)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    resolved_at = Column(DateTime, nullable=True)
    
    def __repr__(self):
        return f"<Alert(title='{self.title}', type='{self.alert_type}')>"