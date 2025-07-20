# JADE Ultimate Security Platform - AI Model Tracking

from sqlalchemy import Column, String, Boolean, DateTime, Integer, Float, JSON, func
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from uuid import uuid4
from app.core.database import Base

class AIModel(Base):
    __tablename__ = "ai_models"
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    provider = Column(String(32), nullable=False)
    name = Column(String(64), nullable=False)
    version = Column(String(32), nullable=True)
    description = Column(String(256), nullable=True)
    usage_count = Column(Integer, default=0)
    last_used_at = Column(DateTime, default=func.now())
    metrics = Column(JSON, default=dict)
    is_active = Column(Boolean, default=True)

class AIRequest(Base):
    __tablename__ = "ai_requests"
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    model_id = Column(PG_UUID(as_uuid=True), nullable=True)
    prompt = Column(String, nullable=False)
    response = Column(String, nullable=True)
    context = Column(String(64), nullable=True)
    latency_ms = Column(Float, default=0)
    success = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())