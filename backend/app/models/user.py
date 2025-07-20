# JADE Ultimate Security Platform - User Model

from sqlalchemy import Column, String, Boolean, DateTime, func
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from uuid import uuid4
from app.core.database import Base
from dataclasses import dataclass

class User(Base):
    __tablename__ = "users"
    
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=func.now())
    last_login = Column(DateTime, nullable=True)
    
    def __repr__(self):
        return f"<User(username='{self.username}', email='{self.email}')>"