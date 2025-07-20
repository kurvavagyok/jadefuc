# JADE Ultimate Security Platform - User Model

from sqlalchemy import Column, String, Boolean, DateTime, Integer, ForeignKey, JSON, Enum, func
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.ext.hybrid import hybrid_property
from uuid import uuid4
import datetime
import pyotp
import secrets
from app.core.database import Base
from app.utils.encryption import hash_password, verify_password

import enum

class UserRole(str, enum.Enum):
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"

class User(Base):
    __tablename__ = "users"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    username = Column(String(40), unique=True, nullable=False, index=True)
    email = Column(String(128), unique=True, nullable=False, index=True)
    full_name = Column(String(128), nullable=True)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    role = Column(Enum(UserRole), default=UserRole.viewer)
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(64), nullable=True)
    backup_codes = Column(JSON, default=list)  # List of strings
    api_key = Column(String(48), unique=True, nullable=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    last_login_at = Column(DateTime, nullable=True)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    
    sessions = relationship("UserSession", back_populates="user")
    audit_logs = relationship("UserAuditLog", back_populates="user")

    def set_password(self, password: str):
        self.hashed_password = hash_password(password)

    def verify_password(self, password: str) -> bool:
        return verify_password(password, self.hashed_password)
    
    def generate_api_key(self):
        self.api_key = secrets.token_urlsafe(32)

    def update_activity(self):
        self.last_login_at = datetime.datetime.now(datetime.timezone.utc)

    def is_locked(self) -> bool:
        if self.locked_until and datetime.datetime.now(datetime.timezone.utc) < self.locked_until:
            return True
        return False

    def record_login_attempt(self, success: bool, ip_address: str):
        if success:
            self.failed_login_attempts = 0
            self.locked_until = None
        else:
            self.failed_login_attempts += 1
            if self.failed_login_attempts > 5:
                self.locked_until = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15)

    # MFA: TOTP
    def generate_mfa_secret(self):
        self.mfa_secret = pyotp.random_base32()
        return self.mfa_secret

    def get_totp_uri(self) -> str:
        return f"otpauth://totp/JADE:{self.email}?secret={self.mfa_secret}&issuer=JADE"

    def verify_totp(self, token: str) -> bool:
        if self.mfa_secret:
            totp = pyotp.TOTP(self.mfa_secret)
            return totp.verify(token)
        return False

    def generate_backup_codes(self):
        self.backup_codes = [secrets.token_hex(8) for _ in range(5)]
        return self.backup_codes

    def use_backup_code(self, code: str) -> bool:
        if code in self.backup_codes:
            self.backup_codes.remove(code)
            return True
        return False

class UserSession(Base):
    __tablename__ = "user_sessions"
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    user_id = Column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    session_token = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    ip_address = Column(String(64), nullable=True)
    user_agent = Column(String(256), nullable=True)
    created_at = Column(DateTime, default=func.now())
    last_activity_at = Column(DateTime, default=func.now(), onupdate=func.now())
    expires_at = Column(DateTime, nullable=False)
    logout_at = Column(DateTime, nullable=True)

    user = relationship("User", back_populates="sessions")

class UserAuditLog(Base):
    __tablename__ = "user_audit_logs"
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    user_id = Column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    action = Column(String(64), nullable=False)
    ip_address = Column(String(64), nullable=True)
    user_agent = Column(String(256), nullable=True)
    timestamp = Column(DateTime, default=func.now())
    success = Column(Boolean, default=True)
    error_message = Column(String(256), nullable=True)

    user = relationship("User", back_populates="audit_logs")