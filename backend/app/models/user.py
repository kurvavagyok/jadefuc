# JADE Ultimate Security Platform - Enhanced User Models
# Enterprise authentication with MFA, RBAC, session tracking, and audit logging

from sqlalchemy import Column, String, Boolean, DateTime, Integer, JSON, Text, Enum as SQLEnum, ForeignKey
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import relationship
from uuid import uuid4
from datetime import datetime
import enum
from app.core.database import Base

class UserRole(str, enum.Enum):
    """User roles for RBAC"""
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    AUDIT = "audit"

class UserStatus(str, enum.Enum):
    """User account status"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING = "pending"

class User(Base):
    """Enhanced user model with enterprise features"""
    __tablename__ = "users"
    
    # Basic info
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(255), nullable=True)
    
    # Authentication
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    status = Column(SQLEnum(UserStatus), default=UserStatus.PENDING)
    
    # MFA
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(32), nullable=True)
    backup_codes = Column(JSON, default=list)  # For MFA backup
    
    # Security
    failed_login_attempts = Column(Integer, default=0)
    is_locked = Column(Boolean, default=False)
    locked_at = Column(DateTime, nullable=True)
    password_changed_at = Column(DateTime, default=datetime.utcnow)
    
    # Roles and permissions (stored as JSON array for flexibility)
    roles = Column(JSON, default=list)  # List of UserRole values
    permissions = Column(JSON, default=dict)  # Custom permissions
    
    # Profile and preferences
    department = Column(String(100), nullable=True)
    job_title = Column(String(100), nullable=True)
    phone = Column(String(20), nullable=True)
    timezone = Column(String(50), default="UTC")
    notification_preferences = Column(JSON, default=dict)
    
    # IP restrictions
    allowed_ips = Column(JSON, default=list)  # IP whitelist
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    last_activity = Column(DateTime, nullable=True)
    
    # Relationships
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<User(username='{self.username}', email='{self.email}', roles={self.roles})>"
    
    def has_role(self, role: UserRole) -> bool:
        """Check if user has specific role"""
        return role.value in (self.roles or [])
    
    def add_role(self, role: UserRole):
        """Add role to user"""
        if not self.roles:
            self.roles = []
        if role.value not in self.roles:
            self.roles.append(role.value)
    
    def remove_role(self, role: UserRole):
        """Remove role from user"""
        if self.roles and role.value in self.roles:
            self.roles.remove(role.value)
    
    def is_admin(self) -> bool:
        """Check if user is admin"""
        return self.has_role(UserRole.ADMIN)

class UserSession(Base):
    """User session tracking for security"""
    __tablename__ = "user_sessions"
    
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    user_id = Column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    session_token = Column(String(255), unique=True, nullable=False, index=True)
    
    # Session details
    ip_address = Column(String(45), nullable=True)  # IPv6 support
    user_agent = Column(Text, nullable=True)
    device_fingerprint = Column(String(255), nullable=True)
    
    # Session lifecycle
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    last_activity = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    logged_out_at = Column(DateTime, nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="sessions")
    
    def __repr__(self):
        return f"<UserSession(user_id='{self.user_id}', ip='{self.ip_address}', active={self.is_active})>"

class LoginAttempt(Base):
    """Failed login attempt tracking for security monitoring"""
    __tablename__ = "login_attempts"
    
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    email = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(45), nullable=True, index=True)
    user_agent = Column(Text, nullable=True)
    
    # Attempt details
    failure_reason = Column(String(100), nullable=False)  # invalid_password, user_not_found, etc.
    attempted_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    def __repr__(self):
        return f"<LoginAttempt(email='{self.email}', reason='{self.failure_reason}')>"

class AuditLog(Base):
    """Comprehensive audit logging for compliance"""
    __tablename__ = "audit_logs"
    
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    user_id = Column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)
    
    # Event details
    event_type = Column(String(100), nullable=False, index=True)  # login, logout, permission_change, etc.
    resource_type = Column(String(50), nullable=True)  # user, scan, vulnerability, etc.
    resource_id = Column(String(100), nullable=True)
    action = Column(String(50), nullable=True)  # create, read, update, delete
    
    # Request details
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    request_path = Column(String(500), nullable=True)
    request_method = Column(String(10), nullable=True)
    
    # Additional context
    details = Column(JSON, default=dict)  # Flexible additional information
    old_values = Column(JSON, nullable=True)  # For update operations
    new_values = Column(JSON, nullable=True)  # For update operations
    
    # Timestamp
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    user = relationship("User", back_populates="audit_logs")
    
    def __repr__(self):
        return f"<AuditLog(user_id='{self.user_id}', event='{self.event_type}', timestamp='{self.timestamp}')>"

class APIKey(Base):
    """API keys for programmatic access"""
    __tablename__ = "api_keys"
    
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    user_id = Column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    
    # Key details
    name = Column(String(100), nullable=False)  # Human-readable name
    key_hash = Column(String(255), nullable=False, unique=True)  # Hashed API key
    key_prefix = Column(String(10), nullable=False)  # First few chars for identification
    
    # Permissions and restrictions
    permissions = Column(JSON, default=list)  # List of allowed permissions
    allowed_ips = Column(JSON, default=list)  # IP restrictions
    rate_limit = Column(Integer, default=1000)  # Requests per hour
    
    # Usage tracking
    last_used = Column(DateTime, nullable=True)
    usage_count = Column(Integer, default=0)
    
    # Lifecycle
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<APIKey(name='{self.name}', prefix='{self.key_prefix}', active={self.is_active})>"