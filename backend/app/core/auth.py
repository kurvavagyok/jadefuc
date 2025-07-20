# JADE Ultimate Security Platform - Advanced Authentication System
# Enterprise-grade authentication with MFA, RBAC, and audit logging

import os
import jwt
import pyotp
import qrcode
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_
from fastapi import HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import structlog

from app.core.config import settings
from app.core.database import get_db
from app.models.user import User, UserRole, UserSession, LoginAttempt, AuditLog
from app.utils.security import generate_secure_token, verify_ip_whitelist

logger = structlog.get_logger()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

class AuthenticationService:
    """Enterprise authentication service with MFA and RBAC"""
    
    def __init__(self):
        self.jwt_algorithm = settings.JWT_ALGORITHM
        self.secret_key = settings.JWT_SECRET_KEY
        self.access_token_expire = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        self.refresh_token_expire = timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
        
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        return pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        return pwd_context.verify(plain_password, hashed_password)
    
    def generate_mfa_secret(self) -> str:
        """Generate MFA secret for TOTP"""
        return pyotp.random_base32()
    
    def generate_mfa_qr(self, email: str, secret: str) -> bytes:
        """Generate QR code for MFA setup"""
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            email, issuer_name="JADE Ultimate Security"
        )
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        from io import BytesIO
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        return buffer.getvalue()
    
    def verify_mfa_token(self, secret: str, token: str) -> bool:
        """Verify MFA token"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=2)  # Allow 2-step window
    
    def create_access_token(self, data: Dict[str, Any]) -> str:
        """Create JWT access token"""
        to_encode = data.copy()
        expire = datetime.utcnow() + self.access_token_expire
        to_encode.update({"exp": expire, "type": "access"})
        return jwt.encode(to_encode, self.secret_key, algorithm=self.jwt_algorithm)
    
    def create_refresh_token(self, data: Dict[str, Any]) -> str:
        """Create JWT refresh token"""
        to_encode = data.copy()
        expire = datetime.utcnow() + self.refresh_token_expire
        to_encode.update({"exp": expire, "type": "refresh"})
        return jwt.encode(to_encode, self.secret_key, algorithm=self.jwt_algorithm)
    
    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.jwt_algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired")
        except jwt.JWTError:
            raise HTTPException(status_code=401, detail="Invalid token")
    
    async def authenticate_user(self, db: AsyncSession, email: str, password: str, 
                              mfa_token: Optional[str] = None, request: Request = None) -> Optional[User]:
        """Authenticate user with optional MFA"""
        
        # Get user
        result = await db.execute(select(User).filter(User.email == email))
        user = result.scalar_one_or_none()
        
        if not user:
            await self.log_failed_attempt(db, email, "user_not_found", request)
            return None
        
        # Check if account is locked
        if user.is_locked:
            await self.log_failed_attempt(db, email, "account_locked", request)
            raise HTTPException(status_code=423, detail="Account is locked")
        
        # Verify password
        if not self.verify_password(password, user.hashed_password):
            user.failed_login_attempts += 1
            
            # Lock account after 5 failed attempts
            if user.failed_login_attempts >= 5:
                user.is_locked = True
                user.locked_at = datetime.utcnow()
                await self.log_security_event(db, user.id, "account_locked", request)
            
            await db.commit()
            await self.log_failed_attempt(db, email, "invalid_password", request)
            return None
        
        # Check MFA if enabled
        if user.mfa_enabled:
            if not mfa_token:
                raise HTTPException(status_code=422, detail="MFA token required")
            
            if not self.verify_mfa_token(user.mfa_secret, mfa_token):
                await self.log_failed_attempt(db, email, "invalid_mfa", request)
                return None
        
        # Reset failed attempts on successful login
        user.failed_login_attempts = 0
        user.last_login = datetime.utcnow()
        await db.commit()
        
        # Log successful login
        await self.log_security_event(db, user.id, "login_success", request)
        
        return user
    
    async def create_user_session(self, db: AsyncSession, user: User, request: Request) -> UserSession:
        """Create user session with tracking"""
        
        session_token = generate_secure_token()
        user_agent = request.headers.get("user-agent", "")
        ip_address = request.client.host if request.client else "unknown"
        
        session = UserSession(
            user_id=user.id,
            session_token=session_token,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=datetime.utcnow() + self.access_token_expire
        )
        
        db.add(session)
        await db.commit()
        await db.refresh(session)
        
        return session
    
    async def invalidate_session(self, db: AsyncSession, session_token: str):
        """Invalidate user session"""
        result = await db.execute(
            select(UserSession).filter(UserSession.session_token == session_token)
        )
        session = result.scalar_one_or_none()
        
        if session:
            session.is_active = False
            session.logged_out_at = datetime.utcnow()
            await db.commit()
    
    async def log_failed_attempt(self, db: AsyncSession, email: str, reason: str, request: Request):
        """Log failed login attempt"""
        attempt = LoginAttempt(
            email=email,
            ip_address=request.client.host if request.client else "unknown",
            user_agent=request.headers.get("user-agent", ""),
            failure_reason=reason,
            attempted_at=datetime.utcnow()
        )
        
        db.add(attempt)
        await db.commit()
    
    async def log_security_event(self, db: AsyncSession, user_id: str, event_type: str, 
                                request: Request, details: Optional[Dict] = None):
        """Log security event for audit"""
        
        audit_log = AuditLog(
            user_id=user_id,
            event_type=event_type,
            ip_address=request.client.host if request.client else "unknown",
            user_agent=request.headers.get("user-agent", ""),
            details=details or {},
            timestamp=datetime.utcnow()
        )
        
        db.add(audit_log)
        await db.commit()
        
        logger.info("security_event", 
                   user_id=user_id, 
                   event_type=event_type,
                   ip_address=audit_log.ip_address)

# Global auth service
auth_service = AuthenticationService()

class RoleChecker:
    """Role-based access control checker"""
    
    def __init__(self, required_roles: List[UserRole]):
        self.required_roles = required_roles
    
    def __call__(self, current_user: User = Depends(get_current_user)) -> User:
        if not any(role in current_user.roles for role in self.required_roles):
            raise HTTPException(
                status_code=403, 
                detail=f"Insufficient permissions. Required: {[r.value for r in self.required_roles]}"
            )
        return current_user

# Dependency functions
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> User:
    """Get current authenticated user"""
    
    token = credentials.credentials
    payload = auth_service.verify_token(token)
    user_id = payload.get("sub")
    
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # Check if session is still active
    session_token = payload.get("session_token")
    if session_token:
        result = await db.execute(
            select(UserSession).filter(
                and_(
                    UserSession.session_token == session_token,
                    UserSession.is_active == True,
                    UserSession.expires_at > datetime.utcnow()
                )
            )
        )
        session = result.scalar_one_or_none()
        
        if not session:
            raise HTTPException(status_code=401, detail="Session expired")
    
    # Get user
    result = await db.execute(select(User).filter(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    
    return user

# Role-based access decorators
require_admin = RoleChecker([UserRole.ADMIN])
require_analyst = RoleChecker([UserRole.ADMIN, UserRole.ANALYST])
require_viewer = RoleChecker([UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER])

# Permission classes for different access levels
class PermissionLevel:
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"

def check_permission(user: User, resource: str, action: str) -> bool:
    """Check if user has permission for specific resource/action"""
    
    # Admin can do everything
    if UserRole.ADMIN in user.roles:
        return True
    
    # Define role permissions
    role_permissions = {
        UserRole.ANALYST: {
            "scans": [PermissionLevel.READ, PermissionLevel.WRITE],
            "vulnerabilities": [PermissionLevel.READ, PermissionLevel.WRITE],
            "ai_analysis": [PermissionLevel.READ, PermissionLevel.WRITE],
            "reports": [PermissionLevel.READ, PermissionLevel.WRITE]
        },
        UserRole.VIEWER: {
            "scans": [PermissionLevel.READ],
            "vulnerabilities": [PermissionLevel.READ],
            "ai_analysis": [PermissionLevel.READ],
            "reports": [PermissionLevel.READ]
        }
    }
    
    for role in user.roles:
        if role in role_permissions:
            resource_permissions = role_permissions[role].get(resource, [])
            if action in resource_permissions:
                return True
    
    return False