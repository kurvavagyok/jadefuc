# JADE Ultimate Security Platform - Enhanced Authentication API
# Enterprise-grade auth endpoints with MFA, session management, and audit logging

from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func
from datetime import datetime, timedelta
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field
import structlog

from app.core.database import get_db
from app.core.auth import auth_service, get_current_user, require_admin, UserRole
from app.models.user import User, UserSession, LoginAttempt, AuditLog, UserStatus
from app.utils.security import generate_backup_codes, check_password_strength, generate_api_key

logger = structlog.get_logger()

router = APIRouter(prefix="/auth", tags=["authentication"])

# Pydantic models for API
class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    mfa_token: Optional[str] = None
    remember_me: bool = False

class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: dict
    mfa_required: bool = False

class MFASetupResponse(BaseModel):
    secret: str
    qr_code: str  # Base64 encoded PNG
    backup_codes: List[str]

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: Optional[str] = None
    roles: List[str] = Field(default=["viewer"])

class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    department: Optional[str] = None
    job_title: Optional[str] = None
    phone: Optional[str] = None
    timezone: Optional[str] = None

class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8)

class PasswordReset(BaseModel):
    email: EmailStr

class UserProfile(BaseModel):
    id: str
    username: str
    email: str
    full_name: Optional[str]
    roles: List[str]
    is_active: bool
    mfa_enabled: bool
    created_at: datetime
    last_login: Optional[datetime]

@router.post("/login", response_model=LoginResponse)
async def login(
    request: LoginRequest,
    http_request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db)
):
    """Enhanced login with MFA support and session tracking"""
    
    user = await auth_service.authenticate_user(
        db, 
        request.email, 
        request.password, 
        request.mfa_token,
        http_request
    )
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # Check if MFA is required but not provided
    if user.mfa_enabled and not request.mfa_token:
        return LoginResponse(
            access_token="",
            refresh_token="",
            expires_in=0,
            user={},
            mfa_required=True
        )
    
    # Create session
    session = await auth_service.create_user_session(db, user, http_request)
    
    # Create tokens
    token_data = {
        "sub": str(user.id),
        "email": user.email,
        "roles": user.roles or [],
        "session_token": session.session_token
    }
    
    access_token = auth_service.create_access_token(token_data)
    refresh_token = auth_service.create_refresh_token(token_data)
    
    # Set HTTP-only cookie for refresh token if remember_me
    if request.remember_me:
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            secure=True,
            samesite="strict",
            max_age=7 * 24 * 60 * 60  # 7 days
        )
    
    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=auth_service.access_token_expire.total_seconds(),
        user={
            "id": str(user.id),
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "roles": user.roles or [],
            "mfa_enabled": user.mfa_enabled
        }
    )

@router.post("/logout")
async def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Logout and invalidate session"""
    
    # Get session token from the JWT
    auth_header = request.headers.get("authorization")
    if auth_header:
        token = auth_header.replace("Bearer ", "")
        try:
            payload = auth_service.verify_token(token)
            session_token = payload.get("session_token")
            if session_token:
                await auth_service.invalidate_session(db, session_token)
        except:
            pass  # Token might be expired, that's OK
    
    # Log security event
    await auth_service.log_security_event(
        db, str(current_user.id), "logout", request
    )
    
    return {"message": "Successfully logged out"}

@router.get("/me", response_model=UserProfile)
async def get_current_user_profile(
    current_user: User = Depends(get_current_user)
):
    """Get current user profile"""
    
    return UserProfile(
        id=str(current_user.id),
        username=current_user.username,
        email=current_user.email,
        full_name=current_user.full_name,
        roles=current_user.roles or [],
        is_active=current_user.is_active,
        mfa_enabled=current_user.mfa_enabled,
        created_at=current_user.created_at,
        last_login=current_user.last_login
    )

@router.post("/setup-mfa", response_model=MFASetupResponse)
async def setup_mfa(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Setup MFA for user account"""
    
    if current_user.mfa_enabled:
        raise HTTPException(
            status_code=400,
            detail="MFA is already enabled"
        )
    
    # Generate MFA secret
    mfa_secret = auth_service.generate_mfa_secret()
    
    # Generate QR code
    qr_code_bytes = auth_service.generate_mfa_qr(current_user.email, mfa_secret)
    qr_code_base64 = base64.b64encode(qr_code_bytes).decode()
    
    # Generate backup codes
    backup_codes = generate_backup_codes()
    
    # Store in user record (not enabled yet)
    current_user.mfa_secret = mfa_secret
    current_user.backup_codes = backup_codes
    
    await db.commit()
    
    # Log security event
    await auth_service.log_security_event(
        db, str(current_user.id), "mfa_setup_started", 
        request=None  # We'll need to pass request here
    )
    
    return MFASetupResponse(
        secret=mfa_secret,
        qr_code=qr_code_base64,
        backup_codes=backup_codes
    )

@router.post("/enable-mfa")
async def enable_mfa(
    mfa_token: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Enable MFA after verification"""
    
    if not current_user.mfa_secret:
        raise HTTPException(
            status_code=400,
            detail="MFA not set up. Please setup MFA first."
        )
    
    if not auth_service.verify_mfa_token(current_user.mfa_secret, mfa_token):
        raise HTTPException(
            status_code=400,
            detail="Invalid MFA token"
        )
    
    # Enable MFA
    current_user.mfa_enabled = True
    await db.commit()
    
    # Log security event
    await auth_service.log_security_event(
        db, str(current_user.id), "mfa_enabled",
        request=None  # We'll need to pass request here
    )
    
    return {"message": "MFA enabled successfully"}

@router.post("/disable-mfa")
async def disable_mfa(
    password: str,
    mfa_token: Optional[str] = None,
    backup_code: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Disable MFA with password confirmation"""
    
    if not current_user.mfa_enabled:
        raise HTTPException(
            status_code=400,
            detail="MFA is not enabled"
        )
    
    # Verify password
    if not auth_service.verify_password(password, current_user.hashed_password):
        raise HTTPException(
            status_code=400,
            detail="Invalid password"
        )
    
    # Verify MFA token or backup code
    if mfa_token:
        if not auth_service.verify_mfa_token(current_user.mfa_secret, mfa_token):
            raise HTTPException(
                status_code=400,
                detail="Invalid MFA token"
            )
    elif backup_code:
        if backup_code not in (current_user.backup_codes or []):
            raise HTTPException(
                status_code=400,
                detail="Invalid backup code"
            )
        # Remove used backup code
        current_user.backup_codes.remove(backup_code)
    else:
        raise HTTPException(
            status_code=400,
            detail="MFA token or backup code required"
        )
    
    # Disable MFA
    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    current_user.backup_codes = []
    
    await db.commit()
    
    return {"message": "MFA disabled successfully"}

@router.post("/change-password")
async def change_password(
    request: PasswordChange,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Change user password"""
    
    # Verify current password
    if not auth_service.verify_password(request.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=400,
            detail="Invalid current password"
        )
    
    # Check new password strength
    strength = check_password_strength(request.new_password)
    if strength["strength"] in ["very_weak", "weak"]:
        raise HTTPException(
            status_code=400,
            detail=f"Password too weak: {', '.join(strength['feedback'])}"
        )
    
    # Update password
    current_user.hashed_password = auth_service.hash_password(request.new_password)
    current_user.password_changed_at = datetime.utcnow()
    
    await db.commit()
    
    return {"message": "Password changed successfully"}

@router.get("/sessions")
async def get_user_sessions(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get user's active sessions"""
    
    result = await db.execute(
        select(UserSession).filter(
            and_(
                UserSession.user_id == current_user.id,
                UserSession.is_active == True,
                UserSession.expires_at > datetime.utcnow()
            )
        ).order_by(UserSession.last_activity.desc())
    )
    
    sessions = result.scalars().all()
    
    return [
        {
            "id": str(session.id),
            "ip_address": session.ip_address,
            "user_agent": session.user_agent,
            "created_at": session.created_at,
            "last_activity": session.last_activity,
            "expires_at": session.expires_at
        }
        for session in sessions
    ]

@router.delete("/sessions/{session_id}")
async def revoke_session(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Revoke a specific session"""
    
    result = await db.execute(
        select(UserSession).filter(
            and_(
                UserSession.id == session_id,
                UserSession.user_id == current_user.id
            )
        )
    )
    
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(
            status_code=404,
            detail="Session not found"
        )
    
    session.is_active = False
    session.logged_out_at = datetime.utcnow()
    
    await db.commit()
    
    return {"message": "Session revoked successfully"}

# Admin endpoints
@router.post("/users", dependencies=[Depends(require_admin)])
async def create_user(
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create new user (Admin only)"""
    
    # Check if user exists
    result = await db.execute(
        select(User).filter(
            or_(User.email == user_data.email, User.username == user_data.username)
        )
    )
    existing_user = result.scalar_one_or_none()
    
    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="User with this email or username already exists"
        )
    
    # Validate roles
    valid_roles = [role.value for role in UserRole]
    for role in user_data.roles:
        if role not in valid_roles:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid role: {role}"
            )
    
    # Check password strength
    strength = check_password_strength(user_data.password)
    if strength["strength"] in ["very_weak", "weak"]:
        raise HTTPException(
            status_code=400,
            detail=f"Password too weak: {', '.join(strength['feedback'])}"
        )
    
    # Create user
    new_user = User(
        username=user_data.username,
        email=user_data.email,
        full_name=user_data.full_name,
        hashed_password=auth_service.hash_password(user_data.password),
        roles=user_data.roles,
        status=UserStatus.ACTIVE,
        is_active=True
    )
    
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    
    return {
        "id": str(new_user.id),
        "username": new_user.username,
        "email": new_user.email,
        "message": "User created successfully"
    }

@router.get("/audit-logs", dependencies=[Depends(require_admin)])
async def get_audit_logs(
    limit: int = 100,
    offset: int = 0,
    user_id: Optional[str] = None,
    event_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """Get audit logs (Admin only)"""
    
    query = select(AuditLog)
    
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    
    if event_type:
        query = query.filter(AuditLog.event_type == event_type)
    
    query = query.order_by(AuditLog.timestamp.desc()).limit(limit).offset(offset)
    
    result = await db.execute(query)
    logs = result.scalars().all()
    
    return [
        {
            "id": str(log.id),
            "user_id": str(log.user_id) if log.user_id else None,
            "event_type": log.event_type,
            "ip_address": log.ip_address,
            "timestamp": log.timestamp,
            "details": log.details
        }
        for log in logs
    ]