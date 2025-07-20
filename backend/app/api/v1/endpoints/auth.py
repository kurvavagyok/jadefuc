# JADE Ultimate Security Platform - Authentication API

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.models.user import User
from pydantic import BaseModel
import structlog

logger = structlog.get_logger()

router = APIRouter(prefix="/auth", tags=["authentication"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")

class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    is_active: bool

class Token(BaseModel):
    access_token: str
    token_type: str

async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)) -> User:
    """Get current authenticated user"""
    # Mock user for now
    from uuid import uuid4
    mock_user = User(
        id=str(uuid4()),
        username="admin",
        email="admin@jade-security.com",
        is_active=True
    )
    return mock_user

@router.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    """Login endpoint"""
    # Mock authentication for now
    return {
        "access_token": "mock_jwt_token",
        "token_type": "bearer"
    }

@router.get("/me", response_model=UserResponse)
async def read_users_me(current_user: User = Depends(get_current_user)):
    """Get current user info"""
    return current_user