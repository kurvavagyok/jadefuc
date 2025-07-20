from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from uuid import UUID

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    full_name: Optional[str] = None
    password: str
    role: Optional[str] = "viewer"

class UserLogin(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: UUID
    username: str
    email: EmailStr
    full_name: Optional[str] = None
    is_active: bool
    role: str

    class Config:
        orm_mode = True

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse