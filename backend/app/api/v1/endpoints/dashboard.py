# JADE Ultimate Security Platform - Dashboard API

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.models.user import User
from app.api.v1.endpoints.auth import get_current_user
from app.services.ai_service import ai_service
from pydantic import BaseModel
from typing import Dict, Any, List
import structlog

logger = structlog.get_logger()

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

class DashboardStats(BaseModel):
    total_scans: int
    active_scans: int
    vulnerabilities_found: int
    critical_issues: int
    ai_models_available: Dict[str, Any]

@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get dashboard statistics"""
    
    # Get available AI models
    available_models = ai_service.get_available_models()
    
    return DashboardStats(
        total_scans=0,
        active_scans=0,
        vulnerabilities_found=0,
        critical_issues=0,
        ai_models_available=available_models
    )

@router.get("/ai-health")
async def get_ai_health(current_user: User = Depends(get_current_user)):
    """Get AI service health status"""
    return await ai_service.health_check()