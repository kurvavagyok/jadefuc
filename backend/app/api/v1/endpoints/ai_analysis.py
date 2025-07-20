# JADE Ultimate Security Platform - AI Analysis API

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from app.core.database import get_db
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.services.ai_service import AIService
from app.api.v1.endpoints.auth import get_current_user
import structlog

logger = structlog.get_logger()

router = APIRouter(prefix="/ai", tags=["ai_analysis"])

@router.post("/analyze")
async def analyze_scan(
    scan_id: str,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(Scan).filter(and_(Scan.scan_id == scan_id, Scan.user_id == current_user.id))
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Scan must be completed for AI analysis")
    background_tasks.add_task(perform_ai_analysis, scan.id, db)
    return {"message": "AI analysis started"}

async def perform_ai_analysis(scan_id, db: AsyncSession):
    try:
        ai_service = AIService()
        result = await db.execute(select(Scan).filter(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if scan:
            scan_data = scan.__dict__
            analysis = await ai_service.analyze_scan_results(scan_data)
            scan.add_ai_analysis(analysis, "gpt-4")
            await db.commit()
            logger.info("ai_analysis_completed", scan_id=str(scan_id))
    except Exception as e:
        logger.error("ai_analysis_error", scan_id=str(scan_id), error=str(e))