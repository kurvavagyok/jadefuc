# JADE Ultimate Security Platform - Reports API

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from app.core.database import get_db
from app.models.scan import Scan
from app.models.user import User
from app.api.v1.endpoints.auth import get_current_user

router = APIRouter(prefix="/reports", tags=["reports"])

@router.get("/{scan_id}", response_model=dict)
async def get_report(
    scan_id: str,
    report_type: str = Query("executive", regex="^(executive|technical|compliance)$"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(Scan).filter(and_(Scan.scan_id == scan_id, Scan.user_id == current_user.id))
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    report = getattr(scan, f"{report_type}_report", None)
    if not report:
        raise HTTPException(status_code=404, detail=f"{report_type.title()} report not available")
    return {
        "scan_id": scan.scan_id,
        "report_type": report_type,
        "content": report,
        "generated_at": scan.completed_at.isoformat() if scan.completed_at else None
    }