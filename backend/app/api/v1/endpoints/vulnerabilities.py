# JADE Ultimate Security Platform - Vulnerabilities API

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, and_
from typing import List, Optional
from app.core.database import get_db
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.api.v1.endpoints.auth import get_current_user

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])

@router.get("/", response_model=List[dict])
async def list_vulnerabilities(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    severity: Optional[str] = None,
    unresolved: bool = False,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    query = select(Vulnerability)
    if severity:
        query = query.filter(Vulnerability.severity == severity)
    if unresolved:
        query = query.filter(Vulnerability.is_resolved == False)
    query = query.order_by(desc(Vulnerability.detected_at)).offset(skip).limit(limit)
    result = await db.execute(query)
    vulns = result.scalars().all()
    return [vuln.to_dict() for vuln in vulns]

@router.get("/{vuln_id}", response_model=dict)
async def get_vulnerability(
    vuln_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(Vulnerability).filter(Vulnerability.id == vuln_id)
    )
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return vuln.to_dict()

@router.put("/{vuln_id}/resolve")
async def resolve_vulnerability(
    vuln_id: str,
    notes: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(Vulnerability).filter(Vulnerability.id == vuln_id)
    )
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    vuln.is_resolved = True
    vuln.resolution_notes = notes
    vuln.resolved_at = vuln.resolved_at or __import__('datetime').datetime.now(__import__('datetime').timezone.utc)
    await db.commit()
    return {"message": "Vulnerability resolved"}