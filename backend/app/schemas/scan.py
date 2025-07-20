from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from uuid import UUID
from datetime import datetime

class ScanCreate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    scan_type: str
    target: str
    target_type: Optional[str] = None
    config: Optional[Dict[str, Any]] = {}
    options: Optional[Dict[str, Any]] = {}
    priority: Optional[str] = "medium"
    ai_analysis_enabled: Optional[bool] = False
    scheduled_at: Optional[datetime] = None

class ScanResponse(BaseModel):
    scan_id: str
    name: Optional[str]
    description: Optional[str]
    scan_type: str
    target: str
    status: str
    progress: int
    progress_message: Optional[str]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    risk_score: Optional[int]

    class Config:
        orm_mode = True

class ScanUpdate(BaseModel):
    name: Optional[str]
    description: Optional[str]
    priority: Optional[str]

class ScanListResponse(BaseModel):
    items: List[ScanResponse]
    total: int
    skip: int
    limit: int