# JADE Ultimate Security Platform - API Router

from fastapi import APIRouter
from app.api.v1.endpoints import (
    auth,
    scans,
    vulnerabilities,
    reports,
    ai_analysis,
    dashboard,
)

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(scans.router)
api_router.include_router(vulnerabilities.router)
api_router.include_router(reports.router)
api_router.include_router(ai_analysis.router)
api_router.include_router(dashboard.router)