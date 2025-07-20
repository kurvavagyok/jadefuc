# JADE Ultimate Security Platform - AI Analysis API

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from app.core.database import get_db
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.services.ai_service import ai_service
from app.api.v1.endpoints.auth import get_current_user
from app.core.config import settings, AI_MODELS
from pydantic import BaseModel
from typing import List, Dict, Any
import structlog

logger = structlog.get_logger()

router = APIRouter(prefix="/ai", tags=["ai_analysis"])

class AnalysisRequest(BaseModel):
    scan_id: str
    model: str = "gpt-4"

class ModelListResponse(BaseModel):
    models: Dict[str, Any]

class AnalysisResponse(BaseModel):
    message: str
    analysis_id: str

@router.get("/models", response_model=ModelListResponse)
async def list_available_models(current_user: User = Depends(get_current_user)):
    """Get list of available AI models"""
    # Return the models with availability based on API keys
    models = {}
    for model_name, config in AI_MODELS.items():
        provider = config['provider']
        is_available = False
        
        if provider == 'openai' and settings.OPENAI_API_KEY:
            is_available = True
        elif provider == 'google' and settings.GEMINI_API_KEY:
            is_available = True
        elif provider == 'github' and settings.GITHUB_TOKEN:
            is_available = True
        elif provider == 'cerebras' and settings.CEREBRAS_API_KEY:
            is_available = True
            
        models[model_name] = {
            "provider": provider,
            "model": config['model'],
            "use_case": config['use_case'],
            "available": is_available
        }
    
    return ModelListResponse(models=models)

@router.post("/analyze", response_model=AnalysisResponse)
async def analyze_scan(
    request: AnalysisRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Start AI analysis of scan results"""
    
    # For now, return mock response since we don't have actual scan data
    mock_scan_data = {
        "scan_id": request.scan_id,
        "scan_type": "network",
        "target": "example.com",
        "status": "completed",
        "results": {
            "open_ports": [80, 443, 22],
            "services": ["http", "https", "ssh"],
            "vulnerabilities": []
        }
    }
    
    background_tasks.add_task(perform_ai_analysis, request.scan_id, request.model, mock_scan_data)
    
    return AnalysisResponse(
        message="AI analysis started",
        analysis_id=request.scan_id
    )

@router.post("/test/{model}")
async def test_model(
    model: str,
    current_user: User = Depends(get_current_user)
):
    """Test AI model with a simple prompt"""
    
    try:
        response = await ai_service.generate_completion(
            prompt="Hello! Please respond with a brief test message to confirm you're working correctly.",
            model=model,
            system_prompt="You are a helpful AI assistant for security analysis.",
            temperature=0.1,
            max_tokens=100
        )
        
        return {
            "model": model,
            "status": "success",
            "response": response.content,
            "provider": response.provider,
            "latency_ms": response.latency_ms,
            "tokens_used": response.tokens_used
        }
        
    except Exception as e:
        logger.error("model_test_error", model=model, error=str(e))
        raise HTTPException(status_code=500, detail=f"Model test failed: {str(e)}")

async def perform_ai_analysis(scan_id: str, model: str, scan_data: Dict[str, Any]):
    """Perform AI analysis in background"""
    try:
        logger.info("ai_analysis_started", scan_id=scan_id, model=model)
        
        analysis = await ai_service.analyze_scan_results(scan_data, model)
        
        logger.info("ai_analysis_completed", 
                   scan_id=scan_id, 
                   model=model,
                   analysis_length=len(str(analysis)))
        
        # In a real implementation, you would save this to the database
        # For now, just log it
        
    except Exception as e:
        logger.error("ai_analysis_error", scan_id=scan_id, model=model, error=str(e))