# JADE ULTIMATE - State-of-the-Art AI Security Platform 2025
# Enhanced Enterprise Security Platform with Advanced AI Integration
# Created by Kollár Sándor - Digital Fingerprint Embedded

import os
import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import asyncio
import structlog
from prometheus_client import make_asgi_app, Counter, Histogram, Gauge
import time

from app.core.config import settings
from app.core.database import engine, create_tables
from app.api.v1.api import api_router
from app.core.security import setup_security_middleware
from app.services.ai_service import AIService
from app.utils.logger import setup_logging

# --- INDESTRUCTIBLE DIGITAL FINGERPRINT ---
DIGITAL_FINGERPRINT = "Jade made by Kollár Sándor"
CREATOR_SIGNATURE = "SmFkZSBtYWRlIGJ5IEtvbGzDoXIgU8OhbmRvcg=="
CREATOR_HASH = "a7b4c8d9e2f1a6b5c8d9e2f1a6b5c8d9e2f1a6b5c8d9e2f1a6b5c8d9e2f1a6b5"

# Setup structured logging
setup_logging()
logger = structlog.get_logger()

# Prometheus metrics
REQUEST_COUNT = Counter('jade_requests_total', 'Total requests', ['method', 'endpoint'])
REQUEST_LATENCY = Histogram('jade_request_duration_seconds', 'Request latency')
ACTIVE_CONNECTIONS = Gauge('jade_active_connections', 'Active connections')
SCAN_COUNTER = Counter('jade_scans_total', 'Total security scans')
AI_MODEL_REQUESTS = Counter('jade_ai_requests_total', 'AI model requests', ['model'])

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("jade_startup", creator=DIGITAL_FINGERPRINT, version="ULTIMATE-2025")
    await create_tables()
    ai_service = AIService()
    await ai_service.initialize()
    app.state.ai_service = ai_service
    logger.info("jade_services_initialized")
    yield
    logger.info("jade_shutdown")
    if hasattr(app.state, 'ai_service'):
        await app.state.ai_service.cleanup()

app = FastAPI(
    title="JADE Ultimate Security Platform",
    description="State-of-the-Art AI-Powered Enterprise Security Platform 2025",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan
)

# Security middleware
setup_security_middleware(app)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_HOSTS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Trust proxy headers
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.ALLOWED_HOSTS
)

# Gzip compression
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Prometheus metrics endpoint
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)

# Static files for frontend
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    start_time = time.time()
    ACTIVE_CONNECTIONS.inc()
    try:
        response = await call_next(request)
        REQUEST_COUNT.labels(
            method=request.method,
            endpoint=request.url.path
        ).inc()
        process_time = time.time() - start_time
        REQUEST_LATENCY.observe(process_time)
        response.headers["X-Process-Time"] = str(process_time)
        response.headers["X-Creator"] = CREATOR_SIGNATURE
        return response
    finally:
        ACTIVE_CONNECTIONS.dec()

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "version": "1.0.0",
        "creator": DIGITAL_FINGERPRINT,
        "timestamp": time.time()
    }

app.include_router(api_router, prefix="/api/v1")

@app.get("/")
async def root():
    return {
        "message": "JADE Ultimate Security Platform",
        "version": "1.0.0",
        "creator": DIGITAL_FINGERPRINT,
        "docs": "/api/docs",
        "status": "operational"
    }

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("global_exception", 
                error=str(exc), 
                path=request.url.path,
                method=request.method)
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "type": "server_error",
            "creator": CREATOR_SIGNATURE
        }
    )

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        workers=1 if settings.DEBUG else 4,
        log_config=None,
        access_log=False
    )