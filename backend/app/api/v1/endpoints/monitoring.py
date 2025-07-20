# JADE Ultimate Security Platform - Monitoring API Endpoints
# Endpoints for metrics, health checks, and observability

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, text
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import structlog
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

from app.core.database import get_db, get_pool_status
from app.core.monitoring import monitoring_service, alert_manager
from app.core.auth import get_current_user, require_admin
from app.models.user import User, AuditLog, LoginAttempt
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability

logger = structlog.get_logger()

router = APIRouter(prefix="/monitoring", tags=["monitoring"])

@router.get("/health")
async def health_check():
    """Comprehensive health check endpoint"""
    return monitoring_service.get_health_status()

@router.get("/metrics")
async def metrics_endpoint():
    """Prometheus metrics endpoint"""
    metrics_data = generate_latest()
    return PlainTextResponse(
        content=metrics_data.decode('utf-8'),
        media_type=CONTENT_TYPE_LATEST
    )

@router.get("/status")
async def system_status(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Detailed system status for dashboard"""
    
    # Database health check
    try:
        result = await db.execute(text("SELECT 1"))
        db_healthy = result.scalar() == 1
    except Exception:
        db_healthy = False
    
    # Database pool status
    pool_status = get_pool_status()
    
    # Get recent activity metrics
    current_time = datetime.utcnow()
    one_hour_ago = current_time - timedelta(hours=1)
    
    # Count recent activities
    recent_logins = await db.execute(
        select(func.count(AuditLog.id))
        .filter(AuditLog.event_type == 'login_success')
        .filter(AuditLog.timestamp >= one_hour_ago)
    )
    
    recent_scans = await db.execute(
        select(func.count(Scan.id))
        .filter(Scan.created_at >= one_hour_ago)
    )
    
    recent_vulnerabilities = await db.execute(
        select(func.count(Vulnerability.id))
        .filter(Vulnerability.created_at >= one_hour_ago)
    )
    
    failed_logins = await db.execute(
        select(func.count(LoginAttempt.id))
        .filter(LoginAttempt.attempted_at >= one_hour_ago)
    )
    
    # Get basic health status
    health_status = monitoring_service.get_health_status()
    metrics_summary = monitoring_service.get_metrics_summary()
    
    return {
        "overall_status": "healthy" if db_healthy else "degraded",
        "timestamp": current_time.isoformat(),
        "components": {
            "database": {
                "status": "healthy" if db_healthy else "unhealthy",
                "pool": pool_status
            },
            "monitoring": {
                "status": "healthy",
                "metrics_collected": True
            }
        },
        "system_metrics": health_status["system"],
        "application_metrics": {
            **metrics_summary,
            "recent_activity": {
                "logins_last_hour": recent_logins.scalar(),
                "scans_last_hour": recent_scans.scalar(),
                "vulnerabilities_last_hour": recent_vulnerabilities.scalar(),
                "failed_logins_last_hour": failed_logins.scalar()
            }
        },
        "uptime_seconds": health_status["uptime_seconds"]
    }

@router.get("/alerts")
async def get_alerts(
    active_only: bool = True,
    limit: int = 100,
    current_user: User = Depends(get_current_user)
):
    """Get system alerts"""
    
    if active_only:
        alerts = alert_manager.get_active_alerts()
    else:
        alerts = alert_manager.alert_history[-limit:]
    
    return {
        "alerts": alerts,
        "total_active": len(alert_manager.get_active_alerts()),
        "total_all": len(alert_manager.alert_history)
    }

@router.post("/alerts/{alert_id}/resolve")
async def resolve_alert(
    alert_id: str,
    current_user: User = Depends(require_admin)
):
    """Resolve an active alert (Admin only)"""
    
    success = alert_manager.resolve_alert(alert_id)
    
    if not success:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    return {"message": "Alert resolved successfully"}

@router.get("/performance")
async def performance_metrics(
    time_range: str = "1h",  # 1h, 24h, 7d
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get performance metrics over time"""
    
    # Parse time range
    if time_range == "1h":
        start_time = datetime.utcnow() - timedelta(hours=1)
        interval = "5 minutes"
    elif time_range == "24h":
        start_time = datetime.utcnow() - timedelta(days=1)
        interval = "1 hour"
    elif time_range == "7d":
        start_time = datetime.utcnow() - timedelta(days=7)
        interval = "6 hours"
    else:
        start_time = datetime.utcnow() - timedelta(hours=1)
        interval = "5 minutes"
    
    # This would typically query a time-series database
    # For now, return current metrics as baseline
    current_metrics = monitoring_service.get_health_status()
    
    return {
        "time_range": time_range,
        "start_time": start_time.isoformat(),
        "end_time": datetime.utcnow().isoformat(),
        "interval": interval,
        "metrics": {
            "cpu_usage": [current_metrics["system"]["cpu_usage_percent"]],
            "memory_usage": [current_metrics["system"]["memory_usage_percent"]],
            "disk_usage": [current_metrics["system"]["disk_usage_percent"]],
            "response_times": [],  # Would need historical data
            "request_counts": [],  # Would need historical data
            "error_rates": []      # Would need historical data
        },
        "timestamps": [datetime.utcnow().isoformat()]
    }

@router.get("/logs")
async def get_logs(
    level: str = "INFO",
    limit: int = 100,
    search: Optional[str] = None,
    current_user: User = Depends(require_admin)
):
    """Get application logs (Admin only)"""
    
    # This is a simplified implementation
    # In production, you'd query your log aggregation system
    
    return {
        "message": "Log endpoint available - integrate with your log aggregation system",
        "filters": {
            "level": level,
            "limit": limit,
            "search": search
        },
        "suggestion": "Integrate with ELK stack, Grafana Loki, or similar log aggregation system"
    }

@router.get("/database/stats")
async def database_statistics(
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get database statistics (Admin only)"""
    
    try:
        # Table row counts
        user_count = await db.execute(select(func.count(User.id)))
        scan_count = await db.execute(select(func.count(Scan.id)))
        vulnerability_count = await db.execute(select(func.count(Vulnerability.id)))
        audit_log_count = await db.execute(select(func.count(AuditLog.id)))
        
        # Database size (PostgreSQL specific)
        db_size_query = text("""
            SELECT pg_size_pretty(pg_database_size(current_database())) as size,
                   pg_database_size(current_database()) as size_bytes
        """)
        db_size_result = await db.execute(db_size_query)
        db_size = db_size_result.fetchone()
        
        return {
            "table_statistics": {
                "users": user_count.scalar(),
                "scans": scan_count.scalar(),
                "vulnerabilities": vulnerability_count.scalar(),
                "audit_logs": audit_log_count.scalar()
            },
            "database_size": {
                "human_readable": db_size.size if db_size else "Unknown",
                "bytes": db_size.size_bytes if db_size else 0
            },
            "connection_pool": get_pool_status()
        }
    
    except Exception as e:
        logger.error("database_stats_error", error=str(e))
        return {
            "error": "Failed to retrieve database statistics",
            "connection_pool": get_pool_status()
        }

@router.get("/security/events")
async def security_events_summary(
    time_range: str = "24h",
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get security events summary"""
    
    # Parse time range
    if time_range == "1h":
        start_time = datetime.utcnow() - timedelta(hours=1)
    elif time_range == "24h":
        start_time = datetime.utcnow() - timedelta(days=1)
    elif time_range == "7d":
        start_time = datetime.utcnow() - timedelta(days=7)
    else:
        start_time = datetime.utcnow() - timedelta(days=1)
    
    # Security event counts
    login_attempts = await db.execute(
        select(func.count(LoginAttempt.id))
        .filter(LoginAttempt.attempted_at >= start_time)
    )
    
    successful_logins = await db.execute(
        select(func.count(AuditLog.id))
        .filter(AuditLog.event_type == 'login_success')
        .filter(AuditLog.timestamp >= start_time)
    )
    
    security_events = await db.execute(
        select(func.count(AuditLog.id))
        .filter(AuditLog.event_type.like('security_%'))
        .filter(AuditLog.timestamp >= start_time)
    )
    
    # Failed login attempts by IP
    failed_by_ip = await db.execute(
        select(LoginAttempt.ip_address, func.count(LoginAttempt.id).label('count'))
        .filter(LoginAttempt.attempted_at >= start_time)
        .group_by(LoginAttempt.ip_address)
        .order_by(func.count(LoginAttempt.id).desc())
        .limit(10)
    )
    
    return {
        "time_range": time_range,
        "summary": {
            "total_login_attempts": login_attempts.scalar(),
            "successful_logins": successful_logins.scalar(),
            "failed_logins": login_attempts.scalar() - successful_logins.scalar(),
            "security_events": security_events.scalar()
        },
        "top_failed_ips": [
            {"ip": row.ip_address, "attempts": row.count}
            for row in failed_by_ip.fetchall()
        ]
    }

@router.post("/test-alert")
async def test_alert_system(
    current_user: User = Depends(require_admin)
):
    """Test alert system (Admin only)"""
    
    alert_id = await alert_manager.send_alert(
        alert_type="test",
        severity="info",
        message="Test alert triggered by admin user",
        details={
            "triggered_by": current_user.username,
            "timestamp": datetime.utcnow().isoformat()
        }
    )
    
    return {
        "message": "Test alert sent successfully",
        "alert_id": alert_id
    }