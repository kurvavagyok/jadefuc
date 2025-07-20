# JADE Ultimate Security Platform - Monitoring & Observability
# Enterprise-grade monitoring with Prometheus metrics, structured logging, and alerting

import time
import asyncio
import psutil
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from contextlib import asynccontextmanager
from functools import wraps
import structlog
from prometheus_client import (
    Counter, Histogram, Gauge, Info, Enum,
    CollectorRegistry, multiprocess, generate_latest,
    CONTENT_TYPE_LATEST
)

from app.core.config import settings

logger = structlog.get_logger()

# Prometheus metrics
REQUEST_COUNT = Counter(
    'jade_http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status_code', 'user_id']
)

REQUEST_DURATION = Histogram(
    'jade_http_request_duration_seconds',
    'HTTP request duration in seconds',
    ['method', 'endpoint'],
    buckets=(.005, .01, .025, .05, .075, .1, .25, .5, .75, 1.0, 2.5, 5.0, 7.5, 10.0, float('inf'))
)

ACTIVE_CONNECTIONS = Gauge(
    'jade_active_connections',
    'Number of active connections'
)

DATABASE_CONNECTIONS = Gauge(
    'jade_database_connections_active',
    'Active database connections'
)

AI_MODEL_REQUESTS = Counter(
    'jade_ai_model_requests_total',
    'Total AI model requests',
    ['model', 'provider', 'status']
)

AI_MODEL_LATENCY = Histogram(
    'jade_ai_model_latency_seconds',
    'AI model response latency',
    ['model', 'provider'],
    buckets=(.1, .25, .5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, float('inf'))
)

SECURITY_EVENTS = Counter(
    'jade_security_events_total',
    'Security events',
    ['event_type', 'severity', 'user_id']
)

SCAN_COUNT = Counter(
    'jade_scans_total',
    'Total security scans',
    ['scan_type', 'status', 'user_id']
)

SCAN_DURATION = Histogram(
    'jade_scan_duration_seconds',
    'Security scan duration',
    ['scan_type'],
    buckets=(1.0, 5.0, 10.0, 30.0, 60.0, 300.0, 600.0, 1800.0, 3600.0, float('inf'))
)

VULNERABILITY_COUNT = Counter(
    'jade_vulnerabilities_found_total',
    'Total vulnerabilities found',
    ['severity', 'scan_type']
)

# System metrics
SYSTEM_CPU_USAGE = Gauge('jade_system_cpu_usage_percent', 'System CPU usage percentage')
SYSTEM_MEMORY_USAGE = Gauge('jade_system_memory_usage_bytes', 'System memory usage in bytes')
SYSTEM_MEMORY_TOTAL = Gauge('jade_system_memory_total_bytes', 'System total memory in bytes')
SYSTEM_DISK_USAGE = Gauge('jade_system_disk_usage_bytes', 'System disk usage in bytes')
SYSTEM_DISK_TOTAL = Gauge('jade_system_disk_total_bytes', 'System total disk space in bytes')

# Application info
APPLICATION_INFO = Info(
    'jade_application_info',
    'Application information',
    ['version', 'environment', 'creator']
)

APPLICATION_INFO.info({
    'version': settings.VERSION,
    'environment': 'production' if not settings.DEBUG else 'development',
    'creator': 'Kollár Sándor - JADE Ultimate Security'
})

class MonitoringService:
    """Centralized monitoring and observability service"""
    
    def __init__(self):
        self.start_time = time.time()
        self.system_monitor_task = None
        self.alert_thresholds = {
            'cpu_usage': 80.0,
            'memory_usage': 85.0,
            'disk_usage': 90.0,
            'response_time': 5.0,
            'error_rate': 5.0
        }
    
    async def start_monitoring(self):
        """Start background monitoring tasks"""
        self.system_monitor_task = asyncio.create_task(self._monitor_system_metrics())
        logger.info("monitoring_service_started")
    
    async def stop_monitoring(self):
        """Stop background monitoring tasks"""
        if self.system_monitor_task:
            self.system_monitor_task.cancel()
            try:
                await self.system_monitor_task
            except asyncio.CancelledError:
                pass
        logger.info("monitoring_service_stopped")
    
    async def _monitor_system_metrics(self):
        """Monitor system metrics continuously"""
        while True:
            try:
                # CPU usage
                cpu_percent = psutil.cpu_percent(interval=1)
                SYSTEM_CPU_USAGE.set(cpu_percent)
                
                # Memory usage
                memory = psutil.virtual_memory()
                SYSTEM_MEMORY_USAGE.set(memory.used)
                SYSTEM_MEMORY_TOTAL.set(memory.total)
                
                # Disk usage
                disk = psutil.disk_usage('/')
                SYSTEM_DISK_USAGE.set(disk.used)
                SYSTEM_DISK_TOTAL.set(disk.total)
                
                # Check for alerts
                await self._check_system_alerts(cpu_percent, memory.percent, disk.percent)
                
                # Wait before next check
                await asyncio.sleep(30)  # Update every 30 seconds
                
            except Exception as e:
                logger.error("system_monitoring_error", error=str(e))
                await asyncio.sleep(60)  # Wait longer on error
    
    async def _check_system_alerts(self, cpu_percent: float, memory_percent: float, disk_percent: float):
        """Check system metrics against thresholds and generate alerts"""
        
        alerts = []
        
        if cpu_percent > self.alert_thresholds['cpu_usage']:
            alerts.append({
                'type': 'system_alert',
                'severity': 'warning',
                'metric': 'cpu_usage',
                'value': cpu_percent,
                'threshold': self.alert_thresholds['cpu_usage']
            })
        
        if memory_percent > self.alert_thresholds['memory_usage']:
            alerts.append({
                'type': 'system_alert',
                'severity': 'warning',
                'metric': 'memory_usage',
                'value': memory_percent,
                'threshold': self.alert_thresholds['memory_usage']
            })
        
        if disk_percent > self.alert_thresholds['disk_usage']:
            alerts.append({
                'type': 'system_alert',
                'severity': 'critical',
                'metric': 'disk_usage',
                'value': disk_percent,
                'threshold': self.alert_thresholds['disk_usage']
            })
        
        for alert in alerts:
            logger.warning("system_alert", **alert)
            SECURITY_EVENTS.labels(
                event_type='system_alert',
                severity=alert['severity'],
                user_id='system'
            ).inc()
    
    def record_request(self, method: str, endpoint: str, status_code: int, 
                      duration: float, user_id: str = "anonymous"):
        """Record HTTP request metrics"""
        REQUEST_COUNT.labels(
            method=method,
            endpoint=endpoint,
            status_code=status_code,
            user_id=user_id
        ).inc()
        
        REQUEST_DURATION.labels(
            method=method,
            endpoint=endpoint
        ).observe(duration)
    
    def record_ai_request(self, model: str, provider: str, status: str, latency: float):
        """Record AI model request metrics"""
        AI_MODEL_REQUESTS.labels(
            model=model,
            provider=provider,
            status=status
        ).inc()
        
        if status == "success":
            AI_MODEL_LATENCY.labels(
                model=model,
                provider=provider
            ).observe(latency)
    
    def record_security_event(self, event_type: str, severity: str, user_id: str):
        """Record security event"""
        SECURITY_EVENTS.labels(
            event_type=event_type,
            severity=severity,
            user_id=user_id
        ).inc()
        
        logger.info("security_event_recorded",
                   event_type=event_type,
                   severity=severity,
                   user_id=user_id)
    
    def record_scan_metrics(self, scan_type: str, status: str, duration: float, 
                          user_id: str, vulnerabilities: Dict[str, int] = None):
        """Record security scan metrics"""
        SCAN_COUNT.labels(
            scan_type=scan_type,
            status=status,
            user_id=user_id
        ).inc()
        
        if status == "completed":
            SCAN_DURATION.labels(scan_type=scan_type).observe(duration)
            
            # Record vulnerabilities found
            if vulnerabilities:
                for severity, count in vulnerabilities.items():
                    VULNERABILITY_COUNT.labels(
                        severity=severity,
                        scan_type=scan_type
                    ).inc(count)
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get comprehensive health status"""
        uptime = time.time() - self.start_time
        
        # System metrics
        cpu_percent = psutil.cpu_percent()
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        return {
            "status": "healthy",
            "uptime_seconds": uptime,
            "timestamp": datetime.utcnow().isoformat(),
            "system": {
                "cpu_usage_percent": cpu_percent,
                "memory_usage_percent": memory.percent,
                "memory_used_bytes": memory.used,
                "memory_total_bytes": memory.total,
                "disk_usage_percent": (disk.used / disk.total) * 100,
                "disk_used_bytes": disk.used,
                "disk_total_bytes": disk.total
            },
            "application": {
                "version": settings.VERSION,
                "environment": "production" if not settings.DEBUG else "development",
                "creator": "Kollár Sándor - JADE Ultimate Security"
            }
        }
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get metrics summary for dashboard"""
        return {
            "requests_total": REQUEST_COUNT._value.sum(),
            "active_connections": ACTIVE_CONNECTIONS._value.get(),
            "ai_requests_total": AI_MODEL_REQUESTS._value.sum(),
            "security_events_total": SECURITY_EVENTS._value.sum(),
            "scans_total": SCAN_COUNT._value.sum(),
            "vulnerabilities_total": VULNERABILITY_COUNT._value.sum()
        }

# Global monitoring service
monitoring_service = MonitoringService()

# Decorator for timing functions
def monitor_execution_time(metric_name: str = None):
    """Decorator to monitor function execution time"""
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                duration = time.time() - start_time
                
                logger.info("function_execution", 
                           function=func.__name__,
                           duration=duration,
                           status="success")
                return result
            except Exception as e:
                duration = time.time() - start_time
                logger.error("function_execution",
                            function=func.__name__,
                            duration=duration,
                            status="error",
                            error=str(e))
                raise
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                
                logger.info("function_execution",
                           function=func.__name__,
                           duration=duration,
                           status="success")
                return result
            except Exception as e:
                duration = time.time() - start_time
                logger.error("function_execution",
                            function=func.__name__,
                            duration=duration,
                            status="error",
                            error=str(e))
                raise
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    return decorator

# Context manager for operation tracking
@asynccontextmanager
async def track_operation(operation_name: str, user_id: str = "system", **metadata):
    """Context manager to track operation metrics and logging"""
    start_time = time.time()
    operation_id = f"{operation_name}_{int(start_time)}"
    
    logger.info("operation_started",
               operation_id=operation_id,
               operation=operation_name,
               user_id=user_id,
               **metadata)
    
    try:
        yield operation_id
        duration = time.time() - start_time
        
        logger.info("operation_completed",
                   operation_id=operation_id,
                   operation=operation_name,
                   user_id=user_id,
                   duration=duration,
                   status="success",
                   **metadata)
        
    except Exception as e:
        duration = time.time() - start_time
        
        logger.error("operation_failed",
                    operation_id=operation_id,
                    operation=operation_name,
                    user_id=user_id,
                    duration=duration,
                    status="error",
                    error=str(e),
                    **metadata)
        raise

# Alert manager for critical events
class AlertManager:
    """Manage alerts and notifications"""
    
    def __init__(self):
        self.alert_channels = []
        self.alert_history = []
    
    async def send_alert(self, alert_type: str, severity: str, message: str, 
                        details: Dict[str, Any] = None):
        """Send alert through configured channels"""
        
        alert = {
            "id": f"alert_{int(time.time())}",
            "type": alert_type,
            "severity": severity,
            "message": message,
            "details": details or {},
            "timestamp": datetime.utcnow().isoformat(),
            "resolved": False
        }
        
        self.alert_history.append(alert)
        
        # Log alert
        logger.warning("alert_triggered", **alert)
        
        # Record in metrics
        monitoring_service.record_security_event(
            f"alert_{alert_type}", severity, "system"
        )
        
        # Keep only last 1000 alerts in memory
        if len(self.alert_history) > 1000:
            self.alert_history = self.alert_history[-1000:]
        
        return alert["id"]
    
    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get unresolved alerts"""
        return [alert for alert in self.alert_history if not alert["resolved"]]
    
    def resolve_alert(self, alert_id: str):
        """Mark alert as resolved"""
        for alert in self.alert_history:
            if alert["id"] == alert_id:
                alert["resolved"] = True
                alert["resolved_at"] = datetime.utcnow().isoformat()
                logger.info("alert_resolved", alert_id=alert_id)
                return True
        return False

# Global alert manager
alert_manager = AlertManager()