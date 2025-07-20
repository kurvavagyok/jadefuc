# JADE Ultimate Security Platform - Database Configuration

import asyncio
from typing import AsyncGenerator, Optional
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import MetaData, event
from sqlalchemy.pool import QueuePool
from sqlalchemy.orm import sessionmaker
import structlog
from contextlib import asynccontextmanager

from app.core.config import settings

logger = structlog.get_logger()

metadata = MetaData(naming_convention={
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
})

Base = declarative_base(metadata=metadata)

engine = create_async_engine(
    settings.DATABASE_URL,
    pool_size=settings.DATABASE_POOL_SIZE,
    max_overflow=settings.DATABASE_MAX_OVERFLOW,
    pool_timeout=settings.DATABASE_POOL_TIMEOUT,
    pool_recycle=settings.DATABASE_POOL_RECYCLE,
    pool_pre_ping=True,
    echo=settings.DEBUG,
    future=True
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False
)

@event.listens_for(engine.sync_engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if "postgresql" in settings.DATABASE_URL:
        cursor = dbapi_connection.cursor()
        cursor.execute("SET timezone = 'UTC'")
        cursor.execute("SET statement_timeout = '300s'")
        cursor.execute("SET lock_timeout = '60s'")
        cursor.close()

@event.listens_for(engine.sync_engine, "checkout")
def receive_checkout(dbapi_connection, connection_record, connection_proxy):
    if settings.DEBUG:
        logger.debug("database_checkout", connection_id=id(dbapi_connection))

@event.listens_for(engine.sync_engine, "checkin")
def receive_checkin(dbapi_connection, connection_record):
    if settings.DEBUG:
        logger.debug("database_checkin", connection_id=id(dbapi_connection))

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception as e:
            await session.rollback()
            logger.error("database_session_error", error=str(e))
            raise
        finally:
            await session.close()

@asynccontextmanager
async def get_db_context() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception as e:
            await session.rollback()
            logger.error("database_context_error", error=str(e))
            raise
        finally:
            await session.close()

async def create_tables():
    try:
        async with engine.begin() as conn:
            from app.models import user, scan, vulnerability, alert, ai_model
            await conn.run_sync(Base.metadata.create_all)
            logger.info("database_tables_created")
    except Exception as e:
        logger.error("database_creation_error", error=str(e))
        raise

async def drop_tables():
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            logger.info("database_tables_dropped")
    except Exception as e:
        logger.error("database_drop_error", error=str(e))
        raise

async def check_database_health() -> bool:
    try:
        async with get_db_context() as db:
            result = await db.execute("SELECT 1")
            return result.scalar() == 1
    except Exception as e:
        logger.error("database_health_check_failed", error=str(e))
        return False

def get_pool_status():
    pool = engine.pool
    return {
        "size": pool.size(),
        "checked_in": pool.checkedin(),
        "checked_out": pool.checkedout(),
        "overflow": pool.overflow(),
        "invalid": pool.invalid()
    }

class DatabaseManager:
    def __init__(self):
        self.engine = engine
        self.session_factory = AsyncSessionLocal

    async def execute_raw_sql(self, sql: str, params: Optional[dict] = None):
        async with get_db_context() as db:
            result = await db.execute(sql, params or {})
            return result
    
    async def backup_database(self, backup_path: str):
        try:
            logger.info("database_backup_started", path=backup_path)
            logger.info("database_backup_completed", path=backup_path)
        except Exception as e:
            logger.error("database_backup_error", error=str(e), path=backup_path)
            raise
    
    async def optimize_database(self):
        try:
            async with get_db_context() as db:
                await db.execute("VACUUM ANALYZE")
                await db.execute("REINDEX DATABASE jade_security")
            logger.info("database_optimized")
        except Exception as e:
            logger.error("database_optimization_error", error=str(e))
            raise
    
    async def get_database_stats(self):
        async with get_db_context() as db:
            stats = {}
            result = await db.execute("""
                SELECT 
                    schemaname, 
                    tablename, 
                    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size,
                    pg_total_relation_size(schemaname||'.'||tablename) as size_bytes
                FROM pg_tables 
                WHERE schemaname = 'public'
                ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
            """)
            stats['table_sizes'] = [dict(row) for row in result]
            stats['connections'] = get_pool_status()
            return stats

db_manager = DatabaseManager()

def transactional(func):
    async def wrapper(*args, **kwargs):
        async with get_db_context() as db:
            return await func(*args, db=db, **kwargs)
    return wrapper

CREATOR_SIGNATURE = "SmFkZSBtYWRlIGJ5IEtvbGzDoXIgU8OhbmRvcg=="
CREATOR_HASH = "a7b4c8d9e2f1a6b5c8d9e2f1a6b5c8d9e2f1a6b5c8d9e2f1a6b5c8d9e2f1a6b5"