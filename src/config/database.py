#!/usr/bin/env python3
"""
LinkShield Backend Database Configuration

Database connection management using SQLAlchemy with async support.
Handles PostgreSQL connections, session management, and database initialization.
"""

import asyncio
from typing import AsyncGenerator, Optional

from loguru import logger
from sqlalchemy import MetaData, create_engine, event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool, QueuePool

from .settings import get_settings

# Get settings instance
settings = get_settings()

# Create declarative base for models
Base = declarative_base()

# Naming convention for constraints (helps with migrations)
convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}
Base.metadata = MetaData(naming_convention=convention)

# Global database engine and session maker
engine: Optional[AsyncEngine] = None
SessionLocal: Optional[async_sessionmaker[AsyncSession]] = None


def get_database_url() -> str:
    """
    Get the database URL, converting to async format if needed.
    """
    db_url = settings.DATABASE_URL
    
    # Convert postgresql:// to postgresql+asyncpg:// for async support
    if db_url.startswith("postgresql://"):
        db_url = db_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    
    return db_url


def create_database_engine() -> AsyncEngine:
    """
    Create and configure the database engine.
    """
    db_url = get_database_url()
    
    # Engine configuration based on environment
    if settings.ENVIRONMENT == "development":
        # Development: Enable echo for SQL logging
        return create_async_engine(
            db_url,
            echo=settings.DEBUG,
            pool_size=5,
            max_overflow=10,
            pool_pre_ping=True,
            pool_recycle=3600,  # 1 hour
        )
    elif settings.ENVIRONMENT == "testing":
        # Testing: Use NullPool to avoid connection issues
        return create_async_engine(
            db_url,
            echo=False,
            poolclass=NullPool,
        )
    else:
        # Production: Optimized settings
        return create_async_engine(
            db_url,
            echo=False,
            pool_size=settings.DATABASE_POOL_SIZE,
            max_overflow=settings.DATABASE_MAX_OVERFLOW,
            pool_pre_ping=True,
            pool_recycle=3600,  # 1 hour
            connect_args={
                "server_settings": {
                    "application_name": "linkshield_backend",
                }
            },
        )


async def init_db() -> None:
    """
    Initialize the database connection and create tables if needed.
    """
    global engine, SessionLocal
    
    try:
        # Create engine
        engine = create_database_engine()
        
        # Create session maker
        SessionLocal = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
        
        # Test connection
        async with engine.begin() as conn:
            # Import all models to ensure they're registered
            from src.models import user, url_check, report, subscription  # noqa: F401
            
            # Create all tables
            await conn.run_sync(Base.metadata.create_all)
            
        logger.info("Database initialized successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise


async def close_db() -> None:
    """
    Close database connections and cleanup.
    """
    global engine
    
    if engine:
        await engine.dispose()
        logger.info("Database connections closed")


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency to get database session.
    Yields an async database session and ensures proper cleanup.
    """
    if not SessionLocal:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    
    async with SessionLocal() as session:
        try:
            yield session
        except Exception as e:
            await session.rollback()
            logger.error(f"Database session error: {e}")
            raise
        finally:
            await session.close()


async def get_db() -> AsyncSession:
    """
    Get a database session (for use outside of FastAPI dependency injection).
    Remember to close the session when done.
    """
    if not SessionLocal:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    
    return SessionLocal()


class DatabaseManager:
    """
    Database manager class for handling database operations.
    Provides context manager support for database sessions.
    """
    
    def __init__(self):
        self.session: Optional[AsyncSession] = None
    
    async def __aenter__(self) -> AsyncSession:
        """Enter async context manager."""
        self.session = await get_db()
        return self.session
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit async context manager."""
        if self.session:
            if exc_type:
                await self.session.rollback()
            await self.session.close()


# Health check function
async def check_database_health() -> bool:
    """
    Check if database is healthy and accessible.
    Returns True if database is accessible, False otherwise.
    """
    try:
        if not engine:
            return False
        
        async with engine.begin() as conn:
            result = await conn.execute("SELECT 1")
            return result.scalar() == 1
    
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return False


