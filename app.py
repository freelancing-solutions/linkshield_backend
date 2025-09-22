#!/usr/bin/env python3
"""
LinkShield Backend API

FastAPI entry point for the LinkShield URL safety analysis platform.
Provides REST API endpoints for URL analysis, user management, and reporting.
"""

import os
import sys
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from loguru import logger
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

# Config and database
from src.config.settings import get_settings
from src.config.database import init_db, close_db
from src.security.middleware import SecurityMiddleware
from src.middleware.admin_audit import AdminAuditMiddleware

# Routers
from src.routes.health import router as health_router
from src.routes.url_check import router as url_check_router
from src.routes.user import router as user_router
from src.routes.report import router as report_router
from src.routes.ai_analysis import router as ai_analysis_router
from src.routes.admin import router as admin_router
from src.routes.tasks import router as tasks_router

# Initialize settings
settings = get_settings()

# Configure logging
logger.remove()
log_format = "{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{function}:{line} | {message}"
logger.add(sys.stderr, format=log_format, level=settings.LOG_LEVEL, colorize=True)
logger.add(
    "logs/linkshield.log",
    format=log_format,
    level=settings.LOG_LEVEL,
    rotation="10 MB",
    retention="30 days",
    compression="gz",
)
os.makedirs("logs", exist_ok=True)

# Rate limiter
limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application startup and shutdown."""
    logger.info("Starting LinkShield Backend API...")
    await init_db()
    logger.info("Database initialized successfully")
    yield
    logger.info("Shutting down LinkShield Backend API...")
    await close_db()
    logger.info("Database connections closed")


# Create FastAPI application
app = FastAPI(
    title="LinkShield API",
    description="URL safety analysis and reporting platform",
    version="1.0.0",
    docs_url="/docs" if settings.ENVIRONMENT == "development" else None,
    redoc_url="/redoc" if settings.ENVIRONMENT == "development" else None,
    lifespan=lifespan,
)

# Middleware
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(AdminAuditMiddleware)
app.add_middleware(SecurityMiddleware)

if settings.ENVIRONMENT == "development":
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
else:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["Authorization", "Content-Type"],
    )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.ALLOWED_HOSTS)


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    content = {"success": False, "error": "Internal server error"}
    if settings.ENVIRONMENT == "development":
        content["detail"] = str(exc)
    return JSONResponse(status_code=500, content=content)


# Include routers
app.include_router(health_router)             # will be versioned in router
app.include_router(url_check_router)
app.include_router(user_router)
app.include_router(report_router)
app.include_router(ai_analysis_router)
app.include_router(admin_router)
app.include_router(tasks_router)


# Root endpoint
@app.get("/")
async def root() -> dict:
    return {
        "name": "LinkShield API",
        "version": "1.0.0",
        "description": "URL safety analysis and reporting platform",
        "environment": settings.ENVIRONMENT,
        "docs": "/docs" if settings.ENVIRONMENT == "development" else None,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.ENVIRONMENT == "development",
        log_level=settings.LOG_LEVEL.lower(),
    )
