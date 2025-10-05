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
# from slowapi import Limiter, _rate_limit_exceeded_handler
# from slowapi.errors import RateLimitExceeded
# from slowapi.util import get_remote_address

# Used to force controllers and models to initialize
from src.controllers import *
from src.services.advanced_rate_limiter import get_rate_limiter
# Config and database
from src.config.settings import get_settings
from src.config.database import init_db, close_db
from src.security.middleware import SecurityMiddleware
from src.middleware.admin_audit import AdminAuditMiddleware
from src.middleware.csrf_middleware import CSRFMiddleware

# Routers
from src.routes.health import router as health_router
from src.routes.url_check import router as url_check_router
from src.routes.user import router as user_router
from src.routes.report import router as report_router
from src.routes.ai_analysis import router as ai_analysis_router
from src.routes.admin import router as admin_router
from src.routes.dashboard import router as dashboard_router
from src.routes.social_protection import router as social_protection_router
from src.routes.algorithm_health import router as algorithm_health_router
from src.routes.bot_webhooks import router as bot_webhooks_router
from src.routes.bot_auth import router as bot_auth_router
from src.routes.subscription_routes import router as subscription_router
from src.routes.extension import router as extension_router
from src.api.routes.auth import router as auth_router
from src.api.routes.csrf import router as csrf_router
from src.api.routes.security import router as security_router
# from src.routes.tasks import router as tasks_router

# New Social Protection Routes (specialized controllers)
from src.routes.social_protection_user import router as social_protection_user_router
from src.routes.social_protection_bot import router as social_protection_bot_router
from src.routes.social_protection_extension import router as social_protection_extension_router
from src.routes.social_protection_crisis import router as social_protection_crisis_router
from src.routes.monitoring import router as monitoring_router

# Bot Service
from src.bots.startup import initialize_bot_service, shutdown_bot_service

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



@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application startup and shutdown."""
    logger.info("Starting LinkShield Backend API...")
    await init_db()
    logger.info("Database initialized successfully")
    
    # Initialize bot service
    try:
        bot_results = await initialize_bot_service()
        if bot_results["success"]:
            logger.info("Bot service initialized successfully")
            if bot_results["registered_platforms"]:
                logger.info(f"Registered platforms: {bot_results['registered_platforms']}")
        else:
            logger.warning("Bot service initialization had issues")
            for error in bot_results["errors"]:
                logger.error(f"Bot service error: {error}")
    except Exception as e:
        logger.error(f"Failed to initialize bot service: {e}")
        # Don't fail startup if bot service fails
    
    yield
    
    logger.info("Shutting down LinkShield Backend API...")
    
    # Shutdown bot service
    try:
        bot_results = await shutdown_bot_service()
        if bot_results["success"]:
            logger.info("Bot service shutdown completed")
        else:
            logger.warning("Bot service shutdown had issues")
            for error in bot_results["errors"]:
                logger.error(f"Bot service shutdown error: {error}")
    except Exception as e:
        logger.error(f"Error during bot service shutdown: {e}")
    
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

app.add_middleware(AdminAuditMiddleware)
app.add_middleware(SecurityMiddleware)

# Add CSRF protection middleware
app.add_middleware(
    CSRFMiddleware,
    exempt_paths=[
        "/api/webhooks/",  # Webhook endpoints don't need CSRF protection
        "/api/bot/",       # Bot API endpoints use different auth
        "/api/health",     # Health check endpoint
        "/docs",           # API documentation
        "/redoc",          # API documentation
        "/openapi.json"    # OpenAPI schema
    ],
    require_auth=True
)

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
app.include_router(dashboard_router)
app.include_router(social_protection_router)  # Legacy - deprecated
app.include_router(algorithm_health_router)
app.include_router(bot_webhooks_router)
app.include_router(bot_auth_router)
app.include_router(subscription_router)
app.include_router(extension_router)
app.include_router(auth_router)               # JWT authentication endpoints
app.include_router(csrf_router)               # CSRF protection endpoints
app.include_router(security_router)           # Security endpoints (CSP reporting)
# app.include_router(tasks_router)

# New Social Protection Routes (specialized controllers)
app.include_router(social_protection_user_router)
app.include_router(social_protection_bot_router)
app.include_router(social_protection_extension_router)
app.include_router(social_protection_crisis_router)

# Monitoring Routes
app.include_router(monitoring_router)


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
