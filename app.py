
#!/usr/bin/env python3
"""
LinkShield Backend API

Main FastAPI application entry point for the LinkShield URL safety analysis platform.
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

# Import configuration and database
from src.config.settings import get_settings
from src.config.database import init_db, close_db
from src.security.middleware import SecurityMiddleware

# Import route modules
from src.routes.health import router as health_router
from src.routes.auth import router as auth_router
from src.routes.check import router as check_router
from src.routes.reports import router as reports_router
from src.routes.admin import router as admin_router

# Initialize settings
settings = get_settings()

# Configure logging
logger.remove()  # Remove default handler
logger.add(
    sys.stderr,
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{function}:{line} | {message}",
    level=settings.LOG_LEVEL,
    colorize=True,
)
logger.add(
    "logs/linkshield.log",
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{function}:{line} | {message}",
    level=settings.LOG_LEVEL,
    rotation="10 MB",
    retention="30 days",
    compression="gz",
)

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan manager.
    Handles startup and shutdown events for database connections and other resources.
    """
    logger.info("Starting LinkShield Backend API...")
    
    # Initialize database
    await init_db()
    logger.info("Database initialized successfully")
    
    # Create logs directory if it doesn't exist
    os.makedirs("logs", exist_ok=True)
    
    yield
    
    # Cleanup on shutdown
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

# Add rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Add security middleware
app.add_middleware(SecurityMiddleware)

# Add CORS middleware
if settings.ENVIRONMENT == "development":
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )
else:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )

# Add trusted host middleware for production
if settings.ENVIRONMENT == "production":
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.ALLOWED_HOSTS,
    )


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Global exception handler for unhandled exceptions.
    Logs the error and returns a generic error response.
    """
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    
    if settings.ENVIRONMENT == "development":
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "error": "Internal server error",
                "detail": str(exc),
            },
        )
    else:
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "error": "Internal server error",
            },
        )


# Include routers
from src.routes.health import router as health_router
from src.routes.url_check import router as url_check_router
from src.routes.user import router as user_router
from src.routes.report import router as report_router

app.include_router(health_router, prefix="/api", tags=["Health"])
app.include_router(url_check_router, prefix="/api", tags=["URL Check"])
app.include_router(user_router, prefix="/api", tags=["User"])
app.include_router(report_router, prefix="/api", tags=["Report"])


# Root endpoint
@app.get("/")
async def root() -> dict:
    """
    Root endpoint providing basic API information.
    """
    return {
        "name": "LinkShield API",
        "version": "1.0.0",
        "description": "URL safety analysis and reporting platform",
        "environment": settings.ENVIRONMENT,
        "docs": "/docs" if settings.ENVIRONMENT == "development" else None,
    }


if __name__ == "__main__":
    import uvicorn
    
    # Run the application
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.ENVIRONMENT == "development",
        log_level=settings.LOG_LEVEL.lower(),
    )


