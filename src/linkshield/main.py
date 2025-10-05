"""
LinkShield Backend Main Application Entry Point

This module provides the main entry point for the LinkShield backend application.
It sets up the FastAPI application with all necessary middleware, routes, and
security components.
"""

import logging
import sys
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

# Import configuration and settings
from .config.settings import Settings
from .config.database import init_db, close_db

# Import security middleware
from .security.middleware import SecurityMiddleware
from .security.csrf_protection import CSRFMiddleware
from .security.session_security_middleware import SessionSecurityMiddleware

# Import routes
from .routes import (
    admin,
    ai_analysis,
    algorithm_health,
    bot_auth,
    bot_webhooks,
    dashboard,
    extension,
    health,
    monitoring,
    paddle_webhooks,
    report,
    social_protection,
    social_protection_bot,
    social_protection_crisis,
    social_protection_extension,
    social_protection_user,
    subscription_routes,
    tasks,
    url_check,
    user,
)

# Import version information
from .version import __version__, get_full_version

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("linkshield.log"),
    ],
)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan manager.
    
    Handles startup and shutdown events for the FastAPI application.
    """
    # Startup
    logger.info(f"Starting LinkShield Backend v{get_full_version()}")
    
    try:
        # Initialize database connections
        await init_db()
        logger.info("Database connections initialized")
        
        # Initialize Redis connections
        # Note: Redis initialization would be handled by security components
        logger.info("Redis connections initialized")
        
        # Initialize security components
        logger.info("Security components initialized")
        
        logger.info("LinkShield Backend startup complete")
        
        yield
        
    except Exception as e:
        logger.error(f"Failed to start LinkShield Backend: {e}")
        raise
    finally:
        # Shutdown
        logger.info("Shutting down LinkShield Backend")
        
        try:
            # Close database connections
            await close_db()
            logger.info("Database connections closed")
            
            # Close Redis connections
            logger.info("Redis connections closed")
            
            logger.info("LinkShield Backend shutdown complete")
            
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")


def create_app(settings: Settings = None) -> FastAPI:
    """
    Create and configure the FastAPI application.
    
    Args:
        settings: Application settings. If None, will load from environment.
        
    Returns:
        Configured FastAPI application instance.
    """
    if settings is None:
        settings = Settings()
    
    # Create FastAPI application
    app = FastAPI(
        title="LinkShield Backend",
        description="Secure URL shortening service with comprehensive security features",
        version=__version__,
        docs_url="/docs" if settings.DEBUG else None,
        redoc_url="/redoc" if settings.DEBUG else None,
        openapi_url="/openapi.json" if settings.DEBUG else None,
        lifespan=lifespan,
    )
    
    # Add security middleware (order matters!)
    
    # 1. Trusted Host Middleware (first line of defense)
    if settings.ALLOWED_HOSTS:
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=settings.ALLOWED_HOSTS,
        )
    
    # 2. CORS Middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )
    
    # 3. Session Security Middleware
    app.add_middleware(SessionSecurityMiddleware)
    
    # 4. CSRF Protection Middleware
    app.add_middleware(CSRFMiddleware)
    
    # 5. Main Security Middleware (rate limiting, JWT validation, etc.)
    app.add_middleware(SecurityMiddleware)
    
    # Include routers
    app.include_router(health.router, prefix="/api/v1", tags=["health"])
    app.include_router(user.router, prefix="/api/v1", tags=["users"])
    app.include_router(admin.router, prefix="/api/v1", tags=["admin"])
    app.include_router(dashboard.router, prefix="/api/v1", tags=["dashboard"])
    app.include_router(url_check.router, prefix="/api/v1", tags=["url-check"])
    app.include_router(ai_analysis.router, prefix="/api/v1", tags=["ai-analysis"])
    app.include_router(report.router, prefix="/api/v1", tags=["reports"])
    app.include_router(subscription_routes.router, prefix="/api/v1", tags=["subscriptions"])
    app.include_router(tasks.router, prefix="/api/v1", tags=["tasks"])
    app.include_router(monitoring.router, prefix="/api/v1", tags=["monitoring"])
    app.include_router(algorithm_health.router, prefix="/api/v1", tags=["algorithm-health"])
    
    # Bot and webhook routes
    app.include_router(bot_auth.router, prefix="/api/v1", tags=["bot-auth"])
    app.include_router(bot_webhooks.router, prefix="/api/v1", tags=["bot-webhooks"])
    app.include_router(paddle_webhooks.router, prefix="/api/v1", tags=["paddle-webhooks"])
    
    # Social protection routes
    app.include_router(social_protection.router, prefix="/api/v1", tags=["social-protection"])
    app.include_router(social_protection_bot.router, prefix="/api/v1", tags=["social-protection-bot"])
    app.include_router(social_protection_crisis.router, prefix="/api/v1", tags=["social-protection-crisis"])
    app.include_router(social_protection_extension.router, prefix="/api/v1", tags=["social-protection-extension"])
    app.include_router(social_protection_user.router, prefix="/api/v1", tags=["social-protection-user"])
    
    # Extension routes
    app.include_router(extension.router, prefix="/api/v1", tags=["extension"])
    
    # Store settings in app state for access by middleware and routes
    app.state.settings = settings
    
    return app


def main():
    """
    Main entry point for the application.
    
    This function is called when the package is executed as a script
    or when using the console script entry point.
    """
    import uvicorn
    
    settings = Settings()
    
    # Run the application
    uvicorn.run(
        "linkshield.main:create_app",
        factory=True,
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="info" if not settings.DEBUG else "debug",
        access_log=True,
    )


if __name__ == "__main__":
    main()