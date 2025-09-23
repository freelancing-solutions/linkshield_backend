
from typing import Optional
from fastapi import Depends, HTTPException
from src.authentication.auth_service import AuthService
from src.config.database import AsyncSession, get_db_session
from src.services.admin_service import AdminService
from src.services.ai_service import AIService
from src.services.ai_analysis_service import AIAnalysisService
from src.services.email_service import EmailService
from src.services.security_service import SecurityService
from src.services.url_analysis_service import URLAnalysisService
from src.models import User

async def get_email_service():
    """
    Get EmailService instance without database session dependency.
    """
    return EmailService()

async def get_security_service() -> SecurityService:
    """
    Get SecurityService instance without database session dependency.
    """
    return SecurityService()

async def get_auth_service(
    security_service: SecurityService = Depends(get_security_service)
    ) -> AuthService:
    """
    Get AuthService instance without database session dependency.
    """
    return AuthService(security_service=security_service)

async def get_admin_service() -> AdminService:
    """
    Get AdminService instance without database session dependency.
    Pure business logic service for data processing and validation.
    """
    return AdminService()

async def get_rate_limits(user: Optional[User], db: AsyncSession = Depends(get_db_session), security_service: SecurityService = Depends(get_security_service)) -> None:
    """
    Check rate limits for user.
    """   
    identifier = str(user.id) if user else "anonymous"
    
    # Check API request rate limit
    is_allowed, limit_info = security_service.check_rate_limit(identifier, "api_requests", "127.0.0.1")
    if not is_allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Try again in {limit_info['retry_after']:.0f} seconds",
            headers={"Retry-After": str(int(limit_info['retry_after']))}
        )

async def get_ai_service() -> AIService:
    """
    Get AIService instance (pure business logic, no database dependency).
    """
    return AIService()

async def get_ai_analysis_service() -> AIAnalysisService:
    """
    Get AI analysis service instance (pure business logic, no database dependency).
    """
    return AIAnalysisService()

async def get_url_analysis_service(ai_service: AIService = Depends(get_ai_service)) -> URLAnalysisService:
    """
    Get URL analysis service instance (pure business logic, no database dependency).
    """
    return URLAnalysisService(ai_service=ai_service)
