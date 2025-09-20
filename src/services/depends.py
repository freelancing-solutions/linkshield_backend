from fastapi import APIRouter, Depends, HTTPException, Query, Path, BackgroundTasks
from src.authentication import auth_service
from src.authentication.auth_service import AuthService
from src.config.database import AsyncSession, get_db_session
from src.services.ai_service import AIService
from src.services.email_service import EmailService
from src.services.security_service import SecurityService
from src.services.url_analysis_service import URLAnalysisService


async def get_email_service(db_session: AsyncSession = Depends(get_db_session)):
    """

    """
    return EmailService(db_session=db_session)

async def get_security_service(db_session: AsyncSession = Depends(get_db_session)) -> SecurityService:
    """
    """
    security_service = SecurityService(db_session=db_session)
    return security_service

async def get_auth_service(
    db_session: AsyncSession = Depends(get_db_session),
    email_service: EmailService = Depends(get_email_service),
    security_service: SecurityService = Depends(get_security_service)
    ) -> AuthService:
    """

    """
    return AuthService(get_db_session=db_session, email_service=email_service, security_service=security_service)


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
    """
    returm AIService()

async def get_url_analysis_service(db_session: AsyncSession = Depends(get_db_session), ai_service:AIService = Depends(get_ai_service) -> URLAnalysisService):
    return URLAnalysisService(db_session=db_session, ai_service=ai_service)
