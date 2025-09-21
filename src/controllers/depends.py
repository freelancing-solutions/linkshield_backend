from fastapi import APIRouter, Depends, HTTPException, Query, Path, BackgroundTasks
from src.authentication import auth_service
from src.authentication.auth_service import AuthService
from src.config.database import AsyncSession, get_db_session
from src.controllers import URLCheckController, ReportController, HealthController, UserController, AdminController, AIAnalysisController

from src.services.admin_service import AdminService
from src.services.email_service import EmailService
from src.services.security_service import SecurityService
from src.services.url_analysis_service import URLAnalysisService
from src.services.ai_analysis_service import AIAnalysisService
from src.services.ai_service import AIService

from src.services.depends import get_security_service, get_auth_service, get_url_analysis_service, get_ai_analysis_service, get_ai_service, get_email_service, get_admin_service


async def get_health_controller() -> HealthController:
    return HealthController()


async def get_report_controller(
    security_service: SecurityService = Depends(get_security_service),
    auth_service: AuthService = Depends(get_auth_service),
    email_service: EmailService = Depends(get_email_service)) -> ReportController:
    """
    Get report controller instance with required dependencies.
    """
    return ReportController(
        security_service=security_service, 
        auth_service=auth_service,
        email_service=email_service)


async def get_url_check_controller(
    security_service: SecurityService = Depends(get_security_service), 
    auth_service: AuthService = Depends(get_auth_service),
    email_service: EmailService = Depends(get_email_service),
    url_analysis_service: URLAnalysisService = Depends(get_url_analysis_service)) -> URLCheckController:
    """
    Get URL check controller instance with required dependencies.
    """
    return URLCheckController(
        security_service=security_service, 
        auth_service=auth_service,
        email_service=email_service,
        url_analysis_service=url_analysis_service)


async def get_admin_controller(
    admin_service: AdminService = Depends(get_admin_service),
    security_service: SecurityService = Depends(get_security_service),
    auth_service: AuthService = Depends(get_auth_service),
    email_service: EmailService = Depends(get_email_service)
) -> AdminController:
    """
    Get admin controller instance with all required dependencies.
    """
    return AdminController(
        admin_service=admin_service,
        security_service=security_service,
        auth_service=auth_service,
        email_service=email_service
    )


async def get_ai_analysis_controller(
    ai_analysis_service: AIAnalysisService = Depends(get_ai_analysis_service),
    ai_service: AIService = Depends(get_ai_service),
    security_service: SecurityService = Depends(get_security_service),
    auth_service: AuthService = Depends(get_auth_service),
    email_service: EmailService = Depends(get_email_service)
) -> AIAnalysisController:
    """
    Get AI analysis controller instance with all required dependencies.
    """
    return AIAnalysisController(
        ai_analysis_service=ai_analysis_service,
        ai_service=ai_service,
        security_service=security_service,
        auth_service=auth_service,
        email_service=email_service
    )