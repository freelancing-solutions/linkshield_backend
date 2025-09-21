from fastapi import APIRouter, Depends, HTTPException, Query, Path, BackgroundTasks
from src.authentication import auth_service
from src.authentication.auth_service import AuthService
from src.config.database import AsyncSession, get_db_session
from src.controllers import URLCheckController, ReportController, HealthController, UserController, AdminController

from src.services.email_service import EmailService
from src.services.security_service import SecurityService
from src.services.url_analysis_service import URLAnalysisService

from src.services.depends import get_security_service, get_auth_service, get_url_analysis_service


async def get_health_controller() -> HealthController:
    return HealthController()


async def get_report_controller(
    db_session: AsyncSession = Depends(get_db_session),
    security_service: SecurityService = Depends(get_security_service),
    auth_service: AuthService = Depends(get_auth_service)) -> ReportController:
    """
    TODO - can move get_controller to controllers/depends.py
    """
    return ReportController(db_session=db_session,security_service=security_service, auth_service=auth_service)


async def get_url_check_controller(db_session: AsyncSession = Depends(get_db_session), security_service: SecurityService = Depends(get_security_service), 
auth_service: AuthService = Depends(get_auth_service), url_analysis_service:URLAnalysisService = Depends(get_url_analysis_service)) -> URLCheckController:

    """

    """
    return URLCheckController(db_session=db_session, security_service=security_service, auth_service=auth_service, url_analysis_service=url_analysis_service, ai_service=ai_service)