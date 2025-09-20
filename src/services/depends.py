from fastapi import APIRouter, Depends, HTTPException, Query, Path, BackgroundTasks
from src.authentication import auth_service
from src.authentication.auth_service import AuthService
from src.config.database import AsyncSession, get_db_session
from src.services.email_service import EmailService
from src.services.security_service import SecurityService


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

