#!/usr/bin/env python3
"""
Social Protection Controllers Dependencies

Dependency injection for social protection controllers.
"""

from fastapi import Depends

from src.services.depends import (
    get_security_service, get_auth_service, get_email_service,
    get_extension_data_processor, get_social_scan_service
)
from src.services.security_service import SecurityService
from src.services.email_service import EmailService
from src.authentication.auth_service import AuthService
from src.social_protection.services import ExtensionDataProcessor, SocialScanService
from src.social_protection.controllers.user_controller import UserController
from src.social_protection.controllers.bot_controller import BotController
from src.social_protection.controllers.extension_controller import ExtensionController


async def get_user_controller(
    security_service: SecurityService = Depends(get_security_service),
    auth_service: AuthService = Depends(get_auth_service),
    email_service: EmailService = Depends(get_email_service),
    extension_data_processor: ExtensionDataProcessor = Depends(get_extension_data_processor),
    social_scan_service: SocialScanService = Depends(get_social_scan_service)
) -> UserController:
    """Get social protection user controller instance."""
    return UserController(
        security_service=security_service,
        auth_service=auth_service,
        email_service=email_service,
        extension_data_processor=extension_data_processor,
        social_scan_service=social_scan_service
    )


async def get_bot_controller(
    security_service: SecurityService = Depends(get_security_service),
    auth_service: AuthService = Depends(get_auth_service),
    email_service: EmailService = Depends(get_email_service),
    extension_data_processor: ExtensionDataProcessor = Depends(get_extension_data_processor),
    social_scan_service: SocialScanService = Depends(get_social_scan_service)
) -> BotController:
    """Get social protection bot controller instance."""
    return BotController(
        security_service=security_service,
        auth_service=auth_service,
        email_service=email_service,
        extension_data_processor=extension_data_processor,
        social_scan_service=social_scan_service
    )


async def get_extension_controller(
    security_service: SecurityService = Depends(get_security_service),
    auth_service: AuthService = Depends(get_auth_service),
    email_service: EmailService = Depends(get_email_service),
    extension_data_processor: ExtensionDataProcessor = Depends(get_extension_data_processor),
    social_scan_service: SocialScanService = Depends(get_social_scan_service)
) -> ExtensionController:
    """Get social protection extension controller instance."""
    return ExtensionController(
        security_service=security_service,
        auth_service=auth_service,
        email_service=email_service,
        extension_data_processor=extension_data_processor,
        social_scan_service=social_scan_service
    )