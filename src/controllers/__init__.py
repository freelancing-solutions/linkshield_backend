#!/usr/bin/env python3
"""
LinkShield Backend Controllers

Controller classes for handling business logic separated from route handlers.
Provides clean separation of concerns and improved testability.
"""

from src.controllers.base_controller import BaseController
from src.controllers.health_controller import HealthController
from src.controllers.report_controller import ReportController
from src.controllers.url_check_controller import URLCheckController
from src.controllers.user_controller import UserController
from src.controllers.admin_controller import AdminController
from src.controllers.ai_analysis_controller import AIAnalysisController
from src.controllers.dashboard_controller import DashboardController

from src.controllers.dashboard_models import (
    DashboardOverviewResponse,
    ProjectResponse,
    ProjectCreateRequest,
    ProjectUpdateRequest,
    MemberResponse,
    MemberInviteRequest,
    MonitoringConfigResponse,
    AlertResponse,
    AlertInstanceResponse,
    AlertCreateRequest,
    AlertUpdateRequest,
    AnalyticsResponse,
    ActivityLogResponse,
)

__all__ = [
    # Controllers
    "BaseController",
    "HealthController",
    "ReportController",
    "URLCheckController",
    "UserController",
    "AdminController",
    "AIAnalysisController",
    "DashboardController",

    # Dashboard Models
    "DashboardOverviewResponse",
    "ProjectResponse",
    "ProjectCreateRequest",
    "ProjectUpdateRequest",
    "MemberResponse",
    "MemberInviteRequest",
    "MonitoringConfigResponse",
    "AlertResponse",
    "AlertInstanceResponse",
    "AlertCreateRequest",
    "AlertUpdateRequest",
    "AnalyticsResponse",
    "ActivityLogResponse",
]
