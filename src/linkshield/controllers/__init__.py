#!/usr/bin/env python3
"""
LinkShield Backend Controllers

Controller classes for handling business logic separated from route handlers.
Provides clean separation of concerns and improved testability.
"""

from linkshield.controllers.base_controller import BaseController
from linkshield.controllers.health_controller import HealthController
from linkshield.controllers.report_controller import ReportController
from linkshield.controllers.url_check_controller import URLCheckController
from linkshield.controllers.user_controller import UserController
from linkshield.controllers.admin_controller import AdminController
from linkshield.controllers.ai_analysis_controller import AIAnalysisController
from linkshield.controllers.dashboard_controller import DashboardController

from linkshield.controllers.dashboard_models import (
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
