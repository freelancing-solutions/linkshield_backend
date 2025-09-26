"""
Social Media Bot Service for comprehensive account safety analysis, compliance monitoring, and follower insights.

This service extends LinkShield's existing bot integration capabilities by providing:
- Account Safety & Risk Analysis
- Dynamic Code-of-Conduct Compliance Monitoring  
- Verified Followers Overview

The service integrates with existing social protection infrastructure including BotController,
platform adapters, and analysis services.
"""

import asyncio
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

from sqlalchemy.orm import Session
from src.config.database import get_db
from src.models.bot import BotUser, get_or_create_bot_user
from src.models.social_protection import PlatformType, RiskLevel
from src.services.quick_analysis_service import QuickAnalysisService
from src.config.settings import settings

logger = logging.getLogger(__name__)


@dataclass
class AccountSafetyResult:
    """Result of account safety analysis."""
    account_id: str
    platform: PlatformType
    risk_score: float
    risk_level: RiskLevel
    bot_probability: float
    spam_indicators: List[str]
    scam_indicators: List[str]
    recommendations: List[str]
    analysis_timestamp: datetime
    confidence_score: float


@dataclass
class ComplianceResult:
    """Result of compliance monitoring check."""
    platform: PlatformType
    content_id: str
    compliance_score: float
    violations: List['PolicyViolation']
    recommendations: List[str]
    severity_level: RiskLevel
    analysis_timestamp: datetime


@dataclass
class VerifiedFollowerResult:
    """Result of verified follower analysis."""
    account_id: str
    platform: PlatformType
    total_verified_followers: int
    verification_breakdown: Dict[str, int]
    high_value_followers: List['HighValueFollower']
    networking_opportunities: List['NetworkingRecommendation']
    analysis_timestamp: datetime


@dataclass
class PolicyViolation:
    """Policy violation details."""
    violation_type: str
    severity: RiskLevel
    description: str
    recommendation: str
    policy_reference: str


@dataclass
class HighValueFollower:
    """High-value follower information."""
    follower_id: str
    username: str
    verification_type: str
    influence_score: float
    industry_category: str
    engagement_potential: float
    networking_value: str


@dataclass
class NetworkingRecommendation:
    """Networking recommendation based on follower analysis."""
    follower_id: str
    recommendation_type: str
    reason: str
    priority: str
    suggested_action: str


@dataclass
class RiskAssessmentResult:
    """Real-time risk assessment result."""
    content_or_account: str
    platform: PlatformType
    assessment_type: str
    risk_level: RiskLevel
    risk_score: float
    risk_factors: List[str]
    recommendations: List[str]
    analysis_timestamp: datetime
    response_time_ms: int


class SocialMediaBotService:
    """
    Main orchestration service for social media bot functionality.
    
    Coordinates account safety analysis, compliance monitoring, and follower analysis
    using existing LinkShield infrastructure.
    """
    
    def __init__(self):
        """Initialize the social media bot service."""
        self.quick_analysis_service = QuickAnalysisService()
        self.is_initialized = False
        
        # Service components (will be initialized later)
        self.account_analyzer = None
        self.compliance_monitor = None
        self.follower_analyzer = None     
   
    async def initialize(self):
        """Initialize the service and its components."""
        if self.is_initialized:
            return
            
        try:
            # Initialize quick analysis service
            await self.quick_analysis_service.initialize()
            
            # Initialize service components
            from .analyzers.account_safety_analyzer import AccountSafetyAnalyzer
            from .analyzers.compliance_monitor import ComplianceMonitor
            from .analyzers.verified_follower_analyzer import VerifiedFollowerAnalyzer
            
            self.account_analyzer = AccountSafetyAnalyzer()
            self.compliance_monitor = ComplianceMonitor()
            self.follower_analyzer = VerifiedFollowerAnalyzer()
            
            await self.account_analyzer.initialize()
            await self.compliance_monitor.initialize()
            await self.follower_analyzer.initialize()
            
            self.is_initialized = True
            logger.info("SocialMediaBotService initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize SocialMediaBotService: {e}")
            raise
    
    async def analyze_account_safety(
        self, 
        platform: PlatformType, 
        account_identifier: str, 
        user: BotUser
    ) -> AccountSafetyResult:
        """
        Analyze account safety and risk factors.
        
        Args:
            platform: Social media platform
            account_identifier: Account username or ID
            user: Bot user requesting analysis
            
        Returns:
            Account safety analysis result
        """
        if not self.is_initialized:
            await self.initialize()
        
        try:
            start_time = datetime.utcnow()
            
            # Use account analyzer to perform analysis
            result = await self.account_analyzer.analyze_account_risk(
                platform, account_identifier
            )
            
            # Log analysis request
            await self._log_analysis_request(
                user.id, "account_safety", platform.value, 
                account_identifier, result.risk_level.value
            )
            
            logger.info(f"Account safety analysis completed for {account_identifier} on {platform.value}")
            return result
            
        except Exception as e:
            logger.error(f"Error in account safety analysis: {e}")
            # Return safe fallback result
            return AccountSafetyResult(
                account_id=account_identifier,
                platform=platform,
                risk_score=0.0,
                risk_level=RiskLevel.SAFE,
                bot_probability=0.0,
                spam_indicators=[],
                scam_indicators=[],
                recommendations=["Analysis failed, manual verification recommended"],
                analysis_timestamp=datetime.utcnow(),
                confidence_score=0.0
            )
    
    async def check_compliance_status(
        self, 
        platform: PlatformType, 
        content: str, 
        user: BotUser
    ) -> ComplianceResult:
        """
        Check content compliance against platform policies.
        
        Args:
            platform: Social media platform
            content: Content to check for compliance
            user: Bot user requesting check
            
        Returns:
            Compliance check result
        """
        if not self.is_initialized:
            await self.initialize()
        
        try:
            # Use compliance monitor to check content
            result = await self.compliance_monitor.check_content_compliance(
                platform, content, {}
            )
            
            # Log compliance check
            await self._log_analysis_request(
                user.id, "compliance_check", platform.value,
                content[:100], result.severity_level.value
            )
            
            logger.info(f"Compliance check completed for content on {platform.value}")
            return result
            
        except Exception as e:
            logger.error(f"Error in compliance check: {e}")
            # Return safe fallback result
            return ComplianceResult(
                platform=platform,
                content_id="unknown",
                compliance_score=100.0,
                violations=[],
                recommendations=["Analysis failed, manual review recommended"],
                severity_level=RiskLevel.SAFE,
                analysis_timestamp=datetime.utcnow()
            )
    
    async def analyze_verified_followers(
        self, 
        platform: PlatformType, 
        account_identifier: str, 
        user: BotUser
    ) -> VerifiedFollowerResult:
        """
        Analyze verified followers and provide insights.
        
        Args:
            platform: Social media platform
            account_identifier: Account username or ID
            user: Bot user requesting analysis
            
        Returns:
            Verified follower analysis result
        """
        if not self.is_initialized:
            await self.initialize()
        
        try:
            # Use follower analyzer to analyze followers
            result = await self.follower_analyzer.analyze_verified_followers(
                platform, account_identifier
            )
            
            # Log follower analysis
            await self._log_analysis_request(
                user.id, "follower_analysis", platform.value,
                account_identifier, "completed"
            )
            
            logger.info(f"Verified follower analysis completed for {account_identifier} on {platform.value}")
            return result
            
        except Exception as e:
            logger.error(f"Error in verified follower analysis: {e}")
            # Return empty fallback result
            return VerifiedFollowerResult(
                account_id=account_identifier,
                platform=platform,
                total_verified_followers=0,
                verification_breakdown={},
                high_value_followers=[],
                networking_opportunities=[],
                analysis_timestamp=datetime.utcnow()
            )
    
    async def get_real_time_risk_assessment(
        self, 
        platform: PlatformType, 
        content_or_account: str, 
        assessment_type: str, 
        user: BotUser
    ) -> RiskAssessmentResult:
        """
        Perform real-time risk assessment with sub-3-second response.
        
        Args:
            platform: Social media platform
            content_or_account: Content or account to assess
            assessment_type: Type of assessment (account, content, url)
            user: Bot user requesting assessment
            
        Returns:
            Real-time risk assessment result
        """
        if not self.is_initialized:
            await self.initialize()
        
        start_time = datetime.utcnow()
        
        try:
            # Use quick analysis for fast response
            if assessment_type == "url":
                analysis_result = await self.quick_analysis_service.analyze_url(content_or_account)
                risk_level = self._map_risk_level(analysis_result.get("risk_level", "safe"))
                risk_score = analysis_result.get("risk_score", 0)
                risk_factors = analysis_result.get("risk_indicators", [])
                recommendations = [analysis_result.get("message", "No specific recommendations")]
                
            elif assessment_type == "account":
                # Quick account assessment
                account_result = await self.account_analyzer.analyze_account_risk(
                    platform, content_or_account
                )
                risk_level = account_result.risk_level
                risk_score = account_result.risk_score
                risk_factors = account_result.spam_indicators + account_result.scam_indicators
                recommendations = account_result.recommendations
                
            elif assessment_type == "content":
                # Quick content assessment
                compliance_result = await self.compliance_monitor.check_content_compliance(
                    platform, content_or_account, {}
                )
                risk_level = compliance_result.severity_level
                risk_score = 100 - compliance_result.compliance_score
                risk_factors = [v.violation_type for v in compliance_result.violations]
                recommendations = compliance_result.recommendations
                
            else:
                raise ValueError(f"Unknown assessment type: {assessment_type}")
            
            end_time = datetime.utcnow()
            response_time_ms = int((end_time - start_time).total_seconds() * 1000)
            
            # Log real-time assessment
            await self._log_analysis_request(
                user.id, f"realtime_{assessment_type}", platform.value,
                content_or_account[:100], risk_level.value
            )
            
            return RiskAssessmentResult(
                content_or_account=content_or_account,
                platform=platform,
                assessment_type=assessment_type,
                risk_level=risk_level,
                risk_score=risk_score,
                risk_factors=risk_factors,
                recommendations=recommendations,
                analysis_timestamp=end_time,
                response_time_ms=response_time_ms
            )
            
        except Exception as e:
            logger.error(f"Error in real-time risk assessment: {e}")
            end_time = datetime.utcnow()
            response_time_ms = int((end_time - start_time).total_seconds() * 1000)
            
            return RiskAssessmentResult(
                content_or_account=content_or_account,
                platform=platform,
                assessment_type=assessment_type,
                risk_level=RiskLevel.SAFE,
                risk_score=0.0,
                risk_factors=[],
                recommendations=["Assessment failed, manual review recommended"],
                analysis_timestamp=end_time,
                response_time_ms=response_time_ms
            )
    
    def _map_risk_level(self, risk_level_str: str) -> RiskLevel:
        """Map string risk level to RiskLevel enum."""
        mapping = {
            "safe": RiskLevel.SAFE,
            "low": RiskLevel.LOW,
            "medium": RiskLevel.MEDIUM,
            "high": RiskLevel.HIGH,
            "critical": RiskLevel.CRITICAL,
            "unknown": RiskLevel.SAFE  # Default to safe for unknown
        }
        return mapping.get(risk_level_str.lower(), RiskLevel.SAFE)
    
    async def _log_analysis_request(
        self, 
        user_id: int, 
        analysis_type: str, 
        platform: str, 
        target: str, 
        result: str
    ):
        """Log analysis request to database."""
        try:
            db_session = next(get_db())
            
            # Import here to avoid circular imports
            from src.models.social_media_bot import BotAnalysisLog
            
            log_entry = BotAnalysisLog(
                user_id=user_id,
                analysis_type=analysis_type,
                platform=platform,
                target_identifier=target,
                result_summary=result,
                created_at=datetime.utcnow()
            )
            
            db_session.add(log_entry)
            db_session.commit()
            
        except Exception as e:
            logger.error(f"Error logging analysis request: {e}")
        finally:
            if 'db_session' in locals():
                db_session.close()
    
    async def shutdown(self):
        """Shutdown the service and cleanup resources."""
        try:
            if self.account_analyzer:
                await self.account_analyzer.shutdown()
            if self.compliance_monitor:
                await self.compliance_monitor.shutdown()
            if self.follower_analyzer:
                await self.follower_analyzer.shutdown()
            if self.quick_analysis_service:
                await self.quick_analysis_service.shutdown()
            
            self.is_initialized = False
            logger.info("SocialMediaBotService shutdown completed")
            
        except Exception as e:
            logger.error(f"Error during service shutdown: {e}")


# Global service instance
social_media_bot_service = SocialMediaBotService()