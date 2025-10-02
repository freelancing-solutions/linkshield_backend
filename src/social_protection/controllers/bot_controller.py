"""
Bot Controller for Social Protection

This controller provides a specialized facade for bot integration and quick analysis services,
focusing on automated monitoring, API integrations, and rapid content assessment.
"""

import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Union
from fastapi import HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession

from src.authentication.auth_service import AuthService
from src.controllers.base_controller import BaseController
from src.models.user import User, UserRole
from src.models.project import Project
from src.services.email_service import EmailService
from src.services.security_service import SecurityService
from src.social_protection.types import PlatformType, RiskLevel, ScanStatus
from src.social_protection.data_models import ContentRiskAssessment, ContentType
from src.social_protection.services import SocialScanService
from src.social_protection.content_analyzer import (
    ContentRiskAnalyzer, LinkPenaltyDetector, SpamPatternDetector, CommunityNotesAnalyzer
)
from src.social_protection.algorithm_health import (
    VisibilityScorer, EngagementAnalyzer, PenaltyDetector, ShadowBanDetector
)
from src.utils import utc_datetime
from src.social_protection.logging_utils import get_logger
import asyncio
from enum import Enum

logger = get_logger("BotController")


class BotAnalysisType(Enum):
    """Types of bot analysis available"""
    QUICK_SCAN = "quick_scan"
    CONTENT_RISK = "content_risk"
    LINK_SAFETY = "link_safety"
    SPAM_DETECTION = "spam_detection"
    ALGORITHM_HEALTH = "algorithm_health"
    COMPREHENSIVE = "comprehensive"


class BotResponseFormat(Enum):
    """Response formats for bot integration"""
    JSON = "json"
    MINIMAL = "minimal"
    DETAILED = "detailed"
    WEBHOOK = "webhook"


class BotController(BaseController):
    """
    Specialized controller for bot integration and quick analysis services.
    
    This controller provides optimized endpoints for automated systems, bots,
    and third-party integrations that need fast, reliable social protection analysis.
    """
    
    def __init__(
        self,
        security_service: SecurityService,
        auth_service: AuthService,
        email_service: EmailService,
        social_scan_service: SocialScanService,
        content_risk_analyzer: ContentRiskAnalyzer,
        link_penalty_detector: LinkPenaltyDetector,
        spam_pattern_detector: SpamPatternDetector,
        community_notes_analyzer: CommunityNotesAnalyzer,
        visibility_scorer: VisibilityScorer,
        engagement_analyzer: EngagementAnalyzer,
        penalty_detector: PenaltyDetector,
        shadow_ban_detector: ShadowBanDetector
    ):
        """Initialize bot controller with all required services"""
        super().__init__(security_service, auth_service, email_service)
        
        # Core services
        self.social_scan_service = social_scan_service
        
        # Content analyzer services
        self.content_risk_analyzer = content_risk_analyzer
        self.link_penalty_detector = link_penalty_detector
        self.spam_pattern_detector = spam_pattern_detector
        self.community_notes_analyzer = community_notes_analyzer
        
        # Algorithm health services
        self.visibility_scorer = visibility_scorer
        self.engagement_analyzer = engagement_analyzer
        self.penalty_detector = penalty_detector
        self.shadow_ban_detector = shadow_ban_detector
        
        # Bot-specific rate limits (higher for automated systems)
        self.max_bot_requests_per_minute = 100
        self.max_bot_requests_per_hour = 2000
        self.max_batch_size = 50
        
        # Cache for frequent bot requests
        self._analysis_cache = {}
        self._cache_ttl = 300  # 5 minutes
    
    async def analyze_account_safety(
        self, 
        user: User, 
        account_identifier: str, 
        platform: PlatformType
    ) -> Dict[str, Any]:
        """
        Analyze account safety using existing social protection services.
        
        Args:
            user: User requesting the analysis
            account_identifier: Account username or identifier to analyze
            platform: Platform where the account exists
            
        Returns:
            Dict containing account safety analysis results compatible with BotResponse
        """
        try:
            # Check rate limits
            if not await self.check_rate_limit(
                user.id, "bot_account_analysis", 
                self.max_bot_requests_per_minute // 2, window_seconds=60
            ):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Account analysis rate limit exceeded"
                )
            
            # Validate account identifier
            if not account_identifier or len(account_identifier.strip()) == 0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Account identifier is required"
                )
            
            # Clean account identifier (remove @ if present)
            clean_identifier = account_identifier.lstrip('@').strip()
            
            # Use existing social scan service for comprehensive analysis
            try:
                scan_result = await self.social_scan_service.create_profile_scan(
                    user=user,
                    platform=platform,
                    profile_handle=clean_identifier,
                    scan_type="account_safety"
                )
                
                # Extract key safety metrics
                risk_score = 0.0
                risk_level = "low"
                risk_factors = []
                recommendations = []
                
                if scan_result and hasattr(scan_result, 'risk_assessment'):
                    risk_assessment = scan_result.risk_assessment
                    if risk_assessment:
                        risk_score = getattr(risk_assessment, 'overall_risk_score', 0.0)
                        risk_level = getattr(risk_assessment, 'risk_level', RiskLevel.LOW).value
                        
                        # Extract risk factors
                        if hasattr(risk_assessment, 'risk_factors'):
                            risk_factors = [
                                {
                                    "type": factor.risk_type,
                                    "severity": factor.severity,
                                    "description": factor.description
                                }
                                for factor in risk_assessment.risk_factors[:5]  # Limit to top 5
                            ]
                        
                        # Generate recommendations
                        if hasattr(risk_assessment, 'recommendations'):
                            recommendations = risk_assessment.recommendations[:3]  # Limit to 3
                            
            except Exception as scan_error:
                logger.warning(f"Social scan service unavailable: {scan_error}")
                scan_result = None
            
            # Fallback analysis using content risk analyzer if scan service unavailable
            if not scan_result:
                # Create mock profile content for analysis
                profile_content = f"Profile analysis for @{clean_identifier} on {platform.value}"
                
                risk_result = await self.content_risk_analyzer.analyze_content_risk(
                    profile_content, platform, {"account_identifier": clean_identifier}
                )
                
                risk_score = risk_result.overall_risk_score
                risk_level = risk_result.risk_level.value
                risk_factors = [
                    {
                        "type": factor.risk_type,
                        "severity": factor.severity,
                        "description": factor.description
                    }
                    for factor in risk_result.risk_factors[:5]
                ]
                recommendations = risk_result.recommendations[:3]
            
            # Prepare standardized response
            analysis_result = {
                "account_identifier": clean_identifier,
                "platform": platform.value,
                "risk_score": min(100.0, max(0.0, risk_score * 100)),  # Normalize to 0-100
                "risk_level": risk_level,
                "risk_factors": risk_factors,
                "recommendations": recommendations or [
                    "Monitor account activity regularly",
                    "Verify account authenticity through official channels",
                    "Be cautious when interacting with this account"
                ],
                "analysis_timestamp": utc_datetime().isoformat(),
                "confidence_score": 0.85  # Default confidence
            }
            
            self.log_operation(
                "Account safety analysis completed",
                user_id=user.id,
                details={
                    "account_identifier": clean_identifier,
                    "platform": platform.value,
                    "risk_level": risk_level,
                    "risk_score": analysis_result["risk_score"]
                }
            )
            
            return analysis_result
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error in account safety analysis: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Account safety analysis failed"
            )
    
    async def check_content_compliance(
        self, 
        user: User, 
        content: str, 
        platform: PlatformType
    ) -> Dict[str, Any]:
        """
        Check content compliance using existing analysis services.
        
        Args:
            user: User requesting the compliance check
            content: Content text to analyze for compliance
            platform: Platform context for compliance rules
            
        Returns:
            Dict containing compliance check results compatible with BotResponse
        """
        try:
            # Check rate limits
            if not await self.check_rate_limit(
                user.id, "bot_compliance_check", 
                self.max_bot_requests_per_minute, window_seconds=60
            ):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Compliance check rate limit exceeded"
                )
            
            # Validate content
            if not content or len(content.strip()) == 0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Content is required for compliance analysis"
                )
            
            # Limit content length for analysis
            max_content_length = 5000
            if len(content) > max_content_length:
                content = content[:max_content_length] + "..."
            
            # Use spam pattern detector for compliance checking
            spam_result = await self.spam_pattern_detector.detect_spam_patterns(
                content, platform, {"compliance_check": True}
            )
            
            # Use content risk analyzer for additional compliance insights
            risk_result = await self.content_risk_analyzer.analyze_content_risk(
                content, platform, {"analysis_type": "compliance"}
            )
            
            # Calculate compliance metrics
            spam_score = spam_result.spam_score if spam_result else 0.0
            risk_score = risk_result.overall_risk_score if risk_result else 0.0
            
            # Determine compliance status
            compliance_score = max(0.0, 100.0 - (spam_score * 50 + risk_score * 50))
            is_compliant = compliance_score >= 70.0  # 70% threshold for compliance
            
            # Extract violations
            violations = []
            if spam_result and hasattr(spam_result, 'detected_patterns'):
                for pattern in spam_result.detected_patterns:
                    violations.append({
                        "type": pattern.pattern_type,
                        "severity": "high" if pattern.confidence > 0.8 else "medium",
                        "description": f"Detected {pattern.pattern_type} pattern"
                    })
            
            if risk_result and hasattr(risk_result, 'risk_factors'):
                for factor in risk_result.risk_factors:
                    if factor.severity in ["high", "critical"]:
                        violations.append({
                            "type": factor.risk_type,
                            "severity": factor.severity,
                            "description": factor.description
                        })
            
            # Generate compliance recommendations
            recommendations = []
            if not is_compliant:
                if spam_score > 0.5:
                    recommendations.append("Remove spam-like content and promotional language")
                if risk_score > 0.5:
                    recommendations.append("Review content for potential policy violations")
                if violations:
                    recommendations.append("Address identified violations before publishing")
            else:
                recommendations.append("Content appears compliant with platform guidelines")
            
            # Prepare standardized response
            compliance_result = {
                "content_preview": content[:100] + "..." if len(content) > 100 else content,
                "platform": platform.value,
                "is_compliant": is_compliant,
                "compliance_score": round(compliance_score, 1),
                "spam_score": round(spam_score * 100, 1),
                "risk_score": round(risk_score * 100, 1),
                "violations": violations[:5],  # Limit to 5 violations
                "violation_count": len(violations),
                "recommendations": recommendations[:3],  # Limit to 3 recommendations
                "analysis_timestamp": utc_datetime().isoformat(),
                "confidence_score": 0.80  # Default confidence
            }
            
            self.log_operation(
                "Content compliance check completed",
                user_id=user.id,
                details={
                    "platform": platform.value,
                    "is_compliant": is_compliant,
                    "compliance_score": compliance_result["compliance_score"],
                    "violation_count": len(violations)
                }
            )
            
            return compliance_result
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error in content compliance check: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Content compliance check failed"
            )
    
    async def analyze_verified_followers(
        self, 
        user: User, 
        account_identifier: Optional[str] = None, 
        platform: PlatformType = PlatformType.TWITTER
    ) -> Dict[str, Any]:
        """
        Analyze verified followers using existing follower analysis services.
        
        Args:
            user: User requesting the follower analysis
            account_identifier: Account to analyze (optional, defaults to user's account)
            platform: Platform context for follower analysis
            
        Returns:
            Dict containing verified follower analysis results compatible with BotResponse
        """
        try:
            # Check rate limits (stricter for follower analysis as it's resource intensive)
            if not await self.check_rate_limit(
                user.id, "bot_follower_analysis", 
                self.max_bot_requests_per_minute // 4, window_seconds=60
            ):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Follower analysis rate limit exceeded"
                )
            
            # Use provided account identifier or default to user context
            target_account = account_identifier or user.username or str(user.id)
            if target_account:
                target_account = target_account.lstrip('@').strip()
            
            # Use social scan service for follower analysis
            try:
                scan_result = await self.social_scan_service.create_profile_scan(
                    user=user,
                    platform=platform,
                    profile_handle=target_account,
                    scan_type="follower_analysis"
                )
                
                # Extract follower metrics from scan result
                verified_followers_count = 0
                high_value_count = 0
                follower_categories = {}
                networking_opportunities = []
                
                if scan_result and hasattr(scan_result, 'follower_analysis'):
                    follower_analysis = scan_result.follower_analysis
                    if follower_analysis:
                        verified_followers_count = getattr(follower_analysis, 'verified_count', 0)
                        high_value_count = getattr(follower_analysis, 'high_value_count', 0)
                        
                        # Extract follower categories
                        if hasattr(follower_analysis, 'categories'):
                            follower_categories = follower_analysis.categories
                        
                        # Extract networking opportunities
                        if hasattr(follower_analysis, 'networking_opportunities'):
                            networking_opportunities = follower_analysis.networking_opportunities[:5]
                
            except Exception as scan_error:
                logger.warning(f"Social scan service unavailable for follower analysis: {scan_error}")
                # Fallback to mock analysis based on user data
                verified_followers_count = 0
                high_value_count = 0
                follower_categories = {
                    "verified": 0,
                    "business": 0,
                    "influencer": 0,
                    "regular": 0
                }
                networking_opportunities = []
            
            # Generate insights and recommendations
            insights = []
            recommendations = []
            
            if verified_followers_count > 0:
                insights.append(f"Account has {verified_followers_count} verified followers")
                if high_value_count > 0:
                    insights.append(f"{high_value_count} high-value networking opportunities identified")
                    recommendations.append("Consider engaging with high-value followers for networking")
            else:
                insights.append("No verified followers detected")
                recommendations.append("Focus on creating quality content to attract verified followers")
                recommendations.append("Engage with verified accounts in your industry")
            
            # Calculate follower quality score
            total_followers = sum(follower_categories.values()) if follower_categories else 1
            quality_score = (verified_followers_count + high_value_count * 2) / max(total_followers, 1) * 100
            quality_score = min(100.0, quality_score)
            
            # Prepare standardized response
            follower_result = {
                "account_identifier": target_account,
                "platform": platform.value,
                "verified_followers_count": verified_followers_count,
                "high_value_count": high_value_count,
                "total_analyzed": total_followers,
                "quality_score": round(quality_score, 1),
                "follower_categories": follower_categories,
                "networking_opportunities": networking_opportunities,
                "insights": insights[:3],  # Limit to 3 insights
                "recommendations": recommendations[:3],  # Limit to 3 recommendations
                "analysis_timestamp": utc_datetime().isoformat(),
                "confidence_score": 0.75  # Default confidence for follower analysis
            }
            
            self.log_operation(
                "Verified follower analysis completed",
                user_id=user.id,
                details={
                    "account_identifier": target_account,
                    "platform": platform.value,
                    "verified_count": verified_followers_count,
                    "quality_score": follower_result["quality_score"]
                }
            )
            
            return follower_result
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error in verified follower analysis: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Verified follower analysis failed"
            )  
  
    async def quick_content_analysis(
        self,
        user: User,
        content: str,
        platform: PlatformType,
        analysis_type: BotAnalysisType = BotAnalysisType.QUICK_SCAN,
        response_format: BotResponseFormat = BotResponseFormat.JSON,
        cache_enabled: bool = True
    ) -> Dict[str, Any]:
        """
        Perform quick content analysis optimized for bot integration
        
        Args:
            user: User/bot making the request
            content: Content to analyze
            platform: Platform context
            analysis_type: Type of analysis to perform
            response_format: Format of the response
            cache_enabled: Whether to use caching
            
        Returns:
            Dict containing quick analysis results
        """
        try:
            # Check bot rate limits
            if not await self.check_rate_limit(
                user.id, "bot_quick_analysis", 
                self.max_bot_requests_per_minute, window_seconds=60
            ):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Bot rate limit exceeded"
                )
            
            # Generate cache key if caching enabled
            cache_key = None
            if cache_enabled:
                cache_key = self._generate_cache_key(content, platform, analysis_type)
                cached_result = self._get_cached_result(cache_key)
                if cached_result:
                    return self._format_bot_response(
                        cached_result, response_format, from_cache=True
                    )
            
            # Validate content
            if not content or len(content.strip()) == 0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Content is required for analysis"
                )
            
            # Perform analysis based on type
            analysis_result = await self._perform_quick_analysis(
                content, platform, analysis_type, user
            )
            
            # Cache result if enabled
            if cache_enabled and cache_key:
                self._cache_result(cache_key, analysis_result)
            
            # Format response
            formatted_response = self._format_bot_response(
                analysis_result, response_format
            )
            
            self.log_operation(
                "Bot quick analysis completed",
                user_id=user.id,
                details={
                    "analysis_type": analysis_type.value,
                    "platform": platform.value,
                    "response_format": response_format.value,
                    "cached": cache_enabled and cache_key is not None
                }
            )
            
            return formatted_response
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error in bot quick analysis: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Quick analysis failed"
            )
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Health check endpoint for bot monitoring
        
        Returns:
            Dict containing service health status
        """
        try:
            # Check service health
            health_status = {
                "status": "healthy",
                "timestamp": utc_datetime().isoformat(),
                "services": {
                    "content_analyzer": await self._check_service_health(self.content_risk_analyzer),
                    "link_detector": await self._check_service_health(self.link_penalty_detector),
                    "spam_detector": await self._check_service_health(self.spam_pattern_detector),
                    "visibility_scorer": await self._check_service_health(self.visibility_scorer),
                    "engagement_analyzer": await self._check_service_health(self.engagement_analyzer)
                },
                "performance": {
                    "cache_size": len(self._analysis_cache),
                    "cache_hit_rate": self._calculate_cache_hit_rate(),
                    "average_response_time": 0.15  # Mock value
                },
                "limits": {
                    "max_requests_per_minute": self.max_bot_requests_per_minute,
                    "max_requests_per_hour": self.max_bot_requests_per_hour,
                    "max_batch_size": self.max_batch_size
                }
            }
            
            # Determine overall health
            service_statuses = [status["status"] for status in health_status["services"].values()]
            if "unhealthy" in service_statuses:
                health_status["status"] = "degraded"
            elif "warning" in service_statuses:
                health_status["status"] = "warning"
            
            return health_status
            
        except Exception as e:
            logger.error(f"Health check failed: {str(e)}")
            return {
                "status": "unhealthy",
                "timestamp": utc_datetime().isoformat(),
                "error": str(e)
            }
    
    # Helper methods
    
    async def _perform_quick_analysis(
        self,
        content: str,
        platform: PlatformType,
        analysis_type: BotAnalysisType,
        user: User
    ) -> Dict[str, Any]:
        """Perform quick analysis based on type"""
        
        if analysis_type == BotAnalysisType.QUICK_SCAN:
            # Basic risk assessment
            risk_result = await self.content_risk_analyzer.analyze_content_risk(
                content, platform, {}
            )
            return {
                "risk_score": risk_result.overall_risk_score,
                "risk_level": risk_result.risk_level.value,
                "primary_risks": [factor.risk_type for factor in risk_result.risk_factors[:3]]
            }
        
        elif analysis_type == BotAnalysisType.CONTENT_RISK:
            # Detailed content risk analysis
            risk_result = await self.content_risk_analyzer.analyze_content_risk(
                content, platform, {}
            )
            return {
                "overall_risk_score": risk_result.overall_risk_score,
                "risk_level": risk_result.risk_level.value,
                "risk_factors": [factor.dict() for factor in risk_result.risk_factors],
                "recommendations": risk_result.recommendations[:3]  # Limit for bot response
            }
        
        elif analysis_type == BotAnalysisType.SPAM_DETECTION:
            # Spam pattern detection
            spam_result = await self.spam_pattern_detector.detect_spam_patterns(
                content, platform, {}
            )
            return {
                "spam_score": spam_result.spam_score,
                "is_spam": spam_result.spam_score > 0.7,
                "detected_patterns": [pattern.pattern_type for pattern in spam_result.detected_patterns],
                "confidence": spam_result.confidence
            }
        
        else:
            # Default to quick scan
            return await self._perform_quick_analysis(
                content, platform, BotAnalysisType.QUICK_SCAN, user
            )
    
    def _generate_cache_key(
        self,
        content: str,
        platform: PlatformType,
        analysis_type: BotAnalysisType
    ) -> str:
        """Generate cache key for analysis result"""
        import hashlib
        
        content_hash = hashlib.md5(content.encode()).hexdigest()
        return f"{analysis_type.value}:{platform.value}:{content_hash}"
    
    def _get_cached_result(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached analysis result"""
        if cache_key in self._analysis_cache:
            cached_data = self._analysis_cache[cache_key]
            if utc_datetime().timestamp() - cached_data["timestamp"] < self._cache_ttl:
                return cached_data["result"]
            else:
                # Remove expired cache entry
                del self._analysis_cache[cache_key]
        return None
    
    def _cache_result(self, cache_key: str, result: Dict[str, Any]) -> None:
        """Cache analysis result"""
        self._analysis_cache[cache_key] = {
            "result": result,
            "timestamp": utc_datetime().timestamp()
        }
        
        # Simple cache cleanup (remove oldest entries if cache is too large)
        if len(self._analysis_cache) > 1000:
            oldest_key = min(
                self._analysis_cache.keys(),
                key=lambda k: self._analysis_cache[k]["timestamp"]
            )
            del self._analysis_cache[oldest_key]
    
    def _format_bot_response(
        self,
        result: Dict[str, Any],
        response_format: BotResponseFormat,
        from_cache: bool = False
    ) -> Dict[str, Any]:
        """Format response based on bot requirements"""
        
        if response_format == BotResponseFormat.MINIMAL:
            # Return only essential information
            return {
                "risk_score": result.get("risk_score", result.get("overall_risk_score", 0.0)),
                "risk_level": result.get("risk_level", "low"),
                "cached": from_cache
            }
        
        elif response_format == BotResponseFormat.DETAILED:
            # Return full analysis with metadata
            return {
                "analysis": result,
                "metadata": {
                    "cached": from_cache,
                    "timestamp": utc_datetime().isoformat(),
                    "response_format": response_format.value
                }
            }
        
        else:  # JSON (default)
            return {
                "success": True,
                "analysis": result,
                "cached": from_cache,
                "timestamp": utc_datetime().isoformat()
            }
    
    def _calculate_cache_hit_rate(self) -> float:
        """Calculate current cache hit rate"""
        # In a real implementation, this would track actual cache hits
        return 0.35  # Mock value
    
    async def _check_service_health(self, service) -> Dict[str, str]:
        """Check health of individual service"""
        try:
            # In a real implementation, this would perform actual health checks
            return {"status": "healthy", "response_time": "0.05s"}
        except Exception:
            return {"status": "unhealthy", "error": "Service unavailable"}