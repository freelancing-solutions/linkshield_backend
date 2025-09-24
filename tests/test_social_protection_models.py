"""
Comprehensive tests for social protection data models.

This module tests all social protection Pydantic models including:
- Profile scanning models (SocialProfileInfo, ProfileScanResult, etc.)
- Content risk assessment models (ContentRiskAssessment, ContentAnalysisResult, etc.)
- Extension integration models (ExtensionScanPayload, RealTimeAssessment, etc.)
- Real-time assessment models (ComprehensiveAssessment, AssessmentHistory, etc.)
"""

import pytest
from datetime import datetime, timezone
from typing import Dict, List, Optional
from uuid import UUID, uuid4
import json
import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from src.social_protection.data_models import (
    # Profile scanning models
    ProfileVerificationStatus, FollowerAuthenticityLevel, SocialProfileInfo,
    FollowerAnalysis, ProfileRiskFactor, ProfileSecurityAssessment,
    ProfileScanRequest, ProfileScanResult, BulkProfileScanRequest,
    BulkProfileScanResult, ProfileMonitoringConfig, ProfileMonitoringAlert,
    
    # Content risk assessment models
    ContentType, ContentModerationStatus, PolicyViolationType, ContentInfo,
    ContentRiskFactor, SpamAnalysis, LinkPenaltyAnalysis, SentimentAnalysis,
    ContentRiskAssessment, ContentAnalysisRequest, ContentAnalysisResult,
    BulkContentAnalysisRequest, BulkContentAnalysisResult, ContentMonitoringConfig,
    ContentMonitoringAlert,
    
    # Extension integration models
    ExtensionAction, ScanTrigger, ExtensionStatus, BrowserInfo, PageContext,
    ExtensionScanPayload, RealTimeAssessment, ExtensionResponse,
    FeedMonitoringData, LinkSafetyCheck, ExtensionSettings, ExtensionAnalytics,
    ExtensionHealthCheck, BatchExtensionRequest, BatchExtensionResponse,
    
    # Real-time assessment models
    AlgorithmHealthStatus, VisibilityTrend, PenaltyType, CrisisType,
    CrisisSeverity, EngagementMetrics, VisibilityMetrics,
    AlgorithmHealthAssessment, ReputationMetrics, MentionData,
    ReputationAssessment, CrisisIndicator, CrisisAssessment,
    ComprehensiveAssessment, AssessmentHistory
)


class TestProfileScanningModels:
    """Test profile scanning data models."""
    
    def test_profile_verification_status_enum(self):
        """Test ProfileVerificationStatus enum values."""
        assert ProfileVerificationStatus.VERIFIED == "verified"
        assert ProfileVerificationStatus.UNVERIFIED == "unverified"
        assert ProfileVerificationStatus.SUSPICIOUS == "suspicious"
        assert ProfileVerificationStatus.FAKE == "fake"
    
    def test_follower_authenticity_level_enum(self):
        """Test FollowerAuthenticityLevel enum values."""
        assert FollowerAuthenticityLevel.HIGH == "high"
        assert FollowerAuthenticityLevel.MEDIUM == "medium"
        assert FollowerAuthenticityLevel.LOW == "low"
        assert FollowerAuthenticityLevel.SUSPICIOUS == "suspicious"
    
    def test_social_profile_info_creation(self):
        """Test SocialProfileInfo model creation."""
        profile = SocialProfileInfo(
            platform="twitter",
            username="testuser",
            display_name="Test User",
            bio="Test bio",
            follower_count=1000,
            following_count=500,
            post_count=250,
            verification_status=ProfileVerificationStatus.VERIFIED,
            account_age_days=365,
            profile_image_url="https://example.com/avatar.jpg",
            is_private=False
        )
        
        assert profile.platform == "twitter"
        assert profile.username == "testuser"
        assert profile.display_name == "Test User"
        assert profile.bio == "Test bio"
        assert profile.follower_count == 1000
        assert profile.following_count == 500
        assert profile.post_count == 250
        assert profile.verification_status == ProfileVerificationStatus.VERIFIED
        assert profile.account_age_days == 365
        assert profile.profile_image_url == "https://example.com/avatar.jpg"
        assert profile.is_private is False
    
    def test_follower_analysis_creation(self):
        """Test FollowerAnalysis model creation."""
        analysis = FollowerAnalysis(
            total_followers=1000,
            authentic_followers=800,
            suspicious_followers=150,
            fake_followers=50,
            authenticity_level=FollowerAuthenticityLevel.HIGH,
            engagement_rate=0.05,
            bot_percentage=0.05
        )
        
        assert analysis.total_followers == 1000
        assert analysis.authentic_followers == 800
        assert analysis.suspicious_followers == 150
        assert analysis.fake_followers == 50
        assert analysis.authenticity_level == FollowerAuthenticityLevel.HIGH
        assert analysis.engagement_rate == 0.05
        assert analysis.bot_percentage == 0.05
    
    def test_profile_scan_result_creation(self):
        """Test ProfileScanResult model creation."""
        profile_info = SocialProfileInfo(
            platform="twitter",
            username="testuser",
            display_name="Test User",
            bio="Test bio",
            follower_count=1000,
            following_count=500,
            post_count=250,
            verification_status=ProfileVerificationStatus.VERIFIED,
            account_age_days=365,
            profile_image_url="https://example.com/avatar.jpg",
            is_private=False
        )
        
        follower_analysis = FollowerAnalysis(
            total_followers=1000,
            authentic_followers=800,
            suspicious_followers=150,
            fake_followers=50,
            authenticity_level=FollowerAuthenticityLevel.HIGH,
            engagement_rate=0.05,
            bot_percentage=0.05
        )
        
        scan_result = ProfileScanResult(
            scan_id=str(uuid4()),
            profile_info=profile_info,
            follower_analysis=follower_analysis,
            risk_factors=[],
            security_assessment=ProfileSecurityAssessment(
                overall_risk_score=0.2,
                trust_score=0.8,
                recommendations=["Monitor engagement patterns"]
            ),
            scan_timestamp=datetime.now(timezone.utc),
            processing_time_ms=1500
        )
        
        assert scan_result.profile_info == profile_info
        assert scan_result.follower_analysis == follower_analysis
        assert scan_result.security_assessment.overall_risk_score == 0.2
        assert scan_result.processing_time_ms == 1500


class TestContentRiskModels:
    """Test content risk assessment data models."""
    
    def test_content_type_enum(self):
        """Test ContentType enum values."""
        assert ContentType.TEXT == "text"
        assert ContentType.IMAGE == "image"
        assert ContentType.VIDEO == "video"
        assert ContentType.LINK == "link"
        assert ContentType.MIXED == "mixed"
    
    def test_content_moderation_status_enum(self):
        """Test ContentModerationStatus enum values."""
        assert ContentModerationStatus.APPROVED == "approved"
        assert ContentModerationStatus.FLAGGED == "flagged"
        assert ContentModerationStatus.REMOVED == "removed"
        assert ContentModerationStatus.UNDER_REVIEW == "under_review"
    
    def test_policy_violation_type_enum(self):
        """Test PolicyViolationType enum values."""
        assert PolicyViolationType.SPAM == "spam"
        assert PolicyViolationType.HARASSMENT == "harassment"
        assert PolicyViolationType.HATE_SPEECH == "hate_speech"
        assert PolicyViolationType.MISINFORMATION == "misinformation"
        assert PolicyViolationType.COPYRIGHT == "copyright"
        assert PolicyViolationType.ADULT_CONTENT == "adult_content"
    
    def test_content_info_creation(self):
        """Test ContentInfo model creation."""
        content = ContentInfo(
            content_id="post_123",
            content_type=ContentType.TEXT,
            text_content="This is a test post",
            image_urls=[],
            video_urls=[],
            link_urls=["https://example.com"],
            hashtags=["#test", "#example"],
            mentions=["@testuser"],
            language="en",
            character_count=19,
            word_count=5
        )
        
        assert content.content_id == "post_123"
        assert content.content_type == ContentType.TEXT
        assert content.text_content == "This is a test post"
        assert content.link_urls == ["https://example.com"]
        assert content.hashtags == ["#test", "#example"]
        assert content.mentions == ["@testuser"]
        assert content.language == "en"
        assert content.character_count == 19
        assert content.word_count == 5
    
    def test_spam_analysis_creation(self):
        """Test SpamAnalysis model creation."""
        spam_analysis = SpamAnalysis(
            spam_probability=0.1,
            spam_indicators=["excessive_hashtags"],
            keyword_density=0.05,
            repetitive_content_score=0.2,
            suspicious_patterns=[]
        )
        
        assert spam_analysis.spam_probability == 0.1
        assert spam_analysis.spam_indicators == ["excessive_hashtags"]
        assert spam_analysis.keyword_density == 0.05
        assert spam_analysis.repetitive_content_score == 0.2
        assert spam_analysis.suspicious_patterns == []
    
    def test_content_analysis_result_creation(self):
        """Test ContentAnalysisResult model creation."""
        content_info = ContentInfo(
            content_id="post_123",
            content_type=ContentType.TEXT,
            text_content="This is a test post",
            image_urls=[],
            video_urls=[],
            link_urls=["https://example.com"],
            hashtags=["#test"],
            mentions=["@testuser"],
            language="en",
            character_count=19,
            word_count=5
        )
        
        spam_analysis = SpamAnalysis(
            spam_probability=0.1,
            spam_indicators=[],
            keyword_density=0.05,
            repetitive_content_score=0.2,
            suspicious_patterns=[]
        )
        
        result = ContentAnalysisResult(
            analysis_id=str(uuid4()),
            content_info=content_info,
            spam_analysis=spam_analysis,
            link_penalty_analysis=LinkPenaltyAnalysis(
                penalty_risk_score=0.1,
                flagged_domains=[],
                suspicious_redirects=[],
                malware_risk=0.05
            ),
            sentiment_analysis=SentimentAnalysis(
                sentiment_score=0.7,
                sentiment_label="positive",
                confidence=0.85,
                emotional_indicators=["joy", "satisfaction"]
            ),
            risk_assessment=ContentRiskAssessment(
                overall_risk_score=0.15,
                risk_factors=[],
                moderation_status=ContentModerationStatus.APPROVED,
                policy_violations=[],
                recommendations=["Continue monitoring"]
            ),
            analysis_timestamp=datetime.now(timezone.utc),
            processing_time_ms=800
        )
        
        assert result.content_info == content_info
        assert result.spam_analysis == spam_analysis
        assert result.risk_assessment.overall_risk_score == 0.15
        assert result.processing_time_ms == 800


class TestExtensionIntegrationModels:
    """Test extension integration data models."""
    
    def test_extension_action_enum(self):
        """Test ExtensionAction enum values."""
        assert ExtensionAction.SCAN_PAGE == "scan_page"
        assert ExtensionAction.SCAN_LINK == "scan_link"
        assert ExtensionAction.MONITOR_FEED == "monitor_feed"
        assert ExtensionAction.CHECK_PROFILE == "check_profile"
    
    def test_scan_trigger_enum(self):
        """Test ScanTrigger enum values."""
        assert ScanTrigger.USER_CLICK == "user_click"
        assert ScanTrigger.PAGE_LOAD == "page_load"
        assert ScanTrigger.HOVER == "hover"
        assert ScanTrigger.SCHEDULED == "scheduled"
        assert ScanTrigger.REAL_TIME == "real_time"
    
    def test_extension_status_enum(self):
        """Test ExtensionStatus enum values."""
        assert ExtensionStatus.ACTIVE == "active"
        assert ExtensionStatus.INACTIVE == "inactive"
        assert ExtensionStatus.ERROR == "error"
        assert ExtensionStatus.UPDATING == "updating"
    
    def test_browser_info_creation(self):
        """Test BrowserInfo model creation."""
        browser_info = BrowserInfo(
            name="Chrome",
            version="120.0.0.0",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            platform="Windows",
            language="en-US",
            timezone="America/New_York"
        )
        
        assert browser_info.name == "Chrome"
        assert browser_info.version == "120.0.0.0"
        assert browser_info.platform == "Windows"
        assert browser_info.language == "en-US"
        assert browser_info.timezone == "America/New_York"
    
    def test_page_context_creation(self):
        """Test PageContext model creation."""
        page_context = PageContext(
            url="https://twitter.com/testuser",
            title="Test User (@testuser) / Twitter",
            domain="twitter.com",
            path="/testuser",
            referrer="https://google.com",
            is_social_media=True,
            platform_detected="twitter"
        )
        
        assert page_context.url == "https://twitter.com/testuser"
        assert page_context.title == "Test User (@testuser) / Twitter"
        assert page_context.domain == "twitter.com"
        assert page_context.path == "/testuser"
        assert page_context.referrer == "https://google.com"
        assert page_context.is_social_media is True
        assert page_context.platform_detected == "twitter"
    
    def test_extension_scan_payload_creation(self):
        """Test ExtensionScanPayload model creation."""
        browser_info = BrowserInfo(
            name="Chrome",
            version="120.0.0.0",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            platform="Windows",
            language="en-US",
            timezone="America/New_York"
        )
        
        page_context = PageContext(
            url="https://twitter.com/testuser",
            title="Test User (@testuser) / Twitter",
            domain="twitter.com",
            path="/testuser",
            referrer="https://google.com",
            is_social_media=True,
            platform_detected="twitter"
        )
        
        payload = ExtensionScanPayload(
            action=ExtensionAction.SCAN_PAGE,
            trigger=ScanTrigger.PAGE_LOAD,
            user_id=str(uuid4()),
            session_id=str(uuid4()),
            browser_info=browser_info,
            page_context=page_context,
            target_elements=[],
            scan_options={
                "deep_scan": True,
                "include_links": True,
                "monitor_changes": False
            },
            timestamp=datetime.now(timezone.utc)
        )
        
        assert payload.action == ExtensionAction.SCAN_PAGE
        assert payload.trigger == ScanTrigger.PAGE_LOAD
        assert payload.browser_info == browser_info
        assert payload.page_context == page_context
        assert payload.scan_options["deep_scan"] is True
    
    def test_real_time_assessment_creation(self):
        """Test RealTimeAssessment model creation."""
        assessment = RealTimeAssessment(
            assessment_id=str(uuid4()),
            overall_safety_score=0.85,
            threat_level="low",
            risk_factors=[],
            recommendations=["Safe to proceed"],
            confidence_score=0.9,
            processing_time_ms=150,
            timestamp=datetime.now(timezone.utc)
        )
        
        assert assessment.overall_safety_score == 0.85
        assert assessment.threat_level == "low"
        assert assessment.risk_factors == []
        assert assessment.recommendations == ["Safe to proceed"]
        assert assessment.confidence_score == 0.9
        assert assessment.processing_time_ms == 150


class TestRealTimeAssessmentModels:
    """Test real-time assessment data models."""
    
    def test_algorithm_health_status_enum(self):
        """Test AlgorithmHealthStatus enum values."""
        assert AlgorithmHealthStatus.HEALTHY == "healthy"
        assert AlgorithmHealthStatus.WARNING == "warning"
        assert AlgorithmHealthStatus.CRITICAL == "critical"
        assert AlgorithmHealthStatus.UNKNOWN == "unknown"
    
    def test_visibility_trend_enum(self):
        """Test VisibilityTrend enum values."""
        assert VisibilityTrend.INCREASING == "increasing"
        assert VisibilityTrend.STABLE == "stable"
        assert VisibilityTrend.DECREASING == "decreasing"
        assert VisibilityTrend.VOLATILE == "volatile"
    
    def test_crisis_type_enum(self):
        """Test CrisisType enum values."""
        assert CrisisType.REPUTATION == "reputation"
        assert CrisisType.SECURITY == "security"
        assert CrisisType.CONTENT == "content"
        assert CrisisType.ENGAGEMENT == "engagement"
        assert CrisisType.ALGORITHM == "algorithm"
    
    def test_crisis_severity_enum(self):
        """Test CrisisSeverity enum values."""
        assert CrisisSeverity.LOW == "low"
        assert CrisisSeverity.MEDIUM == "medium"
        assert CrisisSeverity.HIGH == "high"
        assert CrisisSeverity.CRITICAL == "critical"
    
    def test_engagement_metrics_creation(self):
        """Test EngagementMetrics model creation."""
        metrics = EngagementMetrics(
            likes_count=100,
            comments_count=25,
            shares_count=15,
            reactions_count=140,
            engagement_rate=0.05,
            average_engagement_per_post=35.0,
            engagement_trend=VisibilityTrend.INCREASING
        )
        
        assert metrics.likes_count == 100
        assert metrics.comments_count == 25
        assert metrics.shares_count == 15
        assert metrics.reactions_count == 140
        assert metrics.engagement_rate == 0.05
        assert metrics.average_engagement_per_post == 35.0
        assert metrics.engagement_trend == VisibilityTrend.INCREASING
    
    def test_visibility_metrics_creation(self):
        """Test VisibilityMetrics model creation."""
        metrics = VisibilityMetrics(
            reach=10000,
            impressions=25000,
            visibility_score=0.75,
            organic_reach=8000,
            paid_reach=2000,
            visibility_trend=VisibilityTrend.STABLE
        )
        
        assert metrics.reach == 10000
        assert metrics.impressions == 25000
        assert metrics.visibility_score == 0.75
        assert metrics.organic_reach == 8000
        assert metrics.paid_reach == 2000
        assert metrics.visibility_trend == VisibilityTrend.STABLE
    
    def test_algorithm_health_assessment_creation(self):
        """Test AlgorithmHealthAssessment model creation."""
        assessment = AlgorithmHealthAssessment(
            health_status=AlgorithmHealthStatus.HEALTHY,
            health_score=0.85,
            performance_indicators={
                "content_distribution": 0.9,
                "engagement_quality": 0.8,
                "reach_consistency": 0.85
            },
            detected_issues=[],
            recommendations=["Continue current strategy"],
            last_updated=datetime.now(timezone.utc)
        )
        
        assert assessment.health_status == AlgorithmHealthStatus.HEALTHY
        assert assessment.health_score == 0.85
        assert assessment.performance_indicators["content_distribution"] == 0.9
        assert assessment.detected_issues == []
        assert assessment.recommendations == ["Continue current strategy"]
    
    def test_comprehensive_assessment_creation(self):
        """Test ComprehensiveAssessment model creation."""
        engagement_metrics = EngagementMetrics(
            likes_count=100,
            comments_count=25,
            shares_count=15,
            reactions_count=140,
            engagement_rate=0.05,
            average_engagement_per_post=35.0,
            engagement_trend=VisibilityTrend.INCREASING
        )
        
        visibility_metrics = VisibilityMetrics(
            reach=10000,
            impressions=25000,
            visibility_score=0.75,
            organic_reach=8000,
            paid_reach=2000,
            visibility_trend=VisibilityTrend.STABLE
        )
        
        algorithm_health = AlgorithmHealthAssessment(
            health_status=AlgorithmHealthStatus.HEALTHY,
            health_score=0.85,
            performance_indicators={
                "content_distribution": 0.9,
                "engagement_quality": 0.8,
                "reach_consistency": 0.85
            },
            detected_issues=[],
            recommendations=["Continue current strategy"],
            last_updated=datetime.now(timezone.utc)
        )
        
        assessment = ComprehensiveAssessment(
            assessment_id=str(uuid4()),
            user_id=str(uuid4()),
            platform="twitter",
            engagement_metrics=engagement_metrics,
            visibility_metrics=visibility_metrics,
            algorithm_health=algorithm_health,
            reputation_assessment=ReputationAssessment(
                reputation_score=0.8,
                sentiment_score=0.7,
                mention_volume=50,
                positive_mentions=35,
                negative_mentions=5,
                neutral_mentions=10,
                reputation_trend=VisibilityTrend.STABLE,
                key_topics=["technology", "innovation"],
                influencer_mentions=[]
            ),
            crisis_assessment=CrisisAssessment(
                crisis_detected=False,
                crisis_indicators=[],
                overall_crisis_score=0.1,
                active_crises=[],
                mitigation_recommendations=[]
            ),
            overall_health_score=0.82,
            assessment_timestamp=datetime.now(timezone.utc),
            next_assessment_due=datetime.now(timezone.utc)
        )
        
        assert assessment.engagement_metrics == engagement_metrics
        assert assessment.visibility_metrics == visibility_metrics
        assert assessment.algorithm_health == algorithm_health
        assert assessment.overall_health_score == 0.82
        assert assessment.platform == "twitter"


class TestModelSerialization:
    """Test model serialization and deserialization."""
    
    def test_profile_scan_result_json_serialization(self):
        """Test ProfileScanResult JSON serialization."""
        profile_info = SocialProfileInfo(
            platform="twitter",
            username="testuser",
            display_name="Test User",
            bio="Test bio",
            follower_count=1000,
            following_count=500,
            post_count=250,
            verification_status=ProfileVerificationStatus.VERIFIED,
            account_age_days=365,
            profile_image_url="https://example.com/avatar.jpg",
            is_private=False
        )
        
        follower_analysis = FollowerAnalysis(
            total_followers=1000,
            authentic_followers=800,
            suspicious_followers=150,
            fake_followers=50,
            authenticity_level=FollowerAuthenticityLevel.HIGH,
            engagement_rate=0.05,
            bot_percentage=0.05
        )
        
        scan_result = ProfileScanResult(
            scan_id=str(uuid4()),
            profile_info=profile_info,
            follower_analysis=follower_analysis,
            risk_factors=[],
            security_assessment=ProfileSecurityAssessment(
                overall_risk_score=0.2,
                trust_score=0.8,
                recommendations=["Monitor engagement patterns"]
            ),
            scan_timestamp=datetime.now(timezone.utc),
            processing_time_ms=1500
        )
        
        # Test JSON serialization
        json_data = scan_result.model_dump_json()
        assert isinstance(json_data, str)
        
        # Test deserialization
        parsed_data = json.loads(json_data)
        reconstructed = ProfileScanResult.model_validate(parsed_data)
        
        assert reconstructed.profile_info.username == "testuser"
        assert reconstructed.follower_analysis.total_followers == 1000
        assert reconstructed.security_assessment.overall_risk_score == 0.2
    
    def test_extension_scan_payload_json_serialization(self):
        """Test ExtensionScanPayload JSON serialization."""
        browser_info = BrowserInfo(
            name="Chrome",
            version="120.0.0.0",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            platform="Windows",
            language="en-US",
            timezone="America/New_York"
        )
        
        page_context = PageContext(
            url="https://twitter.com/testuser",
            title="Test User (@testuser) / Twitter",
            domain="twitter.com",
            path="/testuser",
            referrer="https://google.com",
            is_social_media=True,
            platform_detected="twitter"
        )
        
        payload = ExtensionScanPayload(
            action=ExtensionAction.SCAN_PAGE,
            trigger=ScanTrigger.PAGE_LOAD,
            user_id=str(uuid4()),
            session_id=str(uuid4()),
            browser_info=browser_info,
            page_context=page_context,
            target_elements=[],
            scan_options={
                "deep_scan": True,
                "include_links": True,
                "monitor_changes": False
            },
            timestamp=datetime.now(timezone.utc)
        )
        
        # Test JSON serialization
        json_data = payload.model_dump_json()
        assert isinstance(json_data, str)
        
        # Test deserialization
        parsed_data = json.loads(json_data)
        reconstructed = ExtensionScanPayload.model_validate(parsed_data)
        
        assert reconstructed.action == ExtensionAction.SCAN_PAGE
        assert reconstructed.browser_info.name == "Chrome"
        assert reconstructed.page_context.domain == "twitter.com"
        assert reconstructed.scan_options["deep_scan"] is True


class TestModelValidation:
    """Test model validation and error handling."""
    
    def test_social_profile_info_validation_errors(self):
        """Test SocialProfileInfo validation errors."""
        with pytest.raises(ValueError):
            # Invalid follower count (negative)
            SocialProfileInfo(
                platform="twitter",
                username="testuser",
                display_name="Test User",
                bio="Test bio",
                follower_count=-1,  # Invalid
                following_count=500,
                post_count=250,
                verification_status=ProfileVerificationStatus.VERIFIED,
                account_age_days=365,
                profile_image_url="https://example.com/avatar.jpg",
                is_private=False
            )
    
    def test_engagement_metrics_validation_errors(self):
        """Test EngagementMetrics validation errors."""
        with pytest.raises(ValueError):
            # Invalid engagement rate (greater than 1)
            EngagementMetrics(
                likes_count=100,
                comments_count=25,
                shares_count=15,
                reactions_count=140,
                engagement_rate=1.5,  # Invalid (> 1.0)
                average_engagement_per_post=35.0,
                engagement_trend=VisibilityTrend.INCREASING
            )
    
    def test_required_field_validation(self):
        """Test required field validation."""
        with pytest.raises(ValueError):
            # Missing required fields
            SocialProfileInfo(
                platform="twitter",
                # username missing - required field
                display_name="Test User",
                bio="Test bio",
                follower_count=1000,
                following_count=500,
                post_count=250,
                verification_status=ProfileVerificationStatus.VERIFIED,
                account_age_days=365,
                profile_image_url="https://example.com/avatar.jpg",
                is_private=False
            )