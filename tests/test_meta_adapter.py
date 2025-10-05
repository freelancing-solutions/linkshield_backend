"""
Unit tests for MetaProtectionAdapter

Tests Facebook and Instagram Graph API integration, profile data fetching,
content policy checking, and Meta-specific risk assessment.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime
from typing import Dict, Any

from linkshield.social_protection.platform_adapters.meta_adapter import (
    MetaProtectionAdapter,
    MetaRiskFactor,
    MetaContentType
)
from linkshield.social_protection.types import PlatformType, RiskLevel
from linkshield.social_protection.exceptions import PlatformAdapterError


@pytest.fixture
def meta_config():
    """Meta adapter configuration for testing."""
    return {
        'facebook_access_token': 'test_fb_token_12345',
        'instagram_access_token': 'test_ig_token_12345',
        'facebook_app_id': 'test_app_id',
        'facebook_app_secret': 'test_app_secret',
        'enabled': True,
        'risk_thresholds': {
            'link_reach_reduction': 0.6,
            'content_review_flag': 0.8,
            'engagement_bait_score': 0.7,
            'ad_policy_violation': 0.9,
            'spam_detection_score': 0.5,
            'fake_engagement_ratio': 0.4,
            'community_standards_risk': 0.75
        }
    }


@pytest.fixture
def meta_adapter(meta_config):
    """Create MetaProtectionAdapter instance for testing."""
    with patch('httpx.AsyncClient'):
        adapter = MetaProtectionAdapter(config=meta_config)
        return adapter


@pytest.fixture
def mock_facebook_profile():
    """Mock Facebook profile data."""
    return {
        'id': '123456789',
        'name': 'Test User',
        'username': 'testuser',
        'picture': {'data': {'url': 'https://example.com/pic.jpg'}},
        'verified': False,
        'followers_count': 1000,
        'friends_count': 500
    }


@pytest.fixture
def mock_instagram_profile():
    """Mock Instagram profile data."""
    return {
        'id': '987654321',
        'username': 'testuser_ig',
        'name': 'Test User IG',
        'biography': 'Test bio',
        'followers_count': 5000,
        'follows_count': 300,
        'media_count': 150
    }


@pytest.fixture
def mock_facebook_post():
    """Mock Facebook post data."""
    return {
        'id': '123456789_987654321',
        'message': 'This is a test post with a link https://example.com',
        'created_time': '2024-01-01T12:00:00+0000',
        'from': {'id': '123456789', 'name': 'Test User'},
        'reactions': {'summary': {'total_count': 50}},
        'comments': {'summary': {'total_count': 10}},
        'shares': {'count': 5}
    }


class TestMetaAdapterInitialization:
    """Test Meta adapter initialization and configuration."""
    
    def test_adapter_initialization_with_facebook_token(self):
        """Test adapter initializes correctly with Facebook token."""
        config = {'facebook_access_token': 'test_token'}
        
        with patch('httpx.AsyncClient') as mock_client:
            adapter = MetaProtectionAdapter(config=config)
            
            assert adapter.platform_type == PlatformType.META_FACEBOOK
            assert adapter.is_enabled is True
            assert adapter.fb_client is not None
    
    def test_adapter_initialization_with_instagram_token(self):
        """Test adapter initializes correctly with Instagram token."""
        config = {'instagram_access_token': 'test_token'}
        
        with patch('httpx.AsyncClient') as mock_client:
            adapter = MetaProtectionAdapter(config=config)
            
            assert adapter.ig_client is not None
    
    def test_adapter_initialization_with_app_credentials(self):
        """Test adapter initializes with app ID and secret."""
        config = {
            'facebook_app_id': 'test_app_id',
            'facebook_app_secret': 'test_app_secret'
        }
        
        with patch('httpx.AsyncClient') as mock_client:
            adapter = MetaProtectionAdapter(config=config)
            
            assert adapter.fb_client is not None
    
    def test_adapter_initialization_without_credentials(self):
        """Test adapter handles missing credentials gracefully."""
        with patch('httpx.AsyncClient'):
            adapter = MetaProtectionAdapter(config={})
            
            assert adapter.is_enabled is False
            assert adapter.fb_client is None
            assert adapter.ig_client is None
    
    def test_risk_thresholds_loaded(self, meta_adapter):
        """Test risk thresholds are loaded from config."""
        assert meta_adapter.risk_thresholds['link_reach_reduction'] == 0.6
        assert meta_adapter.risk_thresholds['engagement_bait_score'] == 0.7


class TestCredentialValidation:
    """Test Meta API credential validation."""
    
    @pytest.mark.asyncio
    async def test_validate_facebook_credentials_success(self, meta_adapter):
        """Test successful Facebook credential validation."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'id': '123', 'name': 'Test'}
        
        meta_adapter.fb_client = AsyncMock()
        meta_adapter.fb_client.get = AsyncMock(return_value=mock_response)
        
        result = await meta_adapter.validate_credentials()
        
        assert result is True
        meta_adapter.fb_client.get.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_validate_instagram_credentials_success(self, meta_adapter):
        """Test successful Instagram credential validation."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'id': '456', 'username': 'test'}
        
        meta_adapter.fb_client = None
        meta_adapter.ig_client = AsyncMock()
        meta_adapter.ig_client.get = AsyncMock(return_value=mock_response)
        
        result = await meta_adapter.validate_credentials()
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_validate_credentials_no_clients(self, meta_adapter):
        """Test credential validation with no clients."""
        meta_adapter.fb_client = None
        meta_adapter.ig_client = None
        
        result = await meta_adapter.validate_credentials()
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_validate_credentials_api_error(self, meta_adapter):
        """Test credential validation handles API errors."""
        meta_adapter.fb_client = AsyncMock()
        meta_adapter.fb_client.get = AsyncMock(side_effect=Exception('API Error'))
        
        result = await meta_adapter.validate_credentials()
        
        assert result is False


class TestFacebookProfileFetching:
    """Test Facebook profile data fetching."""
    
    @pytest.mark.asyncio
    async def test_fetch_facebook_profile_success(self, meta_adapter, mock_facebook_profile):
        """Test successful Facebook profile fetch."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_facebook_profile
        
        meta_adapter.fb_client = AsyncMock()
        meta_adapter.fb_client.get = AsyncMock(return_value=mock_response)
        
        profile_data = await meta_adapter._fetch_facebook_profile('123456789')
        
        assert profile_data['id'] == '123456789'
        assert profile_data['name'] == 'Test User'
        assert profile_data['platform'] == 'facebook'
        assert 'fetched_at' in profile_data
    
    @pytest.mark.asyncio
    async def test_fetch_facebook_profile_no_client(self, meta_adapter):
        """Test Facebook profile fetch fails without client."""
        meta_adapter.fb_client = None
        
        with pytest.raises(PlatformAdapterError, match="not initialized"):
            await meta_adapter._fetch_facebook_profile('123456789')
    
    @pytest.mark.asyncio
    async def test_fetch_facebook_profile_api_error(self, meta_adapter):
        """Test Facebook profile fetch handles API errors."""
        mock_response = Mock()
        mock_response.status_code = 404
        
        meta_adapter.fb_client = AsyncMock()
        meta_adapter.fb_client.get = AsyncMock(return_value=mock_response)
        
        with pytest.raises(PlatformAdapterError, match="Facebook API error"):
            await meta_adapter._fetch_facebook_profile('invalid_id')


class TestInstagramProfileFetching:
    """Test Instagram profile data fetching."""
    
    @pytest.mark.asyncio
    async def test_fetch_instagram_profile_success(self, meta_adapter, mock_instagram_profile):
        """Test successful Instagram profile fetch."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_instagram_profile
        
        meta_adapter.ig_client = AsyncMock()
        meta_adapter.ig_client.get = AsyncMock(return_value=mock_response)
        
        profile_data = await meta_adapter._fetch_instagram_profile('987654321')
        
        assert profile_data['id'] == '987654321'
        assert profile_data['username'] == 'testuser_ig'
        assert profile_data['platform'] == 'instagram'
        assert 'fetched_at' in profile_data
    
    @pytest.mark.asyncio
    async def test_fetch_instagram_profile_no_client(self, meta_adapter):
        """Test Instagram profile fetch fails without client."""
        meta_adapter.ig_client = None
        
        with pytest.raises(PlatformAdapterError, match="not initialized"):
            await meta_adapter._fetch_instagram_profile('987654321')


class TestContentPolicyChecking:
    """Test Meta content policy checking."""
    
    def test_check_engagement_bait_patterns(self, meta_adapter):
        """Test engagement bait pattern detection."""
        content = 'Like if you agree! Share if you support! Tag someone who needs this!'
        
        result = meta_adapter._check_meta_content_policy(content, 'facebook_post')
        
        assert result['compliant'] is False
        assert result['risk_score'] > 0
        assert len(result['violations']) > 0
        assert any(v['type'] == 'engagement_bait' for v in result['violations'])
    
    def test_check_external_link_penalty(self, meta_adapter):
        """Test external link reach reduction detection."""
        content = 'Check out this link https://example.com for more info'
        
        result = meta_adapter._check_meta_content_policy(content, 'facebook_post')
        
        assert any(v['type'] == 'external_link' for v in result['violations'])
        assert result['risk_score'] > 0
    
    def test_check_spam_indicators(self, meta_adapter):
        """Test spam indicator detection."""
        content = 'FREE!!! CLICK NOW!!! LIMITED TIME!!! ACT NOW!!!'
        
        result = meta_adapter._check_meta_content_policy(content, 'facebook_post')
        
        assert any(v['type'] == 'spam_indicators' for v in result['violations'])
        assert result['risk_score'] >= 0.3
    
    def test_check_sensational_content(self, meta_adapter):
        """Test sensational content detection."""
        content = 'You won\'t believe this shocking secret that they don\'t want you to know!'
        
        result = meta_adapter._check_meta_content_policy(content, 'facebook_post')
        
        assert any(v['type'] == 'sensational_content' for v in result['violations'])
    
    def test_check_ad_prohibited_content(self, meta_adapter):
        """Test prohibited ad content detection."""
        content = 'Get rich quick with crypto! Miracle cure for weight loss!'
        
        result = meta_adapter._check_meta_content_policy(content, 'facebook_ad')
        
        assert any(v['type'] == 'prohibited_ad_content' for v in result['violations'])
        assert result['risk_score'] > 0.4
    
    def test_check_compliant_content(self, meta_adapter):
        """Test compliant content passes checks."""
        content = 'Just sharing my thoughts on this beautiful day.'
        
        result = meta_adapter._check_meta_content_policy(content, 'facebook_post')
        
        assert result['compliant'] is True
        assert result['risk_score'] == 0.0
        assert len(result['violations']) == 0


class TestPolicyRecommendations:
    """Test policy recommendation generation."""
    
    def test_generate_engagement_bait_recommendations(self, meta_adapter):
        """Test recommendations for engagement bait."""
        violations = [{'type': 'engagement_bait', 'pattern': 'like if'}]
        
        recommendations = meta_adapter._generate_policy_recommendations(violations)
        
        assert len(recommendations) > 0
        assert any('engagement bait' in r.lower() for r in recommendations)
    
    def test_generate_external_link_recommendations(self, meta_adapter):
        """Test recommendations for external links."""
        violations = [{'type': 'external_link'}]
        
        recommendations = meta_adapter._generate_policy_recommendations(violations)
        
        assert any('native content' in r.lower() for r in recommendations)
    
    def test_generate_multiple_recommendations(self, meta_adapter):
        """Test recommendations for multiple violations."""
        violations = [
            {'type': 'engagement_bait'},
            {'type': 'spam_indicators'},
            {'type': 'sensational_content'}
        ]
        
        recommendations = meta_adapter._generate_policy_recommendations(violations)
        
        assert len(recommendations) >= 3



class TestProfileScanning:
    """Test comprehensive profile scanning."""
    
    @pytest.mark.asyncio
    async def test_scan_facebook_profile(self, meta_adapter):
        """Test Facebook profile scan."""
        profile_data = {
            'platform': 'facebook',
            'user_id': '123456789',
            'username': 'testuser',
            'verified': False,
            'followers_count': 1000,
            'has_ad_account': False
        }
        
        # Mock the helper methods
        meta_adapter._analyze_account_authenticity = AsyncMock(return_value={
            'authenticity_score': 0.9,
            'verification_status': False
        })
        meta_adapter._check_community_standards = AsyncMock(return_value={
            'compliance_score': 0.95
        })
        meta_adapter._analyze_engagement_quality = AsyncMock(return_value={
            'engagement_authenticity': 0.8
        })
        meta_adapter._analyze_content_policy_compliance = AsyncMock(return_value={
            'compliance_score': 0.9
        })
        
        result = await meta_adapter.scan_profile(profile_data)
        
        assert result['platform'] == PlatformType.META_FACEBOOK.value
        assert result['sub_platform'] == 'facebook'
        assert result['username'] == 'testuser'
        assert 'risk_score' in result
        assert 'overall_risk_level' in result
        assert 'recommendations' in result
        assert 'risk_factors' in result
    
    @pytest.mark.asyncio
    async def test_scan_instagram_profile(self, meta_adapter):
        """Test Instagram profile scan."""
        profile_data = {
            'platform': 'instagram',
            'user_id': '987654321',
            'username': 'testuser_ig',
            'followers_count': 5000
        }
        
        # Mock the helper methods
        meta_adapter._analyze_account_authenticity = AsyncMock(return_value={})
        meta_adapter._check_community_standards = AsyncMock(return_value={})
        meta_adapter._analyze_engagement_quality = AsyncMock(return_value={})
        meta_adapter._analyze_content_policy_compliance = AsyncMock(return_value={})
        
        result = await meta_adapter.scan_profile(profile_data)
        
        assert result['sub_platform'] == 'instagram'
        assert result['username'] == 'testuser_ig'
    
    @pytest.mark.asyncio
    async def test_scan_profile_with_ad_account(self, meta_adapter):
        """Test profile scan includes ad account health."""
        profile_data = {
            'platform': 'facebook',
            'user_id': '123456789',
            'username': 'testuser',
            'has_ad_account': True
        }
        
        # Mock the helper methods
        meta_adapter._analyze_account_authenticity = AsyncMock(return_value={})
        meta_adapter._check_community_standards = AsyncMock(return_value={})
        meta_adapter._analyze_ad_account_health = AsyncMock(return_value={
            'account_status': 'active',
            'ad_delivery_health': 0.85
        })
        meta_adapter._analyze_engagement_quality = AsyncMock(return_value={})
        meta_adapter._analyze_content_policy_compliance = AsyncMock(return_value={})
        
        result = await meta_adapter.scan_profile(profile_data)
        
        assert 'ad_account_health' in result['risk_factors']
        meta_adapter._analyze_ad_account_health.assert_called_once()


class TestContentAnalysis:
    """Test Meta content analysis."""
    
    @pytest.mark.asyncio
    async def test_analyze_facebook_post(self, meta_adapter):
        """Test Facebook post analysis."""
        content_data = {
            'content_id': '123_456',
            'content_type': 'facebook_post',
            'message': 'This is a test post',
            'external_links': [],
            'is_ad': False
        }
        
        # Mock the helper methods
        meta_adapter._analyze_link_reach_reduction = AsyncMock(return_value={
            'reach_reduction_risk': 0.0
        })
        meta_adapter._detect_engagement_bait = AsyncMock(return_value={
            'engagement_bait_score': 0.0
        })
        meta_adapter._check_content_review_triggers = AsyncMock(return_value={
            'review_trigger_score': 0.0
        })
        meta_adapter._detect_spam_patterns = AsyncMock(return_value={
            'spam_score': 0.0
        })
        meta_adapter._check_community_standards_violations = AsyncMock(return_value={
            'violation_score': 0.0
        })
        
        result = await meta_adapter.analyze_content(content_data)
        
        assert result['platform'] == PlatformType.META_FACEBOOK.value
        assert result['content_type'] == 'facebook_post'
        assert 'risk_score' in result
        assert 'risk_factors' in result
        assert 'recommendations' in result
    
    @pytest.mark.asyncio
    async def test_analyze_instagram_post(self, meta_adapter):
        """Test Instagram post analysis."""
        content_data = {
            'content_id': '789',
            'content_type': 'instagram_post',
            'caption': 'Instagram test post',
            'external_links': []
        }
        
        # Mock the helper methods
        meta_adapter._analyze_link_reach_reduction = AsyncMock(return_value={})
        meta_adapter._detect_engagement_bait = AsyncMock(return_value={})
        meta_adapter._check_content_review_triggers = AsyncMock(return_value={})
        meta_adapter._detect_spam_patterns = AsyncMock(return_value={})
        meta_adapter._check_community_standards_violations = AsyncMock(return_value={})
        
        result = await meta_adapter.analyze_content(content_data)
        
        assert result['content_type'] == 'instagram_post'
    
    @pytest.mark.asyncio
    async def test_analyze_ad_content(self, meta_adapter):
        """Test ad content analysis includes ad policy check."""
        content_data = {
            'content_id': '123_456',
            'content_type': 'facebook_ad',
            'message': 'Ad content',
            'is_ad': True
        }
        
        # Mock the helper methods
        meta_adapter._analyze_link_reach_reduction = AsyncMock(return_value={})
        meta_adapter._detect_engagement_bait = AsyncMock(return_value={})
        meta_adapter._check_content_review_triggers = AsyncMock(return_value={})
        meta_adapter._analyze_ad_policy_compliance = AsyncMock(return_value={
            'policy_compliance_score': 0.95
        })
        meta_adapter._detect_spam_patterns = AsyncMock(return_value={})
        meta_adapter._check_community_standards_violations = AsyncMock(return_value={})
        
        result = await meta_adapter.analyze_content(content_data)
        
        assert 'ad_policy' in result['risk_factors']
        meta_adapter._analyze_ad_policy_compliance.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_analyze_content_with_external_links(self, meta_adapter):
        """Test content analysis with external links."""
        content_data = {
            'content_id': '123_456',
            'content_type': 'facebook_post',
            'message': 'Check this out https://example.com',
            'external_links': ['https://example.com']
        }
        
        # Mock the helper methods
        meta_adapter._analyze_link_reach_reduction = AsyncMock(return_value={
            'external_link_count': 1,
            'reach_reduction_risk': 0.4
        })
        meta_adapter._detect_engagement_bait = AsyncMock(return_value={})
        meta_adapter._check_content_review_triggers = AsyncMock(return_value={})
        meta_adapter._detect_spam_patterns = AsyncMock(return_value={})
        meta_adapter._check_community_standards_violations = AsyncMock(return_value={})
        
        result = await meta_adapter.analyze_content(content_data)
        
        assert result['risk_factors']['link_reach_reduction']['external_link_count'] == 1


class TestAlgorithmHealthAssessment:
    """Test Meta algorithm health assessment."""
    
    @pytest.mark.asyncio
    async def test_get_algorithm_health_facebook(self, meta_adapter):
        """Test Facebook algorithm health assessment."""
        account_data = {
            'platform': 'facebook',
            'user_id': '123456789',
            'username': 'testuser',
            'recent_posts': []
        }
        
        # Mock the helper methods
        meta_adapter._calculate_reach_score = AsyncMock(return_value=0.75)
        meta_adapter._analyze_engagement_health = AsyncMock(return_value={
            'engagement_rate': 0.05
        })
        meta_adapter._analyze_content_distribution = AsyncMock(return_value={
            'organic_reach': 0.6
        })
        meta_adapter._detect_algorithmic_penalties = AsyncMock(return_value={
            'penalties_detected': []
        })
        
        result = await meta_adapter.get_algorithm_health(account_data)
        
        assert result['platform'] == PlatformType.META_FACEBOOK.value
        assert result['sub_platform'] == 'facebook'
        assert 'reach_score' in result
        assert 'engagement_health' in result
        assert 'distribution_metrics' in result
        assert 'penalty_indicators' in result
        assert 'recommendations' in result
    
    @pytest.mark.asyncio
    async def test_get_algorithm_health_instagram(self, meta_adapter):
        """Test Instagram algorithm health assessment."""
        account_data = {
            'platform': 'instagram',
            'user_id': '987654321',
            'username': 'testuser_ig'
        }
        
        # Mock the helper methods
        meta_adapter._calculate_reach_score = AsyncMock(return_value=0.8)
        meta_adapter._analyze_engagement_health = AsyncMock(return_value={})
        meta_adapter._analyze_content_distribution = AsyncMock(return_value={})
        meta_adapter._detect_algorithmic_penalties = AsyncMock(return_value={})
        
        result = await meta_adapter.get_algorithm_health(account_data)
        
        assert result['sub_platform'] == 'instagram'
        assert result['reach_score'] == 0.8


class TestCrisisDetection:
    """Test Meta crisis signal detection."""
    
    @pytest.mark.asyncio
    async def test_detect_crisis_signals(self, meta_adapter):
        """Test crisis signal detection."""
        monitoring_data = {
            'platform': 'facebook',
            'user_id': '123456789',
            'username': 'testuser',
            'recent_comments': [],
            'recent_reactions': []
        }
        
        # Mock the helper methods
        meta_adapter._detect_viral_negative_content = AsyncMock(return_value={
            'viral_negative_detected': False
        })
        meta_adapter._detect_coordinated_reporting = AsyncMock(return_value={
            'coordinated_reporting_detected': False
        })
        meta_adapter._monitor_community_backlash = AsyncMock(return_value={
            'backlash_level': 'low'
        })
        meta_adapter._assess_brand_safety_issues = AsyncMock(return_value={
            'brand_safety_score': 0.9
        })
        meta_adapter._monitor_policy_enforcement = AsyncMock(return_value={
            'enforcement_actions': []
        })
        
        result = await meta_adapter.detect_crisis_signals(monitoring_data)
        
        assert result['platform'] == PlatformType.META_FACEBOOK.value
        assert result['sub_platform'] == 'facebook'
        assert 'crisis_level' in result
        assert 'crisis_indicators' in result
        assert 'alert_triggers' in result
        assert 'recommended_actions' in result
    
    @pytest.mark.asyncio
    async def test_detect_high_crisis_level(self, meta_adapter):
        """Test detection of high crisis level."""
        monitoring_data = {
            'platform': 'facebook',
            'user_id': '123456789',
            'username': 'testuser'
        }
        
        # Mock high-risk indicators
        meta_adapter._detect_viral_negative_content = AsyncMock(return_value={
            'viral_negative_detected': True,
            'severity': 'high'
        })
        meta_adapter._detect_coordinated_reporting = AsyncMock(return_value={
            'coordinated_reporting_detected': True
        })
        meta_adapter._monitor_community_backlash = AsyncMock(return_value={
            'backlash_level': 'high'
        })
        meta_adapter._assess_brand_safety_issues = AsyncMock(return_value={
            'brand_safety_score': 0.2
        })
        meta_adapter._monitor_policy_enforcement = AsyncMock(return_value={
            'enforcement_actions': ['content_removed']
        })
        
        result = await meta_adapter.detect_crisis_signals(monitoring_data)
        
        # Verify crisis indicators were collected
        assert 'crisis_indicators' in result
        assert result['crisis_indicators']['viral_negative_content']['viral_negative_detected'] is True
        assert result['crisis_indicators']['coordinated_reporting']['coordinated_reporting_detected'] is True


class TestHelperMethods:
    """Test helper methods."""
    
    @pytest.mark.asyncio
    async def test_analyze_account_authenticity(self, meta_adapter):
        """Test account authenticity analysis."""
        profile_data = {'verified': True, 'followers_count': 10000}
        
        result = await meta_adapter._analyze_account_authenticity(profile_data)
        
        assert 'authenticity_score' in result
        assert 'verification_status' in result
        assert result['verification_status'] is True
    
    @pytest.mark.asyncio
    async def test_check_community_standards(self, meta_adapter):
        """Test community standards check."""
        profile_data = {'user_id': '123'}
        
        result = await meta_adapter._check_community_standards(profile_data)
        
        assert 'compliance_score' in result
        assert 'violations_history' in result
    
    @pytest.mark.asyncio
    async def test_analyze_link_reach_reduction(self, meta_adapter):
        """Test link reach reduction analysis."""
        content_data = {'external_links': ['https://example.com', 'https://test.com']}
        
        result = await meta_adapter._analyze_link_reach_reduction(content_data)
        
        assert 'external_link_count' in result
        assert result['external_link_count'] == 2
        assert 'reach_reduction_risk' in result


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
