"""
Unit tests for LinkedInProtectionAdapter

Tests LinkedIn API integration, profile data fetching, professional content analysis,
rate limit handling, and LinkedIn-specific risk assessment.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime
from typing import Dict, Any

from src.social_protection.platform_adapters.linkedin_adapter import (
    LinkedInProtectionAdapter,
    LinkedInRiskFactor,
    LinkedInContentType
)
from src.social_protection.types import PlatformType, RiskLevel
from src.social_protection.exceptions import PlatformAdapterError


@pytest.fixture
def linkedin_config():
    """LinkedIn adapter configuration for testing."""
    return {
        'access_token': 'test_access_token_12345',
        'enabled': True,
        'api_base_url': 'https://api.linkedin.com/v2',
        'daily_request_limit': 500,
        'hourly_request_limit': 100,
        'risk_thresholds': {
            'fake_connection_ratio': 0.25,
            'professional_compliance_score': 0.8,
            'business_reputation_risk': 0.7,
            'content_professionalism_score': 0.75,
            'spam_messaging_threshold': 0.6,
            'fake_endorsement_ratio': 0.3,
            'company_impersonation_risk': 0.9,
            'recruitment_scam_score': 0.8
        }
    }


@pytest.fixture
def linkedin_adapter(linkedin_config):
    """Create LinkedInProtectionAdapter instance for testing."""
    with patch('src.social_protection.platform_adapters.linkedin_adapter.requests.Session'):
        adapter = LinkedInProtectionAdapter(config=linkedin_config)
        return adapter


@pytest.fixture
def mock_linkedin_profile():
    """Mock LinkedIn profile data."""
    return {
        'id': 'abc123xyz',
        'firstName': {'localized': {'en_US': 'John'}},
        'lastName': {'localized': {'en_US': 'Doe'}},
        'headline': {'localized': {'en_US': 'Senior Software Engineer at Tech Company'}},
        'vanityName': 'johndoe',
        'industry': 'Information Technology',
        'location': {'name': 'San Francisco, CA'},
        'summary': {'localized': {'en_US': 'Experienced software engineer with 10+ years in the industry.'}},
        'profilePicture': {'displayImage': 'https://example.com/profile.jpg'}
    }


@pytest.fixture
def mock_linkedin_post():
    """Mock LinkedIn post data."""
    return {
        'id': 'urn:li:share:123456789',
        'text': {'text': 'Excited to share our latest innovation in AI technology!'},
        'author': 'urn:li:person:abc123xyz',
        'created': {'time': 1704067200000},
        'lastModified': {'time': 1704067200000},
        'distribution': {'feedDistribution': 'MAIN_FEED'},
        'content': {}
    }


class TestLinkedInAdapterInitialization:
    """Test LinkedIn adapter initialization and configuration."""
    
    def test_adapter_initialization_with_access_token(self, linkedin_config):
        """Test adapter initializes correctly with access token."""
        with patch('src.social_protection.platform_adapters.linkedin_adapter.requests.Session') as mock_session:
            adapter = LinkedInProtectionAdapter(config=linkedin_config)
            
            assert adapter.platform_type == PlatformType.LINKEDIN
            assert adapter.is_enabled is True
            assert adapter.config == linkedin_config
            mock_session.assert_called_once()
    
    def test_adapter_initialization_without_credentials(self):
        """Test adapter handles missing credentials gracefully."""
        with patch('src.social_protection.platform_adapters.linkedin_adapter.requests.Session'):
            adapter = LinkedInProtectionAdapter(config={})
            
            assert adapter.is_enabled is False
            assert adapter.api_client is None
    
    def test_adapter_initialization_with_oauth_credentials(self):
        """Test adapter initializes with OAuth credentials."""
        config = {
            'client_id': 'test_client_id',
            'client_secret': 'test_client_secret'
        }
        
        with patch('src.social_protection.platform_adapters.linkedin_adapter.requests.Session') as mock_session:
            adapter = LinkedInProtectionAdapter(config=config)
            
            mock_session.assert_called_once()
    
    def test_risk_thresholds_loaded(self, linkedin_adapter):
        """Test risk thresholds are loaded from config."""
        assert linkedin_adapter.risk_thresholds['fake_connection_ratio'] == 0.25
        assert linkedin_adapter.risk_thresholds['professional_compliance_score'] == 0.8
        assert linkedin_adapter.risk_thresholds['recruitment_scam_score'] == 0.8
    
    def test_api_base_url_configured(self, linkedin_adapter):
        """Test API base URL is configured correctly."""
        assert linkedin_adapter.api_base_url == 'https://api.linkedin.com/v2'


class TestCredentialValidation:
    """Test LinkedIn API credential validation."""
    
    @pytest.mark.asyncio
    async def test_validate_credentials_success(self, linkedin_adapter):
        """Test successful credential validation."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json = Mock(return_value={'localizedFirstName': 'John'})
        
        linkedin_adapter.api_client = Mock()
        linkedin_adapter.api_client.get = Mock(return_value=mock_response)
        
        result = await linkedin_adapter.validate_credentials()
        
        assert result is True
        linkedin_adapter.api_client.get.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_validate_credentials_no_client(self, linkedin_adapter):
        """Test credential validation with no client."""
        linkedin_adapter.api_client = None
        
        result = await linkedin_adapter.validate_credentials()
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_validate_credentials_unauthorized(self, linkedin_adapter):
        """Test credential validation handles 401 unauthorized."""
        mock_response = Mock()
        mock_response.status_code = 401
        
        linkedin_adapter.api_client = Mock()
        linkedin_adapter.api_client.get = Mock(return_value=mock_response)
        
        result = await linkedin_adapter.validate_credentials()
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_validate_credentials_api_error(self, linkedin_adapter):
        """Test credential validation handles API errors."""
        from requests.exceptions import RequestException
        
        linkedin_adapter.api_client = Mock()
        linkedin_adapter.api_client.get = Mock(side_effect=RequestException('Connection error'))
        
        result = await linkedin_adapter.validate_credentials()
        
        assert result is False


class TestProfileDataFetching:
    """Test LinkedIn profile data fetching."""
    
    @pytest.mark.asyncio
    async def test_fetch_profile_data_success(self, linkedin_adapter, mock_linkedin_profile):
        """Test successful profile data fetch."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json = Mock(return_value=mock_linkedin_profile)
        
        linkedin_adapter.api_client = Mock()
        linkedin_adapter.api_client.get = Mock(return_value=mock_response)
        
        profile_data = await linkedin_adapter.fetch_profile_data('abc123xyz')
        
        assert profile_data['profile_id'] == 'abc123xyz'
        assert profile_data['first_name'] == 'John'
        assert profile_data['last_name'] == 'Doe'
        assert profile_data['vanity_name'] == 'johndoe'
        assert 'fetched_at' in profile_data
        linkedin_adapter.api_client.get.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_fetch_profile_data_no_client(self, linkedin_adapter):
        """Test profile fetch fails without client."""
        linkedin_adapter.api_client = None
        
        with pytest.raises(PlatformAdapterError, match="not initialized"):
            await linkedin_adapter.fetch_profile_data('abc123xyz')
    
    @pytest.mark.asyncio
    async def test_fetch_profile_data_not_found(self, linkedin_adapter):
        """Test profile fetch handles profile not found."""
        mock_response = Mock()
        mock_response.status_code = 404
        
        linkedin_adapter.api_client = Mock()
        linkedin_adapter.api_client.get = Mock(return_value=mock_response)
        
        with pytest.raises(PlatformAdapterError, match="Failed to fetch"):
            await linkedin_adapter.fetch_profile_data('nonexistent')
    
    @pytest.mark.asyncio
    async def test_fetch_profile_data_rate_limit(self, linkedin_adapter):
        """Test profile fetch handles rate limit."""
        mock_response = Mock()
        mock_response.status_code = 429
        mock_response.headers = {'Retry-After': '60'}
        
        linkedin_adapter.api_client = Mock()
        linkedin_adapter.api_client.get = Mock(return_value=mock_response)
        
        with pytest.raises(PlatformAdapterError, match="rate limit"):
            await linkedin_adapter.fetch_profile_data('abc123xyz')
    
    @pytest.mark.asyncio
    async def test_fetch_profile_data_tracks_requests(self, linkedin_adapter, mock_linkedin_profile):
        """Test profile fetch tracks API requests."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json = Mock(return_value=mock_linkedin_profile)
        
        linkedin_adapter.api_client = Mock()
        linkedin_adapter.api_client.get = Mock(return_value=mock_response)
        
        initial_requests = linkedin_adapter._rate_limit_status['requests_made']
        await linkedin_adapter.fetch_profile_data('abc123xyz')
        
        assert linkedin_adapter._rate_limit_status['requests_made'] == initial_requests + 1


class TestPostDataFetching:
    """Test LinkedIn post data fetching."""
    
    @pytest.mark.asyncio
    async def test_fetch_post_data_success(self, linkedin_adapter, mock_linkedin_post):
        """Test successful post data fetch."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json = Mock(return_value=mock_linkedin_post)
        
        linkedin_adapter.api_client = Mock()
        linkedin_adapter.api_client.get = Mock(return_value=mock_response)
        
        post_data = await linkedin_adapter.fetch_post_data('urn:li:share:123456789')
        
        assert post_data['post_id'] == 'urn:li:share:123456789'
        assert 'Excited to share' in post_data['text']
        assert 'fetched_at' in post_data
    
    @pytest.mark.asyncio
    async def test_fetch_post_data_not_found(self, linkedin_adapter):
        """Test post fetch handles post not found."""
        mock_response = Mock()
        mock_response.status_code = 404
        
        linkedin_adapter.api_client = Mock()
        linkedin_adapter.api_client.get = Mock(return_value=mock_response)
        
        with pytest.raises(PlatformAdapterError, match="Failed to fetch"):
            await linkedin_adapter.fetch_post_data('urn:li:share:999999999')


class TestProfessionalContentAnalysis:
    """Test LinkedIn professional content analysis."""
    
    @pytest.mark.asyncio
    async def test_check_content_professionalism_high_quality(self, linkedin_adapter):
        """Test professional content analysis for high-quality content."""
        content_data = {
            'text': 'Excited to announce our new strategy for business growth and innovation in the industry.'
        }
        
        result = await linkedin_adapter._check_content_professionalism(content_data)
        
        assert result['professionalism_score'] > 0.8
        assert result['professional_language_use'] is True
        assert result['business_relevance'] == 'high'
    
    @pytest.mark.asyncio
    async def test_check_content_professionalism_unprofessional(self, linkedin_adapter):
        """Test detection of unprofessional content."""
        content_data = {
            'text': 'OMG lol this is so amazing wtf 😂😂😂😂😂'
        }
        
        result = await linkedin_adapter._check_content_professionalism(content_data)
        
        assert result['professionalism_score'] < 0.7
        assert result['professional_language_use'] is False
        assert result['unprofessional_word_count'] > 0
        assert result['emoji_count'] > 3
    
    @pytest.mark.asyncio
    async def test_check_content_professionalism_excessive_caps(self, linkedin_adapter):
        """Test detection of excessive capitalization."""
        content_data = {
            'text': 'THIS IS SHOUTING AND UNPROFESSIONAL!!!'
        }
        
        result = await linkedin_adapter._check_content_professionalism(content_data)
        
        assert result['caps_ratio'] > 0.5
        assert result['professionalism_score'] < 0.8
    
    @pytest.mark.asyncio
    async def test_detect_spam_content_clean(self, linkedin_adapter):
        """Test spam detection on clean professional content."""
        content_data = {
            'text': 'Sharing insights on leadership and professional development.'
        }
        
        result = await linkedin_adapter._detect_spam_content(content_data)
        
        assert result['spam_score'] < 0.3
        assert result['promotional_violation'] is False
        assert len(result['spam_indicators']) == 0
    
    @pytest.mark.asyncio
    async def test_detect_spam_content_spammy(self, linkedin_adapter):
        """Test spam detection on spammy content."""
        content_data = {
            'text': 'Click here now! Limited time offer! Buy now and get rich quick! Make money fast!'
        }
        
        result = await linkedin_adapter._detect_spam_content(content_data)
        
        assert result['spam_score'] > 0.5
        assert len(result['spam_indicators']) > 0
        assert result['spam_keyword_count'] > 0
    
    @pytest.mark.asyncio
    async def test_detect_spam_content_engagement_bait(self, linkedin_adapter):
        """Test detection of engagement bait."""
        content_data = {
            'text': 'Like if you agree! Share if you support! Comment below! Tag someone!'
        }
        
        result = await linkedin_adapter._detect_spam_content(content_data)
        
        assert result['engagement_bait_count'] > 0
        assert result['spam_score'] > 0.3
    
    @pytest.mark.asyncio
    async def test_detect_spam_content_excessive_links(self, linkedin_adapter):
        """Test detection of excessive links."""
        content_data = {
            'text': 'Check out https://link1.com and https://link2.com and https://link3.com'
        }
        
        result = await linkedin_adapter._detect_spam_content(content_data)
        
        assert 'Excessive links' in str(result['spam_indicators'])
    
    @pytest.mark.asyncio
    async def test_check_recruitment_scam_content_legitimate(self, linkedin_adapter):
        """Test recruitment scam detection on legitimate job posting."""
        content_data = {
            'text': 'Hiring Senior Engineer. Requirements: 5 years experience, Bachelor degree. Full-time position with competitive salary and benefits.',
            'content_type': 'job_posting'
        }
        
        result = await linkedin_adapter._check_recruitment_scam_content(content_data)
        
        assert result['recruitment_scam_score'] < 0.3
        assert result['recruitment_legitimacy'] == 'legitimate'
        assert result['scam_content_detected'] is False
    
    @pytest.mark.asyncio
    async def test_check_recruitment_scam_content_suspicious(self, linkedin_adapter):
        """Test recruitment scam detection on suspicious posting."""
        content_data = {
            'text': 'Work from home! No experience required! Unlimited earning potential! Be your own boss! Make $$$ fast!',
            'content_type': 'job_posting'
        }
        
        result = await linkedin_adapter._check_recruitment_scam_content(content_data)
        
        assert result['recruitment_scam_score'] > 0.5
        assert result['scam_content_detected'] is True
        assert len(result['fake_job_posting_indicators']) > 0
    
    @pytest.mark.asyncio
    async def test_check_recruitment_scam_content_mlm(self, linkedin_adapter):
        """Test detection of MLM/pyramid scheme language."""
        content_data = {
            'text': 'Join our network marketing team! Multi-level marketing opportunity with unlimited income!'
        }
        
        result = await linkedin_adapter._check_recruitment_scam_content(content_data)
        
        assert result['recruitment_scam_score'] > 0.4
        assert result['scam_indicator_count'] > 0


class TestProfileAnalysis:
    """Test LinkedIn profile analysis."""
    
    @pytest.mark.asyncio
    async def test_analyze_connection_authenticity_normal(self, linkedin_adapter):
        """Test connection authenticity analysis for normal profile."""
        profile_data = {
            'connection_count': 500,
            'headline': 'Software Engineer',
            'summary': 'Experienced professional',
            'industry': 'Technology'
        }
        
        result = await linkedin_adapter._analyze_connection_authenticity(profile_data)
        
        assert result['connection_count'] == 500
        assert result['authenticity_score'] > 0.7
        assert result['fake_connection_ratio'] < 0.3
    
    @pytest.mark.asyncio
    async def test_analyze_connection_authenticity_suspicious(self, linkedin_adapter):
        """Test connection authenticity analysis for suspicious profile."""
        profile_data = {
            'connection_count': 35000,  # Unusually high
            'headline': '',
            'summary': '',
            'industry': ''
        }
        
        result = await linkedin_adapter._analyze_connection_authenticity(profile_data)
        
        assert len(result['suspicious_connection_patterns']) > 0
        assert result['fake_connection_ratio'] > 0.2
    
    @pytest.mark.asyncio
    async def test_analyze_connection_authenticity_round_number(self, linkedin_adapter):
        """Test detection of suspiciously round connection counts."""
        profile_data = {
            'connection_count': 5000,  # Suspiciously round
            'headline': 'Professional',
            'summary': 'Summary',
            'industry': 'Tech'
        }
        
        result = await linkedin_adapter._analyze_connection_authenticity(profile_data)
        
        assert 'Suspiciously round' in str(result['suspicious_connection_patterns'])
    
    @pytest.mark.asyncio
    async def test_analyze_profile_professionalism_complete(self, linkedin_adapter):
        """Test profile professionalism analysis for complete profile."""
        profile_data = {
            'first_name': 'John',
            'last_name': 'Doe',
            'headline': 'Senior Software Engineer with 10+ years of experience',
            'summary': 'Experienced professional with expertise in software development, team leadership, and project management. Over 10 years of experience building scalable systems and leading high-performing engineering teams. Passionate about mentoring junior developers and driving technical excellence.',
            'industry': 'Information Technology',
            'location': 'San Francisco, CA',
            'profile_picture_url': 'https://example.com/profile.jpg'
        }
        
        result = await linkedin_adapter._analyze_profile_professionalism(profile_data)
        
        assert result['profile_completeness'] > 0.9
        assert result['professionalism_score'] > 0.8
        assert result['headline_quality'] == 'high'
        assert result['summary_quality'] == 'high'
    
    @pytest.mark.asyncio
    async def test_analyze_profile_professionalism_incomplete(self, linkedin_adapter):
        """Test profile professionalism analysis for incomplete profile."""
        profile_data = {
            'first_name': 'John',
            'last_name': '',
            'headline': '',
            'summary': '',
            'industry': '',
            'location': '',
            'profile_picture_url': ''
        }
        
        result = await linkedin_adapter._analyze_profile_professionalism(profile_data)
        
        assert result['profile_completeness'] < 0.5
        assert result['headline_quality'] == 'low'
        assert result['summary_quality'] == 'low'


class TestRateLimitHandling:
    """Test LinkedIn API rate limit handling."""
    
    def test_get_rate_limit_status(self, linkedin_adapter):
        """Test rate limit status retrieval."""
        status = linkedin_adapter.get_rate_limit_status()
        
        assert status['enabled'] is True
        assert 'requests_made' in status
        assert 'daily_limit' in status
        assert 'hourly_limit' in status
        assert status['daily_limit'] == 500
        assert status['hourly_limit'] == 100
    
    def test_track_api_request(self, linkedin_adapter):
        """Test API request tracking."""
        initial_count = linkedin_adapter._rate_limit_status['requests_made']
        
        linkedin_adapter._track_api_request()
        
        assert linkedin_adapter._rate_limit_status['requests_made'] == initial_count + 1
    
    def test_handle_rate_limit_error(self, linkedin_adapter):
        """Test rate limit error handling."""
        mock_response = Mock()
        mock_response.status_code = 429
        mock_response.headers = {'Retry-After': '3600'}
        
        linkedin_adapter._handle_rate_limit_error(mock_response)
        
        assert linkedin_adapter._rate_limit_status['limit_reached'] is True


class TestProfileScanning:
    """Test comprehensive profile scanning."""
    
    @pytest.mark.asyncio
    async def test_scan_profile_with_identifier(self, linkedin_adapter, mock_linkedin_profile):
        """Test profile scan with just profile identifier."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json = Mock(return_value=mock_linkedin_profile)
        
        linkedin_adapter.api_client = Mock()
        linkedin_adapter.api_client.get = Mock(return_value=mock_response)
        
        result = await linkedin_adapter.scan_profile('abc123xyz')
        
        assert result['platform'] == PlatformType.LINKEDIN.value
        assert result['vanity_name'] == 'johndoe'
        assert 'risk_score' in result
        assert 'overall_risk_level' in result
        assert 'recommendations' in result
    
    @pytest.mark.asyncio
    async def test_scan_profile_with_full_data(self, linkedin_adapter):
        """Test profile scan with full profile data."""
        profile_data = {
            'profile_id': 'abc123xyz',
            'vanity_name': 'johndoe',
            'first_name': 'John',
            'connection_count': 500,
            'headline': 'Engineer',
            'summary': 'Professional',
            'industry': 'Tech'
        }
        
        result = await linkedin_adapter.scan_profile(profile_data)
        
        assert result['vanity_name'] == 'johndoe'
        assert 'risk_factors' in result
        assert 'connection_authenticity' in result['risk_factors']


class TestContentAnalysisIntegration:
    """Test integrated content analysis."""
    
    @pytest.mark.asyncio
    async def test_analyze_content_with_post_id(self, linkedin_adapter, mock_linkedin_post):
        """Test content analysis with just post ID."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json = Mock(return_value=mock_linkedin_post)
        
        linkedin_adapter.api_client = Mock()
        linkedin_adapter.api_client.get = Mock(return_value=mock_response)
        
        result = await linkedin_adapter.analyze_content('urn:li:share:123456789')
        
        assert result['platform'] == PlatformType.LINKEDIN.value
        assert result['content_type'] == 'post'
        assert 'risk_score' in result
        assert 'risk_factors' in result
    
    @pytest.mark.asyncio
    async def test_analyze_content_calculates_overall_risk(self, linkedin_adapter):
        """Test content analysis calculates overall risk score."""
        content_data = {
            'post_id': 'urn:li:share:123',
            'text': 'Professional content about business strategy',
            'content_type': 'post'
        }
        
        result = await linkedin_adapter.analyze_content(content_data)
        
        assert 'risk_score' in result
        assert isinstance(result['risk_score'], float)
        assert 0.0 <= result['risk_score'] <= 1.0
        if isinstance(result['overall_risk_level'], RiskLevel):
            assert result['overall_risk_level'] in list(RiskLevel)
        else:
            assert result['overall_risk_level'] in [level.value for level in RiskLevel]


class TestAlgorithmHealth:
    """Test algorithm health assessment."""
    
    @pytest.mark.asyncio
    async def test_get_algorithm_health(self, linkedin_adapter):
        """Test algorithm health assessment."""
        account_data = {
            'user_id': 'abc123xyz',
            'username': 'johndoe',
            'recent_posts': []
        }
        
        result = await linkedin_adapter.get_algorithm_health(account_data)
        
        assert result['platform'] == PlatformType.LINKEDIN.value
        assert 'professional_visibility_score' in result
        assert 'network_health' in result
        assert 'content_performance' in result
        assert 'recommendations' in result


class TestCrisisDetection:
    """Test crisis signal detection."""
    
    @pytest.mark.asyncio
    async def test_detect_crisis_signals(self, linkedin_adapter):
        """Test crisis signal detection."""
        monitoring_data = {
            'user_id': 'abc123xyz',
            'username': 'johndoe',
            'mentions': []
        }
        
        result = await linkedin_adapter.detect_crisis_signals(monitoring_data)
        
        assert result['platform'] == PlatformType.LINKEDIN.value
        assert 'crisis_level' in result
        assert 'crisis_indicators' in result
        assert 'recommended_actions' in result


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
