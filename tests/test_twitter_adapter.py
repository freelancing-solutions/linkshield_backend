"""
Unit tests for TwitterProtectionAdapter

Tests Twitter API v2 integration, profile data fetching, content analysis,
rate limit handling, and Twitter-specific risk assessment.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime
from typing import Dict, Any

from linkshield.social_protection.platform_adapters.twitter_adapter import (
    TwitterProtectionAdapter,
    TwitterRiskFactor
)
from linkshield.social_protection.types import PlatformType, RiskLevel
from linkshield.social_protection.exceptions import PlatformAdapterError


@pytest.fixture
def twitter_config():
    """Twitter adapter configuration for testing."""
    return {
        'bearer_token': 'test_bearer_token_12345',
        'enabled': True,
        'risk_thresholds': {
            'external_link_penalty': 0.7,
            'community_notes_trigger': 0.8,
            'fake_follower_ratio': 0.3,
            'engagement_manipulation': 0.6,
            'spam_pattern_score': 0.5,
            'shadowban_probability': 0.4
        }
    }


@pytest.fixture
def twitter_adapter(twitter_config):
    """Create TwitterProtectionAdapter instance for testing."""
    with patch('src.social_protection.platform_adapters.twitter_adapter.tweepy.Client'):
        adapter = TwitterProtectionAdapter(config=twitter_config)
        return adapter


@pytest.fixture
def mock_twitter_user():
    """Mock Twitter user data."""
    user = Mock()
    user.id = 123456789
    user.username = 'testuser'
    user.name = 'Test User'
    user.description = 'Test account for unit testing'
    user.location = 'Test City'
    user.url = 'https://example.com'
    user.profile_image_url = 'https://example.com/image.jpg'
    user.created_at = datetime(2020, 1, 1)
    user.verified = False
    user.verified_type = None
    user.protected = False
    user.public_metrics = {
        'followers_count': 1000,
        'following_count': 500,
        'tweet_count': 5000,
        'listed_count': 10
    }
    return user


@pytest.fixture
def mock_twitter_tweet():
    """Mock Twitter tweet data."""
    tweet = Mock()
    tweet.id = 987654321
    tweet.text = 'This is a test tweet with a link https://example.com'
    tweet.created_at = datetime(2024, 1, 1)
    tweet.author_id = 123456789
    tweet.lang = 'en'
    tweet.possibly_sensitive = False
    tweet.public_metrics = {
        'retweet_count': 10,
        'reply_count': 5,
        'like_count': 50,
        'quote_count': 2,
        'impression_count': 1000
    }
    tweet.entities = {
        'urls': [
            {
                'url': 'https://t.co/abc123',
                'expanded_url': 'https://example.com',
                'display_url': 'example.com'
            }
        ],
        'hashtags': [],
        'mentions': []
    }
    return tweet


class TestTwitterAdapterInitialization:
    """Test Twitter adapter initialization and configuration."""
    
    def test_adapter_initialization_with_bearer_token(self, twitter_config):
        """Test adapter initializes correctly with bearer token."""
        with patch('src.social_protection.platform_adapters.twitter_adapter.tweepy.Client') as mock_client:
            adapter = TwitterProtectionAdapter(config=twitter_config)
            
            assert adapter.platform_type == PlatformType.TWITTER
            assert adapter.is_enabled is True
            assert adapter.config == twitter_config
            mock_client.assert_called_once()
    
    def test_adapter_initialization_without_credentials(self):
        """Test adapter handles missing credentials gracefully."""
        with patch('src.social_protection.platform_adapters.twitter_adapter.tweepy.Client'):
            adapter = TwitterProtectionAdapter(config={})
            
            assert adapter.is_enabled is False
            assert adapter.client is None
    
    def test_adapter_initialization_with_oauth(self):
        """Test adapter initializes with OAuth 1.0a credentials."""
        config = {
            'api_key': 'test_key',
            'api_secret': 'test_secret',
            'access_token': 'test_token',
            'access_token_secret': 'test_token_secret'
        }
        
        with patch('src.social_protection.platform_adapters.twitter_adapter.tweepy.Client') as mock_client:
            adapter = TwitterProtectionAdapter(config=config)
            
            mock_client.assert_called_once()
            call_kwargs = mock_client.call_args[1]
            assert 'consumer_key' in call_kwargs
            assert 'consumer_secret' in call_kwargs
    
    def test_risk_thresholds_loaded(self, twitter_adapter):
        """Test risk thresholds are loaded from config."""
        assert twitter_adapter.risk_thresholds['external_link_penalty'] == 0.7
        assert twitter_adapter.risk_thresholds['community_notes_trigger'] == 0.8


class TestCredentialValidation:
    """Test Twitter API credential validation."""
    
    @pytest.mark.asyncio
    async def test_validate_credentials_success(self, twitter_adapter):
        """Test successful credential validation."""
        mock_response = Mock()
        mock_response.data = Mock(username='testuser')
        twitter_adapter.client = Mock()
        twitter_adapter.client.get_me = Mock(return_value=mock_response)
        
        result = await twitter_adapter.validate_credentials()
        
        assert result is True
        twitter_adapter.client.get_me.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_validate_credentials_no_client(self, twitter_adapter):
        """Test credential validation with no client."""
        twitter_adapter.client = None
        
        result = await twitter_adapter.validate_credentials()
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_validate_credentials_api_error(self, twitter_adapter):
        """Test credential validation handles API errors."""
        from tweepy.errors import TweepyException
        
        twitter_adapter.client = Mock()
        twitter_adapter.client.get_me = Mock(side_effect=TweepyException('Invalid credentials'))
        
        result = await twitter_adapter.validate_credentials()
        
        assert result is False


class TestProfileDataFetching:
    """Test Twitter profile data fetching."""
    
    @pytest.mark.asyncio
    async def test_fetch_profile_data_success(self, twitter_adapter, mock_twitter_user):
        """Test successful profile data fetch."""
        mock_user_response = Mock()
        mock_user_response.data = mock_twitter_user
        
        mock_tweets_response = Mock()
        mock_tweets_response.data = []
        
        twitter_adapter.client = Mock()
        twitter_adapter.client.get_user = Mock(return_value=mock_user_response)
        twitter_adapter.client.get_users_tweets = Mock(return_value=mock_tweets_response)
        
        profile_data = await twitter_adapter.fetch_profile_data('testuser')
        
        assert profile_data['username'] == 'testuser'
        assert profile_data['user_id'] == '123456789'
        assert profile_data['public_metrics']['followers_count'] == 1000
        assert 'fetched_at' in profile_data
        twitter_adapter.client.get_user.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_fetch_profile_data_no_client(self, twitter_adapter):
        """Test profile fetch fails without client."""
        twitter_adapter.client = None
        
        with pytest.raises(PlatformAdapterError, match="not initialized"):
            await twitter_adapter.fetch_profile_data('testuser')
    
    @pytest.mark.asyncio
    async def test_fetch_profile_data_user_not_found(self, twitter_adapter):
        """Test profile fetch handles user not found."""
        mock_response = Mock()
        mock_response.data = None
        
        twitter_adapter.client = Mock()
        twitter_adapter.client.get_user = Mock(return_value=mock_response)
        
        with pytest.raises(PlatformAdapterError, match="User not found"):
            await twitter_adapter.fetch_profile_data('nonexistent')
    
    @pytest.mark.asyncio
    async def test_fetch_profile_data_tracks_requests(self, twitter_adapter, mock_twitter_user):
        """Test profile fetch tracks API requests."""
        mock_user_response = Mock()
        mock_user_response.data = mock_twitter_user
        mock_tweets_response = Mock()
        mock_tweets_response.data = []
        
        twitter_adapter.client = Mock()
        twitter_adapter.client.get_user = Mock(return_value=mock_user_response)
        twitter_adapter.client.get_users_tweets = Mock(return_value=mock_tweets_response)
        
        initial_requests = twitter_adapter._rate_limit_status['requests_made']
        await twitter_adapter.fetch_profile_data('testuser')
        
        # Should track 2 requests (user + tweets)
        assert twitter_adapter._rate_limit_status['requests_made'] == initial_requests + 2


class TestTweetDataFetching:
    """Test Twitter tweet data fetching."""
    
    @pytest.mark.asyncio
    async def test_fetch_tweet_data_success(self, twitter_adapter, mock_twitter_tweet):
        """Test successful tweet data fetch."""
        mock_response = Mock()
        mock_response.data = mock_twitter_tweet
        
        twitter_adapter.client = Mock()
        twitter_adapter.client.get_tweet = Mock(return_value=mock_response)
        
        tweet_data = await twitter_adapter.fetch_tweet_data('987654321')
        
        assert tweet_data['tweet_id'] == '987654321'
        assert 'This is a test tweet' in tweet_data['text']
        assert tweet_data['public_metrics']['like_count'] == 50
        assert 'fetched_at' in tweet_data
    
    @pytest.mark.asyncio
    async def test_fetch_tweet_data_not_found(self, twitter_adapter):
        """Test tweet fetch handles tweet not found."""
        mock_response = Mock()
        mock_response.data = None
        
        twitter_adapter.client = Mock()
        twitter_adapter.client.get_tweet = Mock(return_value=mock_response)
        
        with pytest.raises(PlatformAdapterError, match="Tweet not found"):
            await twitter_adapter.fetch_tweet_data('999999999')


class TestContentAnalysis:
    """Test Twitter content analysis."""
    
    @pytest.mark.asyncio
    async def test_analyze_external_links(self, twitter_adapter):
        """Test external link analysis."""
        content_data = {
            'text': 'Check out this link',
            'entities': {
                'urls': [
                    {
                        'expanded_url': 'https://example.com',
                        'display_url': 'example.com'
                    }
                ]
            }
        }
        
        result = await twitter_adapter._analyze_external_links(content_data)
        
        assert result['external_link_count'] == 1
        assert result['penalty_risk_score'] > 0
        assert 'recommendation' in result
    
    @pytest.mark.asyncio
    async def test_analyze_external_links_multiple(self, twitter_adapter):
        """Test analysis with multiple external links."""
        content_data = {
            'text': 'Multiple links',
            'entities': {
                'urls': [
                    {'expanded_url': 'https://example1.com', 'display_url': 'example1.com'},
                    {'expanded_url': 'https://example2.com', 'display_url': 'example2.com'}
                ]
            }
        }
        
        result = await twitter_adapter._analyze_external_links(content_data)
        
        assert result['external_link_count'] == 2
        assert result['penalty_risk_score'] >= 0.5  # Higher penalty for multiple links
    
    @pytest.mark.asyncio
    async def test_analyze_external_links_penalized_domain(self, twitter_adapter):
        """Test analysis detects penalized domains."""
        content_data = {
            'text': 'Shortened link',
            'entities': {
                'urls': [
                    {'expanded_url': 'https://bit.ly/abc123', 'display_url': 'bit.ly/abc123'}
                ]
            }
        }
        
        result = await twitter_adapter._analyze_external_links(content_data)
        
        assert len(result['flagged_domains']) > 0
        assert 'bit.ly' in result['flagged_domains']
    
    @pytest.mark.asyncio
    async def test_analyze_community_notes_triggers(self, twitter_adapter):
        """Test Community Notes trigger detection."""
        content_data = {
            'text': 'BREAKING: Shocking truth they don\'t want you to know!',
            'entities': {'urls': []},
            'possibly_sensitive': False
        }
        
        result = await twitter_adapter._analyze_community_notes_triggers(content_data)
        
        assert result['trigger_probability'] > 0
        assert len(result['risk_factors']) > 0
        assert 'misleading_language' in result['content_flags']
    
    @pytest.mark.asyncio
    async def test_detect_spam_patterns(self, twitter_adapter):
        """Test spam pattern detection."""
        content_data = {
            'text': 'CLICK HERE NOW!!! BUY NOW!!! LIMITED TIME!!! #spam #spam #spam #spam #spam #spam',
            'entities': {
                'hashtags': [{'tag': 'spam'}] * 6,
                'mentions': []
            }
        }
        
        result = await twitter_adapter._detect_spam_patterns(content_data)
        
        assert result['spam_score'] > 0.5
        assert result['risk_level'] in ['medium', 'high']
        assert len(result['detected_patterns']) > 0
    
    @pytest.mark.asyncio
    async def test_detect_engagement_manipulation(self, twitter_adapter):
        """Test engagement manipulation detection."""
        content_data = {
            'text': 'Like if you agree! Retweet if you support! Follow me for more!',
            'entities': {},
            'public_metrics': {
                'retweet_count': 100,
                'like_count': 10,
                'reply_count': 0
            }
        }
        
        result = await twitter_adapter._detect_engagement_manipulation(content_data)
        
        assert result['manipulation_score'] > 0
        assert len(result['suspicious_metrics']) > 0


class TestRateLimitHandling:
    """Test Twitter API rate limit handling."""
    
    def test_get_rate_limit_status(self, twitter_adapter):
        """Test rate limit status retrieval."""
        status = twitter_adapter.get_rate_limit_status()
        
        assert status['enabled'] is True
        assert status['auto_wait_enabled'] is True
        assert 'requests_made' in status
        assert 'rate_limits' in status
    
    def test_track_api_request(self, twitter_adapter):
        """Test API request tracking."""
        initial_count = twitter_adapter._rate_limit_status['requests_made']
        
        twitter_adapter._track_api_request()
        
        assert twitter_adapter._rate_limit_status['requests_made'] == initial_count + 1
    
    def test_handle_rate_limit_error(self, twitter_adapter):
        """Test rate limit error handling."""
        from tweepy.errors import TweepyException
        
        mock_error = TweepyException('Rate limit exceeded')
        mock_response = Mock()
        mock_response.headers = {'x-rate-limit-reset': '1704067200'}
        mock_error.response = mock_response
        
        twitter_adapter._handle_rate_limit_error(mock_error)
        
        assert twitter_adapter._rate_limit_status['limit_reached'] is True
        assert 'reset_time' in twitter_adapter._rate_limit_status


class TestProfileScanning:
    """Test comprehensive profile scanning."""
    
    @pytest.mark.asyncio
    async def test_scan_profile_with_username(self, twitter_adapter, mock_twitter_user):
        """Test profile scan with just username."""
        mock_user_response = Mock()
        mock_user_response.data = mock_twitter_user
        mock_tweets_response = Mock()
        mock_tweets_response.data = []
        
        twitter_adapter.client = Mock()
        twitter_adapter.client.get_user = Mock(return_value=mock_user_response)
        twitter_adapter.client.get_users_tweets = Mock(return_value=mock_tweets_response)
        
        result = await twitter_adapter.scan_profile('testuser')
        
        assert result['platform'] == PlatformType.TWITTER.value
        assert result['username'] == 'testuser'
        assert 'risk_score' in result
        assert 'overall_risk_level' in result
        assert 'recommendations' in result
    
    @pytest.mark.asyncio
    async def test_scan_profile_with_full_data(self, twitter_adapter):
        """Test profile scan with full profile data."""
        profile_data = {
            'user_id': '123456789',
            'username': 'testuser',
            'public_metrics': {
                'followers_count': 1000,
                'following_count': 500
            }
        }
        
        result = await twitter_adapter.scan_profile(profile_data)
        
        assert result['username'] == 'testuser'
        assert 'risk_factors' in result


class TestContentAnalysisIntegration:
    """Test integrated content analysis."""
    
    @pytest.mark.asyncio
    async def test_analyze_content_with_tweet_id(self, twitter_adapter, mock_twitter_tweet):
        """Test content analysis with just tweet ID."""
        mock_response = Mock()
        mock_response.data = mock_twitter_tweet
        
        twitter_adapter.client = Mock()
        twitter_adapter.client.get_tweet = Mock(return_value=mock_response)
        
        result = await twitter_adapter.analyze_content('987654321')
        
        assert result['platform'] == PlatformType.TWITTER.value
        assert result['content_type'] == 'tweet'
        assert 'risk_score' in result
        assert 'risk_factors' in result
    
    @pytest.mark.asyncio
    async def test_analyze_content_calculates_overall_risk(self, twitter_adapter):
        """Test content analysis calculates overall risk score."""
        content_data = {
            'tweet_id': '123',
            'text': 'Test tweet',
            'entities': {'urls': [], 'hashtags': [], 'mentions': []},
            'public_metrics': {}
        }
        
        result = await twitter_adapter.analyze_content(content_data)
        
        assert 'risk_score' in result
        assert isinstance(result['risk_score'], float)
        assert 0.0 <= result['risk_score'] <= 1.0
        # Check if it's a RiskLevel enum or its string value
        if isinstance(result['overall_risk_level'], RiskLevel):
            assert result['overall_risk_level'] in list(RiskLevel)
        else:
            assert result['overall_risk_level'] in [level.value for level in RiskLevel]


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
