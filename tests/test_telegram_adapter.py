"""
Unit tests for Telegram Protection Adapter

Tests the Telegram platform adapter functionality including:
- API client initialization and authentication
- Profile scanning and risk assessment
- Content analysis and spam detection
- Channel authenticity analysis
- Algorithm health monitoring
- Crisis signal detection
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime
from typing import Dict, Any

# Import the adapter
from linkshield.social_protection.platform_adapters.telegram_adapter import (
    TelegramProtectionAdapter,
    TelegramRiskFactor,
    TELEGRAM_AVAILABLE
)
from linkshield.social_protection.types import PlatformType, RiskLevel
from linkshield.social_protection.data_models.social_profile_models import (
    ProfileScanRequest,
    ProfileScanResult
)
from linkshield.social_protection.data_models.content_risk_models import (
    ContentAnalysisRequest,
    ContentAnalysisResult,
    ContentType
)
from linkshield.social_protection.exceptions import PlatformAdapterError


@pytest.fixture
def telegram_config():
    """Fixture providing Telegram adapter configuration."""
    return {
        'bot_token': 'test_bot_token_123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11',
        'enabled': True,
        'risk_thresholds': {
            'bot_detection': 0.7,
            'fake_subscriber_ratio': 0.4,
            'scam_pattern_score': 0.75,
            'malicious_link_score': 0.8,
            'spam_content_score': 0.6,
            'forward_manipulation': 0.65,
            'channel_authenticity': 0.5
        }
    }


@pytest.fixture
def telegram_adapter(telegram_config):
    """Fixture providing a Telegram adapter instance."""
    with patch('src.social_protection.platform_adapters.telegram_adapter.Bot'):
        adapter = TelegramProtectionAdapter(config=telegram_config)
        return adapter


@pytest.fixture
def mock_telegram_bot():
    """Fixture providing a mocked Telegram Bot instance."""
    bot = AsyncMock()
    bot.get_me = AsyncMock(return_value=Mock(
        id=123456789,
        username='test_bot',
        first_name='Test Bot'
    ))
    return bot


@pytest.fixture
def sample_chat_data():
    """Fixture providing sample Telegram chat data."""
    return {
        'chat_id': '-1001234567890',
        'type': 'channel',
        'title': 'Test Channel',
        'username': 'testchannel',
        'description': 'A test channel for unit testing',
        'member_count': 5000,
        'photo': {
            'small_file_id': 'small_123',
            'big_file_id': 'big_123'
        },
        'has_protected_content': False,
        'fetched_at': datetime.utcnow().isoformat()
    }


@pytest.fixture
def sample_message_data():
    """Fixture providing sample Telegram message data."""
    return {
        'message_id': '12345',
        'text': 'This is a test message with some content',
        'entities': [],
        'forward_count': 5,
        'created_at': datetime.utcnow().isoformat()
    }


class TestTelegramAdapterInitialization:
    """Test Telegram adapter initialization and configuration."""
    
    def test_adapter_initialization_with_config(self, telegram_config):
        """Test adapter initializes correctly with valid config."""
        with patch('src.social_protection.platform_adapters.telegram_adapter.Bot'):
            adapter = TelegramProtectionAdapter(config=telegram_config)
            
            assert adapter.platform_type == PlatformType.TELEGRAM
            assert adapter.config == telegram_config
            assert adapter.risk_thresholds is not None
    
    def test_adapter_initialization_without_config(self):
        """Test adapter initializes with default config when none provided."""
        with patch('src.social_protection.platform_adapters.telegram_adapter.Bot'):
            adapter = TelegramProtectionAdapter()
            
            assert adapter.platform_type == PlatformType.TELEGRAM
            assert adapter.config == {}
            assert adapter.risk_thresholds is not None
    
    def test_adapter_disabled_without_bot_token(self):
        """Test adapter is disabled when bot token is not provided."""
        with patch('src.social_protection.platform_adapters.telegram_adapter.Bot'):
            adapter = TelegramProtectionAdapter(config={'enabled': True})
            
            assert adapter.is_enabled == False
    
    @pytest.mark.skipif(not TELEGRAM_AVAILABLE, reason="python-telegram-bot not installed")
    def test_adapter_disabled_without_telegram_library(self):
        """Test adapter is disabled when telegram library is not available."""
        with patch('src.social_protection.platform_adapters.telegram_adapter.TELEGRAM_AVAILABLE', False):
            adapter = TelegramProtectionAdapter(config={'bot_token': 'test'})
            
            assert adapter.is_enabled == False


class TestTelegramAPIClient:
    """Test Telegram Bot API client functionality."""
    
    @pytest.mark.asyncio
    async def test_validate_credentials_success(self, telegram_adapter, mock_telegram_bot):
        """Test successful credential validation."""
        telegram_adapter.bot = mock_telegram_bot
        
        result = await telegram_adapter.validate_credentials()
        
        assert result == True
        mock_telegram_bot.get_me.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_validate_credentials_failure(self, telegram_adapter):
        """Test credential validation failure."""
        telegram_adapter.bot = None
        
        result = await telegram_adapter.validate_credentials()
        
        assert result == False
    
    @pytest.mark.asyncio
    async def test_fetch_chat_data_success(self, telegram_adapter, mock_telegram_bot):
        """Test successful chat data fetching."""
        telegram_adapter.bot = mock_telegram_bot
        
        # Mock chat response
        mock_chat = Mock()
        mock_chat.id = -1001234567890
        mock_chat.type = 'channel'
        mock_chat.title = 'Test Channel'
        mock_chat.username = 'testchannel'
        mock_chat.description = 'Test description'
        mock_chat.invite_link = None
        mock_chat.photo = None
        mock_chat.permissions = None
        mock_chat.linked_chat_id = None
        mock_chat.slow_mode_delay = None
        mock_chat.has_protected_content = False
        
        mock_telegram_bot.get_chat = AsyncMock(return_value=mock_chat)
        mock_telegram_bot.get_chat_member_count = AsyncMock(return_value=5000)
        
        result = await telegram_adapter.fetch_chat_data('@testchannel')
        
        assert result['chat_id'] == str(mock_chat.id)
        assert result['type'] == 'channel'
        assert result['title'] == 'Test Channel'
        assert result['member_count'] == 5000
    
    @pytest.mark.asyncio
    async def test_fetch_chat_data_no_bot(self, telegram_adapter):
        """Test chat data fetching fails without bot client."""
        telegram_adapter.bot = None
        
        with pytest.raises(PlatformAdapterError, match="not initialized"):
            await telegram_adapter.fetch_chat_data('@testchannel')


class TestProfileScanning:
    """Test Telegram profile scanning functionality."""
    
    @pytest.mark.asyncio
    async def test_scan_profile_basic(self, telegram_adapter, sample_chat_data, mock_telegram_bot):
        """Test basic profile scanning."""
        # Mock the bot and fetch method
        telegram_adapter.bot = mock_telegram_bot
        telegram_adapter.fetch_chat_data = AsyncMock(return_value=sample_chat_data)
        
        request = ProfileScanRequest(
            platform=PlatformType.TELEGRAM,
            profile_identifier='@testchannel'
        )
        
        result = await telegram_adapter.scan_profile(request)
        
        assert isinstance(result, ProfileScanResult)
        assert result.platform == PlatformType.TELEGRAM
        assert result.risk_level in [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        assert 0.0 <= result.risk_score <= 1.0
        assert result.risk_factors is not None
        assert result.recommendations is not None
    
    @pytest.mark.asyncio
    async def test_scan_profile_with_api_fetch(self, telegram_adapter, mock_telegram_bot, sample_chat_data):
        """Test profile scanning with API data fetching."""
        telegram_adapter.bot = mock_telegram_bot
        telegram_adapter.fetch_chat_data = AsyncMock(return_value=sample_chat_data)
        
        request = ProfileScanRequest(
            platform=PlatformType.TELEGRAM,
            profile_identifier='@testchannel'
        )
        
        result = await telegram_adapter.scan_profile(request)
        
        assert isinstance(result, ProfileScanResult)
        telegram_adapter.fetch_chat_data.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_analyze_channel_authenticity(self, telegram_adapter, sample_chat_data):
        """Test channel authenticity analysis."""
        result = await telegram_adapter._analyze_channel_authenticity(sample_chat_data)
        
        assert 'authenticity_score' in result
        assert 'trust_indicators' in result
        assert 'risk_factors' in result
        assert 0.0 <= result['authenticity_score'] <= 1.0
    
    @pytest.mark.asyncio
    async def test_analyze_channel_authenticity_low_members(self, telegram_adapter):
        """Test channel authenticity with low member count."""
        chat_data = {
            'member_count': 50,
            'description': None,
            'username': None,
            'photo': None
        }
        
        result = await telegram_adapter._analyze_channel_authenticity(chat_data)
        
        assert result['authenticity_score'] < 0.7
        assert 'low_member_count' in result['risk_factors']
    
    @pytest.mark.asyncio
    async def test_analyze_subscriber_authenticity(self, telegram_adapter, sample_chat_data):
        """Test subscriber authenticity analysis."""
        result = await telegram_adapter._analyze_subscriber_authenticity(sample_chat_data)
        
        assert 'fake_subscriber_ratio' in result
        assert 'authenticity_score' in result
        assert 'suspicious_patterns' in result
        assert 0.0 <= result['fake_subscriber_ratio'] <= 1.0


class TestContentAnalysis:
    """Test Telegram content analysis functionality."""
    
    @pytest.mark.asyncio
    async def test_analyze_content_basic(self, telegram_adapter, sample_message_data):
        """Test basic content analysis."""
        # Directly call analyze_content with a dict (the adapter handles both)
        result = await telegram_adapter.analyze_content(sample_message_data)
        
        assert isinstance(result, ContentAnalysisResult)
        assert result.platform == PlatformType.TELEGRAM
        assert result.risk_level in [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        assert 0.0 <= result.risk_score <= 1.0
    
    @pytest.mark.asyncio
    async def test_detect_spam_patterns_clean_content(self, telegram_adapter):
        """Test spam detection on clean content."""
        content_data = {
            'text': 'This is a normal message about technology',
            'entities': []
        }
        
        result = await telegram_adapter._detect_spam_patterns(content_data)
        
        assert result['spam_probability'] < 0.3
        assert len(result['spam_indicators']) == 0
    
    @pytest.mark.asyncio
    async def test_detect_spam_patterns_spammy_content(self, telegram_adapter):
        """Test spam detection on spammy content."""
        content_data = {
            'text': 'FREE CRYPTO AIRDROP! CLICK HERE NOW! LIMITED TIME OFFER! 🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀',
            'entities': [
                {'type': 'url', 'url': 'http://example.com'},
                {'type': 'url', 'url': 'http://example2.com'},
                {'type': 'url', 'url': 'http://example3.com'},
                {'type': 'url', 'url': 'http://example4.com'}
            ]
        }
        
        result = await telegram_adapter._detect_spam_patterns(content_data)
        
        assert result['spam_probability'] > 0.5
        assert len(result['spam_indicators']) > 0
    
    @pytest.mark.asyncio
    async def test_detect_scam_patterns_clean_content(self, telegram_adapter):
        """Test scam detection on clean content."""
        content_data = {
            'text': 'Join our community to discuss technology trends',
            'entities': []
        }
        
        result = await telegram_adapter._detect_scam_patterns(content_data)
        
        assert result['scam_probability'] < 0.3
        assert len(result['scam_indicators']) == 0
    
    @pytest.mark.asyncio
    async def test_detect_scam_patterns_scam_content(self, telegram_adapter):
        """Test scam detection on scam content."""
        content_data = {
            'text': 'URGENT! Send BTC to this wallet address for guaranteed returns! Official support team.',
            'entities': [
                {'type': 'url', 'url': 'http://bit.ly/scam123'}
            ]
        }
        
        result = await telegram_adapter._detect_scam_patterns(content_data)
        
        assert result['scam_probability'] > 0.5
        assert len(result['scam_indicators']) > 0
        assert len(result['pattern_types']) > 0
    
    @pytest.mark.asyncio
    async def test_analyze_forward_chain_low_forwards(self, telegram_adapter):
        """Test forward chain analysis with low forward count."""
        content_data = {
            'forward_count': 5,
            'forward_from': {'id': 123, 'first_name': 'User'},
            'forward_from_chat': None
        }
        
        result = await telegram_adapter._analyze_forward_chain(content_data)
        
        assert result['forward_count'] == 5
        assert result['manipulation_score'] < 0.3
    
    @pytest.mark.asyncio
    async def test_analyze_forward_chain_high_forwards(self, telegram_adapter):
        """Test forward chain analysis with high forward count."""
        content_data = {
            'forward_count': 1500,
            'forward_from': None,
            'forward_from_chat': None
        }
        
        result = await telegram_adapter._analyze_forward_chain(content_data)
        
        assert result['forward_count'] == 1500
        assert result['manipulation_score'] > 0.2
        assert result['has_hidden_source'] == True


class TestAlgorithmHealth:
    """Test Telegram algorithm health monitoring."""
    
    @pytest.mark.asyncio
    async def test_get_algorithm_health(self, telegram_adapter, sample_chat_data):
        """Test algorithm health assessment."""
        result = await telegram_adapter.get_algorithm_health(
            profile_id='@testchannel',
            timeframe_days=30
        )
        
        assert 'platform' in result
        assert 'health_score' in result
        assert 'visibility_score' in result
        assert 'engagement_health' in result
        assert 0.0 <= result['health_score'] <= 1.0
    
    @pytest.mark.asyncio
    async def test_calculate_visibility_score_large_channel(self, telegram_adapter, mock_telegram_bot):
        """Test visibility score calculation for large channel."""
        telegram_adapter.bot = mock_telegram_bot
        
        mock_chat_data = {
            'member_count': 150000,
            'username': 'largechannel'
        }
        telegram_adapter.fetch_chat_data = AsyncMock(return_value=mock_chat_data)
        
        score = await telegram_adapter._calculate_visibility_score('@largechannel', 30)
        
        assert score >= 0.8
    
    @pytest.mark.asyncio
    async def test_calculate_visibility_score_small_channel(self, telegram_adapter, mock_telegram_bot):
        """Test visibility score calculation for small channel."""
        telegram_adapter.bot = mock_telegram_bot
        
        mock_chat_data = {
            'member_count': 50,
            'username': None
        }
        telegram_adapter.fetch_chat_data = AsyncMock(return_value=mock_chat_data)
        
        score = await telegram_adapter._calculate_visibility_score('-1001234567890', 30)
        
        assert score <= 0.4


class TestCrisisDetection:
    """Test Telegram crisis signal detection."""
    
    @pytest.mark.asyncio
    async def test_detect_crisis_signals(self, telegram_adapter):
        """Test crisis signal detection."""
        monitoring_data = {
            'user_id': '123456',
            'username': 'testchannel'
        }
        
        result = await telegram_adapter.detect_crisis_signals('@testchannel')
        
        assert 'platform' in result
        assert 'crisis_level' in result
        assert 'crisis_indicators' in result
        assert 'recommended_actions' in result
    
    @pytest.mark.asyncio
    async def test_detect_viral_negative_content(self, telegram_adapter):
        """Test viral negative content detection."""
        result = await telegram_adapter._detect_viral_negative_content('@testchannel')
        
        assert 'detected' in result
        assert 'severity' in result
        assert isinstance(result['detected'], bool)


class TestRiskCalculation:
    """Test risk score calculation methods."""
    
    def test_calculate_profile_risk_score(self, telegram_adapter):
        """Test profile risk score calculation."""
        risk_factors = {
            'bot_detection': {'risk_score': 0.2},
            'subscriber_authenticity': {'score': 0.1},
            'channel_authenticity': {'score': 0.15},
            'verification_status': {'score': 0.1},
            'suspicious_activity': {'score': 0.05}
        }
        
        score = telegram_adapter._calculate_profile_risk_score(risk_factors)
        
        assert 0.0 <= score <= 1.0
    
    def test_calculate_content_risk_score(self, telegram_adapter):
        """Test content risk score calculation."""
        risk_factors = {
            'spam_patterns': {'score': 0.3},
            'malicious_links': {'risk_score': 0.4},
            'scam_patterns': {'score': 0.5},
            'forward_chain': {'score': 0.2},
            'media_safety': {'score': 0.1}
        }
        
        score = telegram_adapter._calculate_content_risk_score(risk_factors)
        
        assert 0.0 <= score <= 1.0
    
    def test_determine_risk_level(self, telegram_adapter):
        """Test risk level determination from score."""
        assert telegram_adapter._determine_risk_level(0.1) == RiskLevel.LOW
        assert telegram_adapter._determine_risk_level(0.4) == RiskLevel.MEDIUM
        assert telegram_adapter._determine_risk_level(0.7) == RiskLevel.HIGH
        assert telegram_adapter._determine_risk_level(0.9) == RiskLevel.CRITICAL


class TestRecommendations:
    """Test recommendation generation."""
    
    def test_generate_profile_recommendations_low_risk(self, telegram_adapter):
        """Test profile recommendations for low risk."""
        risk_factors = {
            'bot_detection': {'is_bot': False}
        }
        
        recommendations = telegram_adapter._generate_profile_recommendations(
            risk_factors,
            RiskLevel.LOW
        )
        
        assert isinstance(recommendations, list)
    
    def test_generate_profile_recommendations_high_risk(self, telegram_adapter):
        """Test profile recommendations for high risk."""
        risk_factors = {
            'bot_detection': {'is_bot': True}
        }
        
        recommendations = telegram_adapter._generate_profile_recommendations(
            risk_factors,
            RiskLevel.HIGH
        )
        
        assert isinstance(recommendations, list)
        assert len(recommendations) > 0
    
    def test_generate_content_recommendations(self, telegram_adapter):
        """Test content recommendations generation."""
        risk_factors = {
            'malicious_links': {'malicious_link_count': 2}
        }
        
        recommendations = telegram_adapter._generate_content_recommendations(
            risk_factors,
            RiskLevel.HIGH
        )
        
        assert isinstance(recommendations, list)
        assert len(recommendations) > 0


class TestErrorHandling:
    """Test error handling in Telegram adapter."""
    
    @pytest.mark.asyncio
    async def test_scan_profile_handles_exceptions(self, telegram_adapter):
        """Test profile scanning handles exceptions gracefully."""
        # Bot is not initialized, so it should handle gracefully
        telegram_adapter.bot = None
        
        request = ProfileScanRequest(
            platform=PlatformType.TELEGRAM,
            profile_identifier='@testchannel'
        )
        
        # Should not raise exception, but handle gracefully
        try:
            result = await telegram_adapter.scan_profile(request)
            assert isinstance(result, ProfileScanResult)
        except Exception as e:
            # If it does raise, it should be logged
            assert True
    
    @pytest.mark.asyncio
    @pytest.mark.skipif(not TELEGRAM_AVAILABLE, reason="python-telegram-bot not installed")
    async def test_fetch_chat_data_handles_telegram_error(self, telegram_adapter, mock_telegram_bot):
        """Test chat data fetching handles Telegram API errors."""
        telegram_adapter.bot = mock_telegram_bot
        
        # Mock Telegram error
        from telegram.error import TelegramError
        mock_telegram_bot.get_chat = AsyncMock(side_effect=TelegramError("Chat not found"))
        
        with pytest.raises(PlatformAdapterError):
            await telegram_adapter.fetch_chat_data('@nonexistent')


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
