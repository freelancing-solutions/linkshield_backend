"""
Unit tests for Discord Protection Adapter

Tests Discord-specific social media protection functionality including:
- API client initialization and authentication
- Server security analysis
- Member behavior analysis
- Bot detection
- Raid detection
- Content analysis
- Crisis detection
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timedelta
from typing import Dict, Any

# Import the adapter
from src.social_protection.platform_adapters.discord_adapter import (
    DiscordProtectionAdapter,
    DiscordRiskFactor
)
from src.social_protection.types import PlatformType, RiskLevel
from src.social_protection.data_models import (
    ProfileScanRequest,
    ContentAnalysisRequest,
    ContentType
)
from src.social_protection.exceptions import PlatformAdapterError


@pytest.fixture
def discord_config():
    """Fixture for Discord adapter configuration."""
    return {
        'bot_token': 'test_bot_token_12345',
        'enabled': True,
        'risk_thresholds': {
            'raid_detection': 0.8,
            'fake_account_ratio': 0.3,
            'malicious_bot_score': 0.75,
            'spam_content_score': 0.6,
            'harassment_score': 0.7,
            'phishing_score': 0.85,
            'server_security': 0.5,
            'nsfw_violation': 0.9,
            'doxxing_threat': 0.95
        }
    }


@pytest.fixture
def discord_adapter(discord_config):
    """Fixture for Discord adapter instance."""
    with patch('src.social_protection.platform_adapters.discord_adapter.DISCORD_AVAILABLE', True):
        with patch('src.social_protection.platform_adapters.discord_adapter.Client'):
            adapter = DiscordProtectionAdapter(discord_config)
            return adapter


@pytest.fixture
def mock_guild_data():
    """Fixture for mock Discord guild data."""
    return {
        'guild_id': '123456789',
        'name': 'Test Server',
        'description': 'A test Discord server',
        'icon_url': 'https://cdn.discordapp.com/icons/123/abc.png',
        'owner_id': '987654321',
        'verification_level': 3,  # High
        'explicit_content_filter': 2,  # All members
        'mfa_level': 1,  # Required
        'features': ['COMMUNITY', 'VERIFIED', 'MEMBER_VERIFICATION_GATE'],
        'member_count': 5000,
        'premium_tier': 2,
        'premium_subscription_count': 15,
        'nsfw_level': 0,
        'channels_count': 25,
        'roles_count': 15,
        'emojis_count': 50,
        'created_at': (datetime.utcnow() - timedelta(days=365)).isoformat()
    }


@pytest.fixture
def mock_member_data():
    """Fixture for mock Discord member data."""
    return {
        'user_id': '111222333',
        'username': 'testuser',
        'discriminator': '1234',
        'global_name': 'Test User',
        'display_name': 'Test User',
        'is_bot': False,
        'avatar_url': 'https://cdn.discordapp.com/avatars/111/xyz.png',
        'joined_at': (datetime.utcnow() - timedelta(days=180)).isoformat(),
        'created_at': (datetime.utcnow() - timedelta(days=730)).isoformat(),
        'roles': [
            {'id': '1', 'name': '@everyone', 'position': 0},
            {'id': '2', 'name': 'Member', 'position': 1},
            {'id': '3', 'name': 'Active', 'position': 2}
        ],
        'premium_since': None,
        'pending': False,
        'timed_out_until': None
    }


@pytest.fixture
def mock_message_data():
    """Fixture for mock Discord message data."""
    return {
        'message_id': '999888777',
        'channel_id': '555666777',
        'guild_id': '123456789',
        'author_id': '111222333',
        'author_name': 'testuser',
        'author_is_bot': False,
        'content': 'This is a test message',
        'clean_content': 'This is a test message',
        'created_at': datetime.utcnow().isoformat(),
        'is_pinned': False,
        'mentions': [],
        'mention_everyone': False,
        'attachments': [],
        'embeds': [],
        'reactions': []
    }


class TestDiscordAdapterInitialization:
    """Test Discord adapter initialization and configuration."""
    
    def test_adapter_initialization(self, discord_config):
        """Test basic adapter initialization."""
        with patch('src.social_protection.platform_adapters.discord_adapter.DISCORD_AVAILABLE', True):
            with patch('src.social_protection.platform_adapters.discord_adapter.Client'):
                adapter = DiscordProtectionAdapter(discord_config)
                
                assert adapter.platform_type == PlatformType.DISCORD
                assert adapter.config == discord_config
                assert adapter.risk_thresholds == discord_config['risk_thresholds']
    
    def test_adapter_initialization_without_discord_library(self, discord_config):
        """Test adapter initialization when discord.py is not available."""
        with patch('src.social_protection.platform_adapters.discord_adapter.DISCORD_AVAILABLE', False):
            adapter = DiscordProtectionAdapter(discord_config)
            
            assert adapter.is_enabled is False
            assert adapter.client is None
    
    def test_adapter_initialization_without_token(self):
        """Test adapter initialization without bot token."""
        config = {'enabled': True}
        
        with patch('src.social_protection.platform_adapters.discord_adapter.DISCORD_AVAILABLE', True):
            with patch('src.social_protection.platform_adapters.discord_adapter.Client'):
                adapter = DiscordProtectionAdapter(config)
                
                assert adapter.is_enabled is False


class TestDiscordServerAnalysis:
    """Test Discord server security analysis."""
    
    @pytest.mark.asyncio
    async def test_analyze_server_security_high_security(self, discord_adapter, mock_guild_data):
        """Test server security analysis for well-configured server."""
        result = await discord_adapter._analyze_server_security(mock_guild_data)
        
        assert result['security_score'] >= 0.8
        assert result['verification_level'] == 3
        assert result['mfa_required'] is True
        assert 'high_verification_level' in result['security_features']
        assert 'strict_content_filter' in result['security_features']
        assert 'mfa_required' in result['security_features']
    
    @pytest.mark.asyncio
    async def test_analyze_server_security_low_security(self, discord_adapter):
        """Test server security analysis for poorly configured server."""
        insecure_guild_data = {
            'verification_level': 0,  # None
            'explicit_content_filter': 0,  # Disabled
            'mfa_level': 0,  # Not required
            'features': [],
            'member_count': 15000,  # Large server
            'nsfw_level': 1
        }
        
        result = await discord_adapter._analyze_server_security(insecure_guild_data)
        
        assert result['security_score'] <= 0.5
        assert 'low_verification_level' in result['security_issues']
        assert 'no_content_filter' in result['security_issues']
        assert 'mfa_not_required' in result['security_issues']
        assert 'large_server_low_verification' in result['security_issues']


class TestDiscordMemberAnalysis:
    """Test Discord member behavior analysis."""
    
    @pytest.mark.asyncio
    async def test_analyze_member_behavior_trusted_member(self, discord_adapter, mock_member_data):
        """Test member analysis for trusted, established member."""
        result = await discord_adapter._analyze_member_behavior(mock_member_data)
        
        assert result['behavior_score'] >= 0.7
        assert 'established_account' in result['activity_patterns']
        assert result['role_count'] == 2  # Excluding @everyone
    
    @pytest.mark.asyncio
    async def test_analyze_member_behavior_new_account(self, discord_adapter):
        """Test member analysis for very new account."""
        new_member_data = {
            'created_at': (datetime.utcnow() - timedelta(days=3)).isoformat(),
            'joined_at': datetime.utcnow().isoformat(),
            'roles': [{'id': '1', 'name': '@everyone', 'position': 0}],
            'premium_since': None,
            'timed_out_until': None,
            'pending': False
        }
        
        result = await discord_adapter._analyze_member_behavior(new_member_data)
        
        assert result['behavior_score'] < 0.7
        assert 'very_new_account' in result['risk_indicators']
        assert 'just_joined' in result['risk_indicators']
    
    @pytest.mark.asyncio
    async def test_analyze_member_behavior_timed_out_member(self, discord_adapter, mock_member_data):
        """Test member analysis for timed out (muted) member."""
        mock_member_data['timed_out_until'] = (datetime.utcnow() + timedelta(hours=24)).isoformat()
        
        result = await discord_adapter._analyze_member_behavior(mock_member_data)
        
        assert result['behavior_score'] < 0.7
        assert 'currently_timed_out' in result['risk_indicators']
        assert result['is_timed_out'] is True


class TestDiscordBotDetection:
    """Test Discord bot detection and analysis."""
    
    @pytest.mark.asyncio
    async def test_analyze_verified_bot(self, discord_adapter):
        """Test analysis of verified bot account."""
        bot_data = {
            'is_bot': True,
            'is_verified': True,
            'username': 'VerifiedBot',
            'permissions': ['read_messages', 'send_messages']
        }
        
        result = await discord_adapter._analyze_bot_detection(bot_data)
        
        assert result['is_bot'] is True
        assert result['is_verified_bot'] is True
        assert result['bot_risk_score'] < 0.3
        assert 'verified_bot' in result['bot_indicators']
    
    @pytest.mark.asyncio
    async def test_analyze_unverified_bot_dangerous_permissions(self, discord_adapter):
        """Test analysis of unverified bot with dangerous permissions."""
        bot_data = {
            'is_bot': True,
            'is_verified': False,
            'username': 'SuspiciousBot',
            'permissions': ['administrator', 'manage_guild', 'ban_members']
        }
        
        result = await discord_adapter._analyze_bot_detection(bot_data)
        
        assert result['is_bot'] is True
        assert result['is_verified_bot'] is False
        assert result['bot_risk_score'] >= 0.7
        assert 'unverified_bot_with_dangerous_permissions' in result['bot_indicators']
        assert result['has_dangerous_permissions'] is True
    
    @pytest.mark.asyncio
    async def test_analyze_bot_like_username(self, discord_adapter):
        """Test detection of bot-like username patterns."""
        user_data = {
            'is_bot': False,
            'username': 'AutoBot123',
            'permissions': []
        }
        
        result = await discord_adapter._analyze_bot_detection(user_data)
        
        assert result['is_bot'] is False
        assert 'bot_like_username' in result['bot_indicators']
        assert result['bot_risk_score'] > 0


class TestDiscordRaidDetection:
    """Test Discord raid detection."""
    
    @pytest.mark.asyncio
    async def test_detect_raid_vulnerable_server(self, discord_adapter):
        """Test raid detection for vulnerable server configuration."""
        # Mock the client to be available
        discord_adapter.client = Mock()
        
        with patch.object(discord_adapter, 'fetch_guild_data', new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = {
                'member_count': 5000,
                'verification_level': 0,  # None
                'features': [],  # No verification gate
                'mfa_level': 0
            }
            
            result = await discord_adapter._detect_raid_attacks('123456789')
            
            assert result['severity_score'] >= 0.3
            assert 'low_verification_large_server' in result['raid_indicators']
            assert 'no_verification_gate' in result['raid_indicators']
            assert len(result['recommendations']) > 0
    
    @pytest.mark.asyncio
    async def test_detect_raid_protected_server(self, discord_adapter, mock_guild_data):
        """Test raid detection for well-protected server."""
        with patch.object(discord_adapter, 'fetch_guild_data', new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = mock_guild_data
            
            result = await discord_adapter._detect_raid_attacks('123456789')
            
            assert result['severity_score'] < 0.5
            assert result['detected'] is False
            assert result['severity'] == 'low'


class TestDiscordServerDisruption:
    """Test Discord server disruption detection."""
    
    @pytest.mark.asyncio
    async def test_detect_server_disruption_channel_spam(self, discord_adapter):
        """Test detection of channel spam disruption."""
        # Mock the client to be available
        discord_adapter.client = Mock()
        
        with patch.object(discord_adapter, 'fetch_guild_data', new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = {
                'channels_count': 150,
                'member_count': 50,
                'roles_count': 20,
                'emojis_count': 30,
                'mfa_level': 0
            }
            
            result = await discord_adapter._detect_server_disruption('123456789')
            
            assert result['disruption_score'] == 0.3
            assert 'excessive_channels' in result['disruption_types']
            # Detection threshold is 0.4, so this should not be detected
            assert result['detected'] is False
    
    @pytest.mark.asyncio
    async def test_detect_server_disruption_role_spam(self, discord_adapter):
        """Test detection of role spam disruption."""
        # Mock the client to be available
        discord_adapter.client = Mock()
        
        with patch.object(discord_adapter, 'fetch_guild_data', new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = {
                'channels_count': 25,
                'member_count': 1000,
                'roles_count': 150,
                'emojis_count': 50,
                'mfa_level': 1
            }
            
            result = await discord_adapter._detect_server_disruption('123456789')
            
            assert 'excessive_roles' in result['disruption_types']
            # Check if mitigation is needed based on detection
            assert result['mitigation_needed'] == result['detected']


class TestDiscordProfileScan:
    """Test Discord profile scanning."""
    
    @pytest.mark.asyncio
    async def test_scan_guild_profile(self, discord_adapter, mock_guild_data):
        """Test scanning a Discord guild profile."""
        with patch.object(discord_adapter, 'fetch_guild_data', new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = mock_guild_data
            
            request = ProfileScanRequest(
                platform=PlatformType.DISCORD,
                profile_identifier='123456789',
                profile_data={'entity_type': 'server'}
            )
            
            result = await discord_adapter.scan_profile(request)
            
            assert result.platform == PlatformType.DISCORD
            assert result.risk_level in [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
            assert 0.0 <= result.risk_score <= 1.0
            assert len(result.recommendations) > 0
    
    @pytest.mark.asyncio
    async def test_scan_member_profile(self, discord_adapter, mock_member_data):
        """Test scanning a Discord member profile."""
        with patch.object(discord_adapter, 'fetch_member_data', new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = mock_member_data
            
            request = ProfileScanRequest(
                platform=PlatformType.DISCORD,
                profile_identifier='111222333',
                profile_data={'guild_id': '123456789'}
            )
            
            result = await discord_adapter.scan_profile(request)
            
            assert result.platform == PlatformType.DISCORD
            assert result.risk_level in [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
            assert 0.0 <= result.confidence_score <= 1.0


class TestDiscordContentAnalysis:
    """Test Discord content analysis."""
    
    @pytest.mark.asyncio
    async def test_analyze_safe_content(self, discord_adapter, mock_message_data):
        """Test analysis of safe Discord content."""
        request = ContentAnalysisRequest(
            platform=PlatformType.DISCORD,
            content_identifier='999888777',
            analysis_options={'content_data': mock_message_data}
        )
        
        result = await discord_adapter.analyze_content(request)
        
        assert result.platform == PlatformType.DISCORD
        assert result.risk_level == RiskLevel.LOW
        assert result.risk_score < 0.3
    
    @pytest.mark.asyncio
    async def test_analyze_spam_content(self, discord_adapter):
        """Test analysis of spam content."""
        spam_message = {
            'message_id': '999888777',
            'content': 'FREE CRYPTO AIRDROP! CLICK HERE NOW! LIMITED TIME! 🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀',
            'entities': [{'type': 'url'}, {'type': 'url'}, {'type': 'url'}, {'type': 'url'}],
            'forward_count': 150
        }
        
        request = ContentAnalysisRequest(
            platform=PlatformType.DISCORD,
            content_identifier='999888777',
            analysis_options={'content_data': spam_message}
        )
        
        result = await discord_adapter.analyze_content(request)
        
        assert result.risk_level in [RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        assert result.risk_score > 0.3


class TestDiscordAlgorithmHealth:
    """Test Discord algorithm health analysis."""
    
    @pytest.mark.asyncio
    async def test_get_algorithm_health(self, discord_adapter):
        """Test getting algorithm health metrics."""
        with patch.object(discord_adapter, '_calculate_community_engagement', new_callable=AsyncMock) as mock_engagement:
            with patch.object(discord_adapter, '_analyze_moderation_effectiveness', new_callable=AsyncMock) as mock_moderation:
                with patch.object(discord_adapter, '_analyze_member_growth', new_callable=AsyncMock) as mock_growth:
                    with patch.object(discord_adapter, '_analyze_server_activity', new_callable=AsyncMock) as mock_activity:
                        mock_engagement.return_value = 0.8
                        mock_moderation.return_value = {'score': 0.85}
                        mock_growth.return_value = {'score': 0.75}
                        mock_activity.return_value = {'score': 0.9}
                        
                        result = await discord_adapter.get_algorithm_health('123456789', 30)
                        
                        assert 'health_score' in result
                        assert 0.0 <= result['health_score'] <= 1.0
                        assert result['platform'] == PlatformType.DISCORD.value


class TestDiscordCrisisDetection:
    """Test Discord crisis detection."""
    
    @pytest.mark.asyncio
    async def test_detect_crisis_signals(self, discord_adapter):
        """Test crisis signal detection."""
        with patch.object(discord_adapter, '_detect_raid_attacks', new_callable=AsyncMock) as mock_raid:
            with patch.object(discord_adapter, '_detect_harassment_campaigns', new_callable=AsyncMock) as mock_harassment:
                with patch.object(discord_adapter, '_detect_mass_reporting', new_callable=AsyncMock) as mock_reporting:
                    with patch.object(discord_adapter, '_detect_doxxing_campaigns', new_callable=AsyncMock) as mock_doxxing:
                        with patch.object(discord_adapter, '_detect_server_disruption', new_callable=AsyncMock) as mock_disruption:
                            mock_raid.return_value = {'detected': False, 'severity': 'low', 'severity_score': 0.1}
                            mock_harassment.return_value = {'detected': False, 'severity': 'low'}
                            mock_reporting.return_value = {'detected': False}
                            mock_doxxing.return_value = {'detected': False, 'severity': 'low'}
                            mock_disruption.return_value = {'detected': False}
                            
                            result = await discord_adapter.detect_crisis_signals('123456789')
                            
                            assert 'crisis_level' in result
                            assert 'crisis_indicators' in result
                            assert result['platform'] == PlatformType.DISCORD.value


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
