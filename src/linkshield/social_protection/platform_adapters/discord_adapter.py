"""
Discord Platform Protection Adapter

This module implements Discord-specific social media protection functionality,
including server security assessment, user verification, content moderation,
raid detection, and community safety analysis.

Provides comprehensive protection for Discord servers, channels, and user profiles.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from enum import Enum
import asyncio

try:
    import discord
    from discord import Client, Intents, Guild, Member, Message, TextChannel
    from discord.errors import Forbidden, HTTPException, NotFound
    DISCORD_AVAILABLE = True
except ImportError:
    DISCORD_AVAILABLE = False
    Client = None
    Intents = None
    Guild = None
    Member = None
    Message = None
    TextChannel = None
    Forbidden = Exception
    HTTPException = Exception
    NotFound = Exception

from .base_adapter import SocialPlatformAdapter
from ..types import PlatformType, RiskLevel
from ..data_models import (
    ProfileScanRequest,
    ProfileScanResult,
    ContentAnalysisRequest,
    ContentAnalysisResult
)
from ..registry import registry
from ..logging_utils import get_logger
from ..exceptions import PlatformAdapterError

logger = get_logger("DiscordProtectionAdapter")


class DiscordRiskFactor(Enum):
    """Discord-specific risk factors for content and profile analysis."""
    RAID_DETECTION = "raid_detection"
    FAKE_ACCOUNTS = "fake_accounts"
    MALICIOUS_BOTS = "malicious_bots"
    SPAM_CONTENT = "spam_content"
    HARASSMENT_PATTERNS = "harassment_patterns"
    PHISHING_ATTEMPTS = "phishing_attempts"
    SERVER_SECURITY = "server_security"
    SUSPICIOUS_INVITES = "suspicious_invites"
    NSFW_VIOLATIONS = "nsfw_violations"
    DOXXING_THREATS = "doxxing_threats"


class DiscordProtectionAdapter(SocialPlatformAdapter):
    """
    Discord platform adapter for social media protection.
    
    Implements Discord-specific risk analysis including:
    - Server security and moderation assessment
    - User verification and bot detection
    - Raid and coordinated attack detection
    - Content safety and NSFW compliance
    - Harassment and doxxing prevention
    - Phishing and scam identification
    - Community health monitoring
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize Discord protection adapter.
        
        Args:
            config: Platform-specific configuration including API credentials,
                   risk thresholds, and feature flags
        """
        super().__init__(PlatformType.DISCORD, config or {})
        self.risk_thresholds = self._load_risk_thresholds()
        self.client: Optional[Client] = None
        self._initialize_api_client()
        
    def _load_risk_thresholds(self) -> Dict[str, float]:
        """Load Discord-specific risk thresholds from configuration."""
        return self.config.get('risk_thresholds', {
            'raid_detection': 0.8,
            'fake_account_ratio': 0.3,
            'malicious_bot_score': 0.75,
            'spam_content_score': 0.6,
            'harassment_score': 0.7,
            'phishing_score': 0.85,
            'server_security': 0.5,
            'nsfw_violation': 0.9,
            'doxxing_threat': 0.95
        })
    
    def _initialize_api_client(self) -> None:
        """
        Initialize Discord API client with authentication.
        
        Requires a bot token from Discord Developer Portal. The bot token is used to
        authenticate API requests and access Discord's API.
        
        Note: The bot must be added to servers to access their data and requires
        appropriate intents to be enabled in the Developer Portal.
        """
        if not DISCORD_AVAILABLE:
            logger.warning("discord.py library not available. Discord adapter will operate in limited mode.")
            self.is_enabled = False
            return
            
        try:
            # Get bot token from config
            bot_token = self.config.get('bot_token')
            
            if not bot_token:
                logger.warning("Discord bot token not configured. Adapter will operate in limited mode.")
                self.is_enabled = False
                return
            
            # Configure intents for bot capabilities
            intents = Intents.default()
            intents.guilds = True  # Access to guild/server information
            intents.members = True  # Access to member information (requires privileged intent)
            intents.messages = True  # Access to message content
            intents.message_content = True  # Access to message content (requires privileged intent)
            intents.moderation = True  # Access to moderation events
            
            # Initialize Discord client
            self.client = Client(intents=intents)
            self.bot_token = bot_token
            
            logger.info("Discord API client initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Discord API client: {str(e)}")
            self.is_enabled = False
            self.client = None
    
    async def validate_credentials(self) -> bool:
        """
        Validate Discord bot API credentials.
        
        Returns:
            True if credentials are valid and bot is accessible
        """
        if not self.client or not hasattr(self, 'bot_token'):
            logger.warning("Discord API client not initialized")
            return False
            
        try:
            # Start the client temporarily to validate
            async def validate():
                try:
                    await self.client.login(self.bot_token)
                    user = self.client.user
                    await self.client.close()
                    if user:
                        logger.info(f"Discord bot API credentials validated for bot: {user.name}#{user.discriminator}")
                        return True
                    return False
                except Exception as e:
                    logger.error(f"Discord bot API credential validation failed: {str(e)}")
                    return False
            
            return await validate()
            
        except Exception as e:
            logger.error(f"Unexpected error during credential validation: {str(e)}")
            return False
    
    async def fetch_guild_data(self, guild_id: int) -> Dict[str, Any]:
        """
        Fetch comprehensive guild/server data from Discord API.
        
        Args:
            guild_id: Discord guild (server) ID
            
        Returns:
            Dict containing guild data including info, member count, and metadata
            
        Raises:
            PlatformAdapterError: If guild fetch fails
        """
        if not self.client:
            raise PlatformAdapterError("Discord API client not initialized")
            
        try:
            # Ensure client is logged in
            if not self.client.is_ready():
                await self.client.login(self.bot_token)
                await self.client.connect()
            
            # Fetch guild information
            guild = self.client.get_guild(guild_id)
            if not guild:
                # Try fetching if not in cache
                guild = await self.client.fetch_guild(guild_id)
            
            if not guild:
                raise PlatformAdapterError(f"Guild {guild_id} not found or bot not in server")
            
            # Compile guild data
            guild_data = {
                'guild_id': str(guild.id),
                'name': guild.name,
                'description': guild.description,
                'icon_url': str(guild.icon.url) if guild.icon else None,
                'banner_url': str(guild.banner.url) if guild.banner else None,
                'splash_url': str(guild.splash.url) if guild.splash else None,
                'owner_id': str(guild.owner_id),
                'verification_level': guild.verification_level.value,
                'explicit_content_filter': guild.explicit_content_filter.value,
                'default_notifications': guild.default_notifications.value,
                'features': [str(feature) for feature in guild.features],
                'member_count': guild.member_count,
                'premium_tier': guild.premium_tier,
                'premium_subscription_count': guild.premium_subscription_count,
                'max_members': guild.max_members,
                'max_presences': guild.max_presences,
                'mfa_level': guild.mfa_level,
                'nsfw_level': guild.nsfw_level.value if hasattr(guild, 'nsfw_level') else 0,
                'created_at': guild.created_at.isoformat() if guild.created_at else None,
                'channels_count': len(guild.channels),
                'roles_count': len(guild.roles),
                'emojis_count': len(guild.emojis),
                'fetched_at': datetime.utcnow().isoformat()
            }
            
            logger.info(f"Successfully fetched guild data for {guild_id}")
            return guild_data
            
        except (Forbidden, HTTPException, NotFound) as e:
            logger.error(f"Discord API error fetching guild {guild_id}: {str(e)}")
            raise PlatformAdapterError(f"Failed to fetch Discord guild: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error fetching guild {guild_id}: {str(e)}")
            raise PlatformAdapterError(f"Unexpected error: {str(e)}")
        finally:
            # Close connection if we opened it
            if self.client.is_ready():
                await self.client.close()
    
    async def fetch_member_data(self, guild_id: int, user_id: int) -> Dict[str, Any]:
        """
        Fetch member data from a Discord guild.
        
        Args:
            guild_id: Discord guild (server) ID
            user_id: Discord user ID
            
        Returns:
            Dict containing member data
            
        Raises:
            PlatformAdapterError: If member fetch fails
        """
        if not self.client:
            raise PlatformAdapterError("Discord API client not initialized")
            
        try:
            # Ensure client is logged in
            if not self.client.is_ready():
                await self.client.login(self.bot_token)
                await self.client.connect()
            
            # Fetch guild
            guild = self.client.get_guild(guild_id)
            if not guild:
                guild = await self.client.fetch_guild(guild_id)
            
            if not guild:
                raise PlatformAdapterError(f"Guild {guild_id} not found")
            
            # Fetch member
            member = guild.get_member(user_id)
            if not member:
                member = await guild.fetch_member(user_id)
            
            if not member:
                raise PlatformAdapterError(f"Member {user_id} not found in guild {guild_id}")
            
            # Compile member data
            member_data = {
                'user_id': str(member.id),
                'username': member.name,
                'discriminator': member.discriminator,
                'global_name': member.global_name if hasattr(member, 'global_name') else None,
                'display_name': member.display_name,
                'nick': member.nick,
                'is_bot': member.bot,
                'avatar_url': str(member.avatar.url) if member.avatar else None,
                'joined_at': member.joined_at.isoformat() if member.joined_at else None,
                'created_at': member.created_at.isoformat() if member.created_at else None,
                'roles': [{'id': str(role.id), 'name': role.name, 'position': role.position} for role in member.roles],
                'top_role': {'id': str(member.top_role.id), 'name': member.top_role.name} if member.top_role else None,
                'premium_since': member.premium_since.isoformat() if member.premium_since else None,
                'pending': member.pending if hasattr(member, 'pending') else False,
                'timed_out_until': member.timed_out_until.isoformat() if hasattr(member, 'timed_out_until') and member.timed_out_until else None,
                'fetched_at': datetime.utcnow().isoformat()
            }
            
            logger.info(f"Successfully fetched member data for user {user_id} in guild {guild_id}")
            return member_data
            
        except (Forbidden, HTTPException, NotFound) as e:
            logger.error(f"Discord API error fetching member {user_id}: {str(e)}")
            raise PlatformAdapterError(f"Failed to fetch Discord member: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error fetching member {user_id}: {str(e)}")
            raise PlatformAdapterError(f"Unexpected error: {str(e)}")
        finally:
            # Close connection if we opened it
            if self.client.is_ready():
                await self.client.close()
    
    async def fetch_channel_messages(self, channel_id: int, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Fetch recent messages from a Discord channel.
        
        Args:
            channel_id: Discord channel ID
            limit: Maximum number of messages to fetch
            
        Returns:
            List of message data dictionaries
            
        Raises:
            PlatformAdapterError: If messages fetch fails
        """
        if not self.client:
            raise PlatformAdapterError("Discord API client not initialized")
            
        try:
            # Ensure client is logged in
            if not self.client.is_ready():
                await self.client.login(self.bot_token)
                await self.client.connect()
            
            # Fetch channel
            channel = self.client.get_channel(channel_id)
            if not channel:
                channel = await self.client.fetch_channel(channel_id)
            
            if not channel or not isinstance(channel, TextChannel):
                raise PlatformAdapterError(f"Text channel {channel_id} not found or not accessible")
            
            # Fetch messages
            messages = []
            async for message in channel.history(limit=limit):
                message_data = {
                    'message_id': str(message.id),
                    'channel_id': str(message.channel.id),
                    'guild_id': str(message.guild.id) if message.guild else None,
                    'author_id': str(message.author.id),
                    'author_name': message.author.name,
                    'author_discriminator': message.author.discriminator,
                    'author_is_bot': message.author.bot,
                    'content': message.content,
                    'clean_content': message.clean_content,
                    'created_at': message.created_at.isoformat(),
                    'edited_at': message.edited_at.isoformat() if message.edited_at else None,
                    'is_pinned': message.pinned,
                    'mentions': [str(user.id) for user in message.mentions],
                    'mention_everyone': message.mention_everyone,
                    'attachments': [{'id': str(a.id), 'filename': a.filename, 'url': a.url} for a in message.attachments],
                    'embeds': [{'title': e.title, 'description': e.description, 'url': e.url} for e in message.embeds],
                    'reactions': [{'emoji': str(r.emoji), 'count': r.count} for r in message.reactions] if message.reactions else []
                }
                messages.append(message_data)
            
            logger.info(f"Successfully fetched {len(messages)} messages from channel {channel_id}")
            return messages
            
        except (Forbidden, HTTPException, NotFound) as e:
            logger.error(f"Discord API error fetching messages from channel {channel_id}: {str(e)}")
            raise PlatformAdapterError(f"Failed to fetch channel messages: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error fetching messages from channel {channel_id}: {str(e)}")
            raise PlatformAdapterError(f"Unexpected error: {str(e)}")
        finally:
            # Close connection if we opened it
            if self.client.is_ready():
                await self.client.close()
    
    async def scan_profile(self, request: ProfileScanRequest) -> ProfileScanResult:
        """
        Perform comprehensive Discord profile security audit.
        
        Analyzes user profiles, server configurations, and member behavior
        for security risks, verification status, and community safety.
        
        Args:
            request: Profile scan request with Discord-specific data
                         
        Returns:
            ProfileScanResult containing risk assessment and recommendations
        """
        try:
            logger.info(f"Starting Discord profile scan for: {request.profile_identifier}")
            
            # Initialize profile data
            profile_data = {}
            
            # Try to fetch fresh data from API if bot is available
            if self.client and request.profile_identifier:
                try:
                    # Determine if this is a guild or user scan
                    if request.profile_data and request.profile_data.get('entity_type') == 'server':
                        guild_id = int(request.profile_identifier)
                        fetched_data = await self.fetch_guild_data(guild_id)
                        profile_data.update(fetched_data)
                    elif request.profile_data and request.profile_data.get('guild_id'):
                        # User/member scan within a guild
                        guild_id = int(request.profile_data['guild_id'])
                        user_id = int(request.profile_identifier)
                        fetched_data = await self.fetch_member_data(guild_id, user_id)
                        profile_data.update(fetched_data)
                except PlatformAdapterError as e:
                    logger.warning(f"Could not fetch fresh data from API: {str(e)}")
                except ValueError as e:
                    logger.warning(f"Invalid ID format: {str(e)}")
            
            # Merge with any provided profile data
            if request.profile_data:
                profile_data.update(request.profile_data)
            
            # Initialize risk factors
            risk_factors = {}
            
            # Analyze user verification status
            verification_risk = await self._analyze_user_verification(profile_data)
            risk_factors['user_verification'] = verification_risk
            
            # Analyze account authenticity
            authenticity_risk = await self._analyze_account_authenticity(profile_data)
            risk_factors['account_authenticity'] = authenticity_risk
            
            # Analyze server security (if applicable)
            server_risk = await self._analyze_server_security(profile_data)
            risk_factors['server_security'] = server_risk
            
            # Analyze member behavior patterns
            behavior_risk = await self._analyze_member_behavior(profile_data)
            risk_factors['member_behavior'] = behavior_risk
            
            # Analyze bot detection indicators
            bot_risk = await self._analyze_bot_detection(profile_data)
            risk_factors['bot_detection'] = bot_risk
            
            # Calculate overall risk score
            risk_score = self._calculate_profile_risk_score(risk_factors)
            risk_level = self._determine_risk_level(risk_score)
            
            # Generate recommendations
            recommendations = self._generate_profile_recommendations(risk_factors, risk_level)
            
            return ProfileScanResult(
                profile_id=profile_data.get('id', ''),
                platform=self.platform_type,
                risk_level=risk_level,
                risk_score=risk_score,
                risk_factors=risk_factors,
                recommendations=recommendations,
                scan_timestamp=datetime.utcnow(),
                confidence_score=min(0.95, 0.75 + (risk_score * 0.2))
            )
            
        except Exception as e:
            logger.error(f"Error scanning Discord profile: {str(e)}")
            raise
    
    async def analyze_content(self, request: ContentAnalysisRequest) -> ContentAnalysisResult:
        """
        Analyze Discord content for platform-specific risks.
        
        Evaluates messages, attachments, and embeds for spam, harassment,
        NSFW violations, phishing attempts, and community guideline violations.
        
        Args:
            request: Content analysis request with message data
            
        Returns:
            ContentAnalysisResult with risk assessment and recommendations
        """
        try:
            logger.info("Starting Discord content analysis")
            
            # Extract content data from analysis_options or use empty dict
            content_data = request.analysis_options.get('content_data', {})
            
            # Initialize risk factors
            risk_factors = {}
            
            # Analyze spam and promotional content
            spam_risk = await self._detect_spam_content(content_data)
            risk_factors['spam_content'] = spam_risk
            
            # Analyze harassment patterns
            harassment_risk = await self._detect_harassment_patterns(content_data)
            risk_factors['harassment_patterns'] = harassment_risk
            
            # Analyze NSFW content violations
            nsfw_risk = await self._analyze_nsfw_violations(content_data)
            risk_factors['nsfw_violations'] = nsfw_risk
            
            # Analyze phishing and scam attempts
            phishing_risk = await self._detect_phishing_attempts(content_data)
            risk_factors['phishing_attempts'] = phishing_risk
            
            # Analyze doxxing and personal information exposure
            doxxing_risk = await self._detect_doxxing_threats(content_data)
            risk_factors['doxxing_threats'] = doxxing_risk
            
            # Analyze malicious attachments and links
            malicious_risk = await self._analyze_malicious_content(content_data)
            risk_factors['malicious_content'] = malicious_risk
            
            # Calculate overall risk score
            risk_score = self._calculate_content_risk_score(risk_factors)
            risk_level = self._determine_risk_level(risk_score)
            
            # Generate recommendations
            recommendations = self._generate_content_recommendations(risk_factors, risk_level)
            
            return ContentAnalysisResult(
                content_id=content_data.get('message_id', ''),
                platform=self.platform_type,
                content_type=request.content_type,
                risk_level=risk_level,
                risk_score=risk_score,
                risk_factors=risk_factors,
                recommendations=recommendations,
                analysis_timestamp=datetime.utcnow(),
                confidence_score=min(0.95, 0.8 + (risk_score * 0.15))
            )
            
        except Exception as e:
            logger.error(f"Error analyzing Discord content: {str(e)}")
            raise
    
    async def get_algorithm_health(self, profile_id: str, timeframe_days: int = 30) -> Dict[str, Any]:
        """
        Assess Discord community health and engagement metrics.
        
        Analyzes server activity, member engagement, moderation effectiveness,
        and community growth patterns.
        
        Args:
            profile_id: Discord server/user identifier
            timeframe_days: Analysis timeframe in days
            
        Returns:
            Community health metrics and recommendations
        """
        try:
            logger.info(f"Analyzing Discord community health for: {profile_id}")
            
            # Calculate community engagement score
            engagement_score = await self._calculate_community_engagement(profile_id, timeframe_days)
            
            # Analyze moderation effectiveness
            moderation_health = await self._analyze_moderation_effectiveness(profile_id, timeframe_days)
            
            # Analyze member retention and growth
            growth_metrics = await self._analyze_member_growth(profile_id, timeframe_days)
            
            # Analyze server activity patterns
            activity_health = await self._analyze_server_activity(profile_id, timeframe_days)
            
            # Calculate overall community health score
            health_score = (
                engagement_score * 0.3 +
                moderation_health.get('score', 0.5) * 0.25 +
                growth_metrics.get('score', 0.5) * 0.25 +
                activity_health.get('score', 0.5) * 0.2
            )
            
            return {
                'platform': self.platform_type.value,
                'profile_id': profile_id,
                'timeframe_days': timeframe_days,
                'health_score': health_score,
                'community_engagement': engagement_score,
                'moderation_effectiveness': moderation_health,
                'member_growth': growth_metrics,
                'server_activity': activity_health,
                'recommendations': self._generate_community_recommendations(health_score),
                'analysis_timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error analyzing Discord community health: {str(e)}")
            raise
    
    async def detect_crisis_signals(self, profile_id: str) -> Dict[str, Any]:
        """
        Detect crisis signals and security threats on Discord.
        
        Monitors for raid attacks, coordinated harassment campaigns,
        mass reporting, doxxing attempts, and community disruption.
        
        Args:
            profile_id: Discord server/user identifier
            
        Returns:
            Crisis detection results with severity assessment
        """
        try:
            logger.info(f"Detecting crisis signals for Discord profile: {profile_id}")
            
            # Detect raid attacks
            raid_detection = await self._detect_raid_attacks(profile_id)
            
            # Detect coordinated harassment
            harassment_campaigns = await self._detect_harassment_campaigns(profile_id)
            
            # Detect mass reporting campaigns
            mass_reporting = await self._detect_mass_reporting(profile_id)
            
            # Detect doxxing attempts
            doxxing_attempts = await self._detect_doxxing_campaigns(profile_id)
            
            # Detect server disruption attempts
            disruption_attempts = await self._detect_server_disruption(profile_id)
            
            # Calculate crisis severity
            crisis_indicators = {
                'raid_attacks': raid_detection,
                'harassment_campaigns': harassment_campaigns,
                'mass_reporting': mass_reporting,
                'doxxing_attempts': doxxing_attempts,
                'server_disruption': disruption_attempts
            }
            
            crisis_level = self._determine_crisis_level(crisis_indicators)
            
            return {
                'platform': self.platform_type.value,
                'profile_id': profile_id,
                'crisis_level': crisis_level.value,
                'crisis_indicators': crisis_indicators,
                'alerts': self._generate_crisis_alerts(crisis_indicators),
                'recommendations': self._generate_crisis_recommendations(crisis_level),
                'detection_timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error detecting Discord crisis signals: {str(e)}")
            raise
    
    # Private helper methods for specific analysis tasks
    
    async def _analyze_user_verification(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze user verification status and trust indicators."""
        return {
            'is_verified': profile_data.get('verified', False),
            'phone_verified': profile_data.get('phone_verified', False),
            'email_verified': profile_data.get('email_verified', False),
            'trust_score': 0.8,  # Placeholder
            'verification_indicators': []
        }
    
    async def _analyze_account_authenticity(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze account authenticity and fake account indicators."""
        return {
            'authenticity_score': 0.9,  # Placeholder
            'fake_account_probability': 0.05,
            'suspicious_patterns': [],
            'account_age_days': profile_data.get('account_age_days', 0)
        }
    
    async def _analyze_server_security(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze server security configuration and settings."""
        security_score = 1.0
        security_features = []
        security_issues = []
        
        # Check verification level (0=None, 1=Low, 2=Medium, 3=High, 4=Very High)
        verification_level = profile_data.get('verification_level', 0)
        if verification_level >= 3:
            security_features.append('high_verification_level')
        elif verification_level <= 1:
            security_issues.append('low_verification_level')
            security_score -= 0.15
        
        # Check explicit content filter (0=Disabled, 1=Members without roles, 2=All members)
        content_filter = profile_data.get('explicit_content_filter', 0)
        if content_filter == 2:
            security_features.append('strict_content_filter')
        elif content_filter == 0:
            security_issues.append('no_content_filter')
            security_score -= 0.1
        
        # Check MFA requirement for moderators
        mfa_level = profile_data.get('mfa_level', 0)
        if mfa_level > 0:
            security_features.append('mfa_required')
        else:
            security_issues.append('mfa_not_required')
            security_score -= 0.2
        
        # Check server features for security indicators
        features = profile_data.get('features', [])
        if 'COMMUNITY' in features:
            security_features.append('community_server')
        if 'VERIFIED' in features:
            security_features.append('verified_server')
        if 'PARTNERED' in features:
            security_features.append('partnered_server')
        if 'MEMBER_VERIFICATION_GATE' in features:
            security_features.append('member_verification_gate')
        if 'WELCOME_SCREEN_ENABLED' in features:
            security_features.append('welcome_screen')
        
        # Check NSFW level
        nsfw_level = profile_data.get('nsfw_level', 0)
        if nsfw_level > 0:
            security_issues.append(f'nsfw_level_{nsfw_level}')
            security_score -= 0.05
        
        # Check member count for risk assessment
        member_count = profile_data.get('member_count', 0)
        if member_count > 10000 and verification_level < 2:
            security_issues.append('large_server_low_verification')
            security_score -= 0.1
        
        return {
            'security_score': max(0.0, min(1.0, security_score)),
            'verification_level': verification_level,
            'content_filter_level': content_filter,
            'mfa_required': mfa_level > 0,
            'security_features': security_features,
            'security_issues': security_issues,
            'member_count': member_count
        }
    
    async def _analyze_member_behavior(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze member behavior patterns and activity."""
        behavior_score = 0.9
        activity_patterns = []
        risk_indicators = []
        
        # Check account age
        created_at = profile_data.get('created_at')
        if created_at:
            try:
                created_date = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                account_age_days = (datetime.utcnow() - created_date.replace(tzinfo=None)).days
                
                if account_age_days < 7:
                    risk_indicators.append('very_new_account')
                    behavior_score -= 0.2
                elif account_age_days < 30:
                    risk_indicators.append('new_account')
                    behavior_score -= 0.1
                else:
                    activity_patterns.append('established_account')
            except Exception:
                pass
        
        # Check join date (for guild members)
        joined_at = profile_data.get('joined_at')
        if joined_at:
            try:
                joined_date = datetime.fromisoformat(joined_at.replace('Z', '+00:00'))
                member_age_days = (datetime.utcnow() - joined_date.replace(tzinfo=None)).days
                
                if member_age_days < 1:
                    risk_indicators.append('just_joined')
                    behavior_score -= 0.15
            except Exception:
                pass
        
        # Check roles (more roles generally indicates trusted member)
        roles = profile_data.get('roles', [])
        role_count = len(roles) - 1  # Subtract @everyone role
        if role_count > 3:
            activity_patterns.append('multiple_roles')
        elif role_count == 0:
            risk_indicators.append('no_roles')
            behavior_score -= 0.05
        
        # Check if member is boosting the server
        premium_since = profile_data.get('premium_since')
        if premium_since:
            activity_patterns.append('server_booster')
            behavior_score += 0.05
        
        # Check if member is timed out (muted)
        timed_out_until = profile_data.get('timed_out_until')
        if timed_out_until:
            risk_indicators.append('currently_timed_out')
            behavior_score -= 0.3
        
        # Check pending status (membership screening)
        pending = profile_data.get('pending', False)
        if pending:
            risk_indicators.append('pending_verification')
            behavior_score -= 0.1
        
        return {
            'behavior_score': max(0.0, min(1.0, behavior_score)),
            'activity_patterns': activity_patterns,
            'risk_indicators': risk_indicators,
            'role_count': role_count if 'roles' in profile_data else 0,
            'is_booster': premium_since is not None,
            'is_timed_out': timed_out_until is not None
        }
    
    async def _analyze_bot_detection(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze indicators of bot accounts."""
        is_bot = profile_data.get('is_bot', False)
        is_verified_bot = profile_data.get('is_verified', False)
        bot_indicators = []
        bot_risk_score = 0.0
        
        if is_bot:
            bot_indicators.append('flagged_as_bot')
            
            # Verified bots are generally safer
            if is_verified_bot:
                bot_indicators.append('verified_bot')
                bot_risk_score = 0.1
            else:
                bot_indicators.append('unverified_bot')
                bot_risk_score = 0.3
            
            # Check bot permissions if available
            permissions = profile_data.get('permissions', [])
            dangerous_perms = ['administrator', 'manage_guild', 'manage_roles', 'manage_channels', 'kick_members', 'ban_members']
            has_dangerous_perms = any(perm in permissions for perm in dangerous_perms)
            
            if has_dangerous_perms and not is_verified_bot:
                bot_indicators.append('unverified_bot_with_dangerous_permissions')
                bot_risk_score = 0.7
        else:
            # Check for bot-like behavior patterns in regular accounts
            username = profile_data.get('username', '')
            if username:
                # Bot-like username patterns
                if any(keyword in username.lower() for keyword in ['bot', 'auto', 'system', 'service']):
                    bot_indicators.append('bot_like_username')
                    bot_risk_score = 0.2
        
        return {
            'is_bot': is_bot,
            'is_verified_bot': is_verified_bot,
            'bot_risk_score': bot_risk_score,
            'bot_indicators': bot_indicators,
            'has_dangerous_permissions': has_dangerous_perms if is_bot else False
        }
    
    async def _detect_spam_content(self, content_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect spam and promotional content patterns."""
        return {
            'spam_probability': 0.05,  # Placeholder
            'spam_indicators': [],
            'promotional_content': False,
            'repetitive_patterns': []
        }
    
    async def _detect_harassment_patterns(self, content_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect harassment and toxic behavior patterns."""
        return {
            'harassment_score': 0.1,  # Placeholder
            'toxic_language': False,
            'harassment_indicators': [],
            'target_analysis': {}
        }
    
    async def _analyze_nsfw_violations(self, content_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze NSFW content violations."""
        return {
            'nsfw_probability': 0.02,  # Placeholder
            'content_rating': 'safe',
            'violation_types': [],
            'age_appropriate': True
        }
    
    async def _detect_phishing_attempts(self, content_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect phishing and scam attempts."""
        return {
            'phishing_probability': 0.03,  # Placeholder
            'suspicious_links': [],
            'scam_indicators': [],
            'credential_harvesting': False
        }
    
    async def _detect_doxxing_threats(self, content_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect doxxing and personal information exposure."""
        return {
            'doxxing_risk': 0.01,  # Placeholder
            'personal_info_exposed': False,
            'threat_indicators': [],
            'privacy_violations': []
        }
    
    async def _analyze_malicious_content(self, content_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze malicious attachments and links."""
        return {
            'malicious_score': 0.02,  # Placeholder
            'suspicious_attachments': [],
            'malicious_links': [],
            'malware_indicators': []
        }
    
    async def _calculate_community_engagement(self, profile_id: str, timeframe_days: int) -> float:
        """Calculate community engagement score."""
        return 0.75  # Placeholder
    
    async def _analyze_moderation_effectiveness(self, profile_id: str, timeframe_days: int) -> Dict[str, Any]:
        """Analyze moderation effectiveness metrics."""
        return {
            'score': 0.8,  # Placeholder
            'response_time': 'fast',
            'action_accuracy': 0.9,
            'coverage': 'comprehensive'
        }
    
    async def _analyze_member_growth(self, profile_id: str, timeframe_days: int) -> Dict[str, Any]:
        """Analyze member growth and retention patterns."""
        return {
            'score': 0.7,  # Placeholder
            'growth_rate': 0.05,
            'retention_rate': 0.85,
            'churn_analysis': {}
        }
    
    async def _analyze_server_activity(self, profile_id: str, timeframe_days: int) -> Dict[str, Any]:
        """Analyze server activity patterns."""
        return {
            'score': 0.8,  # Placeholder
            'activity_level': 'high',
            'peak_hours': [],
            'channel_utilization': {}
        }
    
    async def _detect_raid_attacks(self, profile_id: str) -> Dict[str, Any]:
        """
        Detect raid attacks and coordinated joining.
        
        Analyzes patterns that indicate a raid:
        - Sudden spike in member joins
        - Multiple accounts created around the same time
        - Similar usernames or profile pictures
        - Coordinated message spam
        - Mass mention abuse
        """
        raid_detected = False
        severity_score = 0.0
        attack_patterns = []
        raid_indicators = []
        
        try:
            # Try to fetch guild data if client is available
            if self.client:
                try:
                    guild_id = int(profile_id)
                    guild_data = await self.fetch_guild_data(guild_id)
                    
                    # Analyze member count growth
                    member_count = guild_data.get('member_count', 0)
                    
                    # Check for suspicious features indicating raid vulnerability
                    verification_level = guild_data.get('verification_level', 0)
                    if verification_level < 2 and member_count > 100:
                        raid_indicators.append('low_verification_large_server')
                        severity_score += 0.2
                    
                    # Check if server has raid protection features
                    features = guild_data.get('features', [])
                    if 'MEMBER_VERIFICATION_GATE' not in features:
                        raid_indicators.append('no_verification_gate')
                        severity_score += 0.15
                    
                    # Try to analyze recent joins (would need audit log access)
                    # This is a placeholder for actual audit log analysis
                    # In production, you'd check audit logs for:
                    # - Multiple joins in short time window
                    # - Accounts with similar creation dates
                    # - Pattern in usernames
                    
                except (PlatformAdapterError, ValueError) as e:
                    logger.warning(f"Could not fetch guild data for raid detection: {str(e)}")
        except Exception as e:
            logger.error(f"Error in raid detection: {str(e)}")
        
        # Determine if raid is detected based on severity
        if severity_score >= 0.5:
            raid_detected = True
            attack_patterns.append('high_risk_configuration')
        
        # Classify severity
        if severity_score >= 0.8:
            severity = 'critical'
        elif severity_score >= 0.6:
            severity = 'high'
        elif severity_score >= 0.3:
            severity = 'medium'
        else:
            severity = 'low'
        
        return {
            'detected': raid_detected,
            'severity': severity,
            'severity_score': severity_score,
            'attack_patterns': attack_patterns,
            'raid_indicators': raid_indicators,
            'recommendations': self._generate_raid_protection_recommendations(severity_score)
        }
    
    def _generate_raid_protection_recommendations(self, severity_score: float) -> List[str]:
        """Generate recommendations for raid protection."""
        recommendations = []
        
        if severity_score >= 0.5:
            recommendations.append("Enable member verification gate")
            recommendations.append("Increase server verification level to High or Very High")
            recommendations.append("Enable 2FA requirement for moderators")
            recommendations.append("Set up auto-moderation rules")
            recommendations.append("Limit permissions for new members")
        
        if severity_score >= 0.3:
            recommendations.append("Monitor member join patterns")
            recommendations.append("Configure welcome screen with rules")
            recommendations.append("Set up raid alert notifications")
        
        recommendations.append("Maintain active moderation team")
        recommendations.append("Use Discord's built-in safety features")
        
        return recommendations
    
    async def _detect_harassment_campaigns(self, profile_id: str) -> Dict[str, Any]:
        """Detect coordinated harassment campaigns."""
        return {
            'detected': False,
            'campaign_indicators': [],
            'coordination_score': 0.0,
            'target_analysis': {}
        }
    
    async def _detect_mass_reporting(self, profile_id: str) -> Dict[str, Any]:
        """Detect mass reporting campaigns."""
        return {
            'detected': False,
            'report_volume': 0,
            'reporting_patterns': [],
            'false_report_indicators': []
        }
    
    async def _detect_doxxing_campaigns(self, profile_id: str) -> Dict[str, Any]:
        """Detect doxxing campaigns and personal information sharing."""
        return {
            'detected': False,
            'severity': 'low',
            'information_types': [],
            'threat_level': 'minimal'
        }
    
    async def _detect_server_disruption(self, profile_id: str) -> Dict[str, Any]:
        """
        Detect server disruption attempts.
        
        Analyzes patterns indicating disruption:
        - Mass channel creation/deletion
        - Role manipulation attacks
        - Permission escalation attempts
        - Webhook abuse
        - Bot spam attacks
        """
        disruption_detected = False
        disruption_types = []
        disruption_score = 0.0
        impact_indicators = []
        
        try:
            # Try to fetch guild data if client is available
            if self.client:
                try:
                    guild_id = int(profile_id)
                    guild_data = await self.fetch_guild_data(guild_id)
                    
                    # Check for excessive channels (could indicate channel spam)
                    channels_count = guild_data.get('channels_count', 0)
                    member_count = guild_data.get('member_count', 1)
                    
                    # Unusual channel to member ratio
                    if channels_count > 50 and member_count < 100:
                        disruption_types.append('excessive_channels')
                        impact_indicators.append('channel_spam_possible')
                        disruption_score += 0.3
                    
                    # Check for excessive roles (could indicate role spam)
                    roles_count = guild_data.get('roles_count', 0)
                    if roles_count > 100:
                        disruption_types.append('excessive_roles')
                        impact_indicators.append('role_spam_possible')
                        disruption_score += 0.2
                    
                    # Check for excessive emojis (could indicate emoji spam)
                    emojis_count = guild_data.get('emojis_count', 0)
                    if emojis_count > 200:
                        disruption_types.append('excessive_emojis')
                        impact_indicators.append('emoji_spam_possible')
                        disruption_score += 0.1
                    
                    # Check MFA requirement (lack of MFA increases disruption risk)
                    mfa_level = guild_data.get('mfa_level', 0)
                    if mfa_level == 0 and member_count > 1000:
                        impact_indicators.append('no_mfa_large_server')
                        disruption_score += 0.2
                    
                except (PlatformAdapterError, ValueError) as e:
                    logger.warning(f"Could not fetch guild data for disruption detection: {str(e)}")
        except Exception as e:
            logger.error(f"Error in disruption detection: {str(e)}")
        
        # Determine if disruption is detected
        if disruption_score >= 0.4:
            disruption_detected = True
        
        # Assess impact level
        if disruption_score >= 0.7:
            impact_assessment = 'critical'
        elif disruption_score >= 0.5:
            impact_assessment = 'high'
        elif disruption_score >= 0.3:
            impact_assessment = 'medium'
        elif disruption_score > 0:
            impact_assessment = 'low'
        else:
            impact_assessment = 'none'
        
        return {
            'detected': disruption_detected,
            'disruption_types': disruption_types,
            'disruption_score': disruption_score,
            'impact_assessment': impact_assessment,
            'impact_indicators': impact_indicators,
            'mitigation_needed': disruption_detected,
            'recommendations': self._generate_disruption_mitigation_recommendations(disruption_score)
        }
    
    def _generate_disruption_mitigation_recommendations(self, disruption_score: float) -> List[str]:
        """Generate recommendations for disruption mitigation."""
        recommendations = []
        
        if disruption_score >= 0.5:
            recommendations.append("Review and audit all administrative actions")
            recommendations.append("Check for compromised moderator accounts")
            recommendations.append("Implement stricter permission controls")
            recommendations.append("Enable audit log monitoring")
            recommendations.append("Consider temporary lockdown of server modifications")
        
        if disruption_score >= 0.3:
            recommendations.append("Review role permissions and hierarchies")
            recommendations.append("Limit channel creation permissions")
            recommendations.append("Monitor webhook usage")
            recommendations.append("Enable 2FA for all moderators")
        
        recommendations.append("Maintain regular backups of server configuration")
        recommendations.append("Document and review permission structure")
        
        return recommendations
    
    def _calculate_profile_risk_score(self, risk_factors: Dict[str, Any]) -> float:
        """Calculate overall profile risk score."""
        weights = {
            'user_verification': 0.2,
            'account_authenticity': 0.25,
            'server_security': 0.2,
            'member_behavior': 0.2,
            'bot_detection': 0.15
        }
        
        total_score = 0.0
        for factor, data in risk_factors.items():
            if factor in weights:
                factor_score = data.get('risk_score', data.get('score', 0.0))
                total_score += factor_score * weights[factor]
        
        return min(1.0, total_score)
    
    def _calculate_content_risk_score(self, risk_factors: Dict[str, Any]) -> float:
        """Calculate overall content risk score."""
        weights = {
            'spam_content': 0.15,
            'harassment_patterns': 0.25,
            'nsfw_violations': 0.2,
            'phishing_attempts': 0.2,
            'doxxing_threats': 0.15,
            'malicious_content': 0.05
        }
        
        total_score = 0.0
        for factor, data in risk_factors.items():
            if factor in weights:
                factor_score = data.get('risk_score', data.get('score', 0.0))
                total_score += factor_score * weights[factor]
        
        return min(1.0, total_score)
    
    def _determine_crisis_level(self, crisis_indicators: Dict[str, Any]) -> RiskLevel:
        """Determine crisis level from indicators."""
        max_severity = 0.0
        for indicator_data in crisis_indicators.values():
            # Check for severity_score or severity fields
            severity = indicator_data.get('severity_score', 0.0)
            if severity == 0.0:
                # Try alternate severity field
                severity_str = indicator_data.get('severity', 'low')
                severity_map = {'low': 0.2, 'medium': 0.4, 'high': 0.7, 'critical': 0.9}
                severity = severity_map.get(severity_str, 0.0)
            max_severity = max(max_severity, severity)
        
        return self._determine_risk_level(max_severity)
    
    def _generate_profile_recommendations(self, risk_factors: Dict[str, Any], risk_level: RiskLevel) -> List[str]:
        """Generate profile-specific recommendations."""
        recommendations = []
        
        if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            recommendations.append("Review server security settings")
            recommendations.append("Enable additional verification requirements")
        
        if not risk_factors.get('user_verification', {}).get('is_verified', False):
            recommendations.append("Complete account verification process")
        
        return recommendations
    
    def _generate_content_recommendations(self, risk_factors: Dict[str, Any], risk_level: RiskLevel) -> List[str]:
        """Generate content-specific recommendations."""
        recommendations = []
        
        if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            recommendations.append("Review content for community guideline violations")
            recommendations.append("Implement stricter content moderation")
        
        if risk_factors.get('harassment_patterns', {}).get('harassment_score', 0) > 0.5:
            recommendations.append("Address harassment behavior immediately")
        
        return recommendations
    
    def _generate_community_recommendations(self, health_score: float) -> List[str]:
        """Generate community health recommendations."""
        recommendations = []
        
        if health_score < 0.5:
            recommendations.append("Improve community engagement strategies")
            recommendations.append("Review moderation policies and effectiveness")
            recommendations.append("Implement member retention programs")
        
        return recommendations
    
    def _generate_crisis_alerts(self, crisis_indicators: Dict[str, Any]) -> List[str]:
        """Generate crisis-specific alerts."""
        alerts = []
        
        for indicator, data in crisis_indicators.items():
            if data.get('detected', False):
                alerts.append(f"Crisis detected: {indicator}")
        
        return alerts
    
    def _generate_crisis_recommendations(self, crisis_level: RiskLevel) -> List[str]:
        """Generate crisis response recommendations."""
        if crisis_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            return [
                "Activate emergency moderation protocols",
                "Implement temporary server lockdown if necessary",
                "Monitor for coordinated attacks",
                "Prepare incident response documentation",
                "Consider contacting Discord Trust & Safety"
            ]
        
        return ["Continue monitoring for escalation"]


# Register the Discord adapter with the platform registry
registry.register_adapter(
    PlatformType.DISCORD,
    DiscordProtectionAdapter,
    config={
        'enabled': True,
        'rate_limits': {
            'profile_scans_per_hour': 100,
            'content_analysis_per_hour': 500,
            'crisis_detection_per_hour': 50,
            'community_health_per_hour': 20
        },
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
)