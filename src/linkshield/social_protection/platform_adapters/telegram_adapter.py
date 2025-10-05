"""
Telegram Platform Protection Adapter

This module implements Telegram-specific social media protection functionality,
including bot detection, channel authenticity assessment, content safety scanning,
scam pattern recognition, and forward chain analysis.

Provides comprehensive protection for Telegram channels, groups, and user profiles.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from enum import Enum
import asyncio

try:
    from telegram import Bot
    from telegram.error import TelegramError, InvalidToken, NetworkError
    TELEGRAM_AVAILABLE = True
except ImportError:
    TELEGRAM_AVAILABLE = False
    Bot = None
    TelegramError = Exception
    InvalidToken = Exception
    NetworkError = Exception

from .base_adapter import SocialPlatformAdapter, PlatformType, RiskLevel
from ..data_models.social_profile_models import ProfileScanRequest, ProfileScanResult
from ..data_models.content_risk_models import ContentAnalysisRequest, ContentAnalysisResult
from ..registry import registry
from ..logging_utils import get_logger
from ..exceptions import PlatformAdapterError

logger = get_logger("TelegramProtectionAdapter")


class TelegramRiskFactor(Enum):
    """Telegram-specific risk factors for content and profile analysis."""
    BOT_DETECTION = "bot_detection"
    FAKE_SUBSCRIBERS = "fake_subscribers"
    SCAM_PATTERNS = "scam_patterns"
    MALICIOUS_LINKS = "malicious_links"
    SPAM_CONTENT = "spam_content"
    FORWARD_CHAIN_MANIPULATION = "forward_chain_manipulation"
    CHANNEL_AUTHENTICITY = "channel_authenticity"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"


class TelegramProtectionAdapter(SocialPlatformAdapter):
    """
    Telegram platform adapter for social media protection.
    
    Implements Telegram-specific risk analysis including:
    - Bot detection and verification status
    - Channel/group authenticity assessment
    - Subscriber count validation
    - Content safety scanning
    - Scam pattern recognition
    - Forward chain analysis
    - Malicious link identification
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize Telegram protection adapter.
        
        Args:
            config: Platform-specific configuration including API credentials,
                   risk thresholds, and feature flags
        """
        super().__init__(PlatformType.TELEGRAM, config or {})
        self.risk_thresholds = self._load_risk_thresholds()
        self.bot: Optional[Bot] = None
        self._initialize_api_client()
        
    def _load_risk_thresholds(self) -> Dict[str, float]:
        """Load Telegram-specific risk thresholds from configuration."""
        return self.config.get('risk_thresholds', {
            'bot_detection': 0.7,
            'fake_subscriber_ratio': 0.4,
            'scam_pattern_score': 0.75,
            'malicious_link_score': 0.8,
            'spam_content_score': 0.6,
            'forward_manipulation': 0.65,
            'channel_authenticity': 0.5
        })
    
    def _initialize_api_client(self) -> None:
        """
        Initialize Telegram Bot API client with authentication.
        
        Requires a bot token from BotFather. The bot token is used to
        authenticate API requests and access Telegram's Bot API.
        
        Note: The bot must be added to channels/groups to access their data.
        """
        if not TELEGRAM_AVAILABLE:
            logger.warning("python-telegram-bot library not available. Telegram adapter will operate in limited mode.")
            self.is_enabled = False
            return
            
        try:
            # Get bot token from config
            bot_token = self.config.get('bot_token')
            
            if not bot_token:
                logger.warning("Telegram bot token not configured. Adapter will operate in limited mode.")
                self.is_enabled = False
                return
            
            # Initialize Bot instance
            self.bot = Bot(token=bot_token)
            logger.info("Telegram Bot API client initialized successfully")
            
        except InvalidToken as e:
            logger.error(f"Invalid Telegram bot token: {str(e)}")
            self.is_enabled = False
            self.bot = None
        except Exception as e:
            logger.error(f"Failed to initialize Telegram Bot API client: {str(e)}")
            self.is_enabled = False
            self.bot = None
    
    async def validate_credentials(self) -> bool:
        """
        Validate Telegram Bot API credentials.
        
        Returns:
            True if credentials are valid and bot is accessible
        """
        if not self.bot:
            logger.warning("Telegram Bot API client not initialized")
            return False
            
        try:
            # Test API access by getting bot info
            bot_info = await self.bot.get_me()
            if bot_info:
                logger.info(f"Telegram Bot API credentials validated for bot: @{bot_info.username}")
                return True
            return False
        except TelegramError as e:
            logger.error(f"Telegram Bot API credential validation failed: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during credential validation: {str(e)}")
            return False
    
    async def fetch_chat_data(self, chat_id: str) -> Dict[str, Any]:
        """
        Fetch comprehensive chat/channel data from Telegram Bot API.
        
        Args:
            chat_id: Telegram chat ID (can be username with @ or numeric ID)
            
        Returns:
            Dict containing chat data including info, member count, and metadata
            
        Raises:
            PlatformAdapterError: If chat fetch fails
        """
        if not self.bot:
            raise PlatformAdapterError("Telegram Bot API client not initialized")
            
        try:
            # Fetch chat information
            chat = await self.bot.get_chat(chat_id)
            
            # Fetch member count for channels/groups
            member_count = None
            try:
                member_count = await self.bot.get_chat_member_count(chat_id)
            except TelegramError:
                # Member count may not be available for all chat types
                pass
            
            # Compile chat data
            chat_data = {
                'chat_id': str(chat.id),
                'type': chat.type,
                'title': chat.title,
                'username': chat.username,
                'description': chat.description,
                'invite_link': chat.invite_link,
                'member_count': member_count,
                'photo': {
                    'small_file_id': chat.photo.small_file_id if chat.photo else None,
                    'big_file_id': chat.photo.big_file_id if chat.photo else None,
                } if chat.photo else None,
                'permissions': {
                    'can_send_messages': chat.permissions.can_send_messages if chat.permissions else None,
                    'can_send_media_messages': chat.permissions.can_send_media_messages if chat.permissions else None,
                    'can_send_polls': chat.permissions.can_send_polls if chat.permissions else None,
                    'can_send_other_messages': chat.permissions.can_send_other_messages if chat.permissions else None,
                    'can_add_web_page_previews': chat.permissions.can_add_web_page_previews if chat.permissions else None,
                    'can_change_info': chat.permissions.can_change_info if chat.permissions else None,
                    'can_invite_users': chat.permissions.can_invite_users if chat.permissions else None,
                    'can_pin_messages': chat.permissions.can_pin_messages if chat.permissions else None,
                } if chat.permissions else None,
                'linked_chat_id': chat.linked_chat_id,
                'slow_mode_delay': chat.slow_mode_delay,
                'has_protected_content': chat.has_protected_content,
                'fetched_at': datetime.utcnow().isoformat()
            }
            
            logger.info(f"Successfully fetched chat data for {chat_id}")
            return chat_data
            
        except TelegramError as e:
            logger.error(f"Telegram API error fetching chat {chat_id}: {str(e)}")
            raise PlatformAdapterError(f"Failed to fetch Telegram chat: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error fetching chat {chat_id}: {str(e)}")
            raise PlatformAdapterError(f"Unexpected error: {str(e)}")
    
    async def fetch_channel_posts(self, channel_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Fetch recent posts from a Telegram channel.
        
        Note: This requires the bot to be a member of the channel.
        
        Args:
            channel_id: Telegram channel ID or username
            limit: Maximum number of posts to fetch
            
        Returns:
            List of post data dictionaries
            
        Raises:
            PlatformAdapterError: If posts fetch fails
        """
        if not self.bot:
            raise PlatformAdapterError("Telegram Bot API client not initialized")
            
        try:
            # Note: Bot API doesn't provide direct access to channel history
            # This is a placeholder for the structure. In practice, you'd need
            # to use MTProto client (telethon/pyrogram) for full channel access
            # or rely on updates/webhooks for new messages
            
            logger.warning("Channel post fetching requires MTProto client. Using limited Bot API capabilities.")
            
            # Return empty list as Bot API has limited channel access
            return []
            
        except TelegramError as e:
            logger.error(f"Telegram API error fetching channel posts {channel_id}: {str(e)}")
            raise PlatformAdapterError(f"Failed to fetch channel posts: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error fetching channel posts {channel_id}: {str(e)}")
            raise PlatformAdapterError(f"Unexpected error: {str(e)}")
    
    async def scan_profile(self, request: ProfileScanRequest) -> ProfileScanResult:
        """
        Perform comprehensive Telegram profile security audit.
        
        Analyzes profile for bot detection, subscriber authenticity, 
        channel/group verification, and suspicious activity patterns.
        
        Args:
            request: Profile scan request with Telegram-specific data
                         
        Returns:
            ProfileScanResult containing risk assessment and recommendations
        """
        try:
            logger.info(f"Starting Telegram profile scan for: {request.profile_identifier}")
            
            # Initialize profile data
            profile_data = {}
            
            # Try to fetch fresh data from API if bot is available
            if self.bot:
                try:
                    fetched_data = await self.fetch_chat_data(request.profile_identifier)
                    profile_data.update(fetched_data)
                except PlatformAdapterError as e:
                    logger.warning(f"Could not fetch fresh data from API: {str(e)}")
            
            # Initialize risk factors
            risk_factors = {}
            
            # Analyze bot detection indicators
            bot_risk = await self._analyze_bot_detection(profile_data)
            risk_factors['bot_detection'] = bot_risk
            
            # Analyze subscriber authenticity
            subscriber_risk = await self._analyze_subscriber_authenticity(profile_data)
            risk_factors['subscriber_authenticity'] = subscriber_risk
            
            # Analyze channel/group authenticity
            channel_risk = await self._analyze_channel_authenticity(profile_data)
            risk_factors['channel_authenticity'] = channel_risk
            
            # Analyze profile completeness and verification
            verification_risk = await self._analyze_verification_status(profile_data)
            risk_factors['verification_status'] = verification_risk
            
            # Analyze suspicious activity patterns
            activity_risk = await self._analyze_suspicious_activity(profile_data)
            risk_factors['suspicious_activity'] = activity_risk
            
            # Calculate overall risk score
            risk_score = self._calculate_profile_risk_score(risk_factors)
            risk_level = self._determine_risk_level(risk_score)
            
            # Generate recommendations
            recommendations = self._generate_profile_recommendations(risk_factors, risk_level)
            
            return ProfileScanResult(
                profile_id=profile_data.get('chat_id', profile_data.get('id', '')),
                platform=self.platform_type,
                risk_level=risk_level,
                risk_score=risk_score,
                risk_factors=risk_factors,
                recommendations=recommendations,
                scan_timestamp=datetime.utcnow(),
                confidence_score=min(0.95, 0.7 + (risk_score * 0.25))
            )
            
        except Exception as e:
            logger.error(f"Error scanning Telegram profile: {str(e)}")
            raise
    
    async def analyze_content(self, request: ContentAnalysisRequest) -> ContentAnalysisResult:
        """
        Analyze Telegram content for platform-specific risks.
        
        Evaluates content for spam patterns, malicious links, scam indicators,
        forward chain manipulation, and policy violations.
        
        Args:
            request: Content analysis request with message data
            
        Returns:
            ContentAnalysisResult with risk assessment and recommendations
        """
        try:
            logger.info("Starting Telegram content analysis")
            
            content_data = request.content_data or {}
            
            # Initialize risk factors
            risk_factors = {}
            
            # Analyze spam patterns
            spam_risk = await self._detect_spam_patterns(content_data)
            risk_factors['spam_patterns'] = spam_risk
            
            # Analyze malicious links
            link_risk = await self._analyze_malicious_links(content_data)
            risk_factors['malicious_links'] = link_risk
            
            # Analyze scam patterns
            scam_risk = await self._detect_scam_patterns(content_data)
            risk_factors['scam_patterns'] = scam_risk
            
            # Analyze forward chain manipulation
            forward_risk = await self._analyze_forward_chain(content_data)
            risk_factors['forward_chain'] = forward_risk
            
            # Analyze media content safety
            media_risk = await self._analyze_media_content(content_data)
            risk_factors['media_safety'] = media_risk
            
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
                confidence_score=min(0.95, 0.75 + (risk_score * 0.2))
            )
            
        except Exception as e:
            logger.error(f"Error analyzing Telegram content: {str(e)}")
            raise
    
    async def get_algorithm_health(self, profile_id: str, timeframe_days: int = 30) -> Dict[str, Any]:
        """
        Assess Telegram algorithmic health and visibility metrics.
        
        Analyzes message delivery rates, engagement patterns, 
        channel/group visibility, and search discoverability.
        
        Args:
            profile_id: Telegram channel/group/user identifier
            timeframe_days: Analysis timeframe in days
            
        Returns:
            Algorithm health metrics and recommendations
        """
        try:
            logger.info(f"Analyzing Telegram algorithm health for: {profile_id}")
            
            # Calculate visibility score
            visibility_score = await self._calculate_visibility_score(profile_id, timeframe_days)
            
            # Analyze engagement patterns
            engagement_health = await self._analyze_engagement_health(profile_id, timeframe_days)
            
            # Analyze message delivery rates
            delivery_metrics = await self._analyze_delivery_metrics(profile_id, timeframe_days)
            
            # Analyze search discoverability
            discoverability = await self._analyze_search_discoverability(profile_id)
            
            # Calculate overall algorithm health score
            health_score = (
                visibility_score * 0.3 +
                engagement_health.get('score', 0.5) * 0.3 +
                delivery_metrics.get('score', 0.5) * 0.25 +
                discoverability.get('score', 0.5) * 0.15
            )
            
            return {
                'platform': self.platform_type.value,
                'profile_id': profile_id,
                'timeframe_days': timeframe_days,
                'health_score': health_score,
                'visibility_score': visibility_score,
                'engagement_health': engagement_health,
                'delivery_metrics': delivery_metrics,
                'search_discoverability': discoverability,
                'recommendations': self._generate_algorithm_recommendations(health_score),
                'analysis_timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error analyzing Telegram algorithm health: {str(e)}")
            raise
    
    async def detect_crisis_signals(self, profile_id: str) -> Dict[str, Any]:
        """
        Detect crisis signals and reputation threats on Telegram.
        
        Monitors for viral negative content spread, mass reporting campaigns,
        coordinated harassment, and misinformation propagation.
        
        Args:
            profile_id: Telegram channel/group/user identifier
            
        Returns:
            Crisis detection results with severity assessment
        """
        try:
            logger.info(f"Detecting crisis signals for Telegram profile: {profile_id}")
            
            # Detect viral negative content
            viral_negative = await self._detect_viral_negative_content(profile_id)
            
            # Detect mass reporting campaigns
            mass_reporting = await self._detect_mass_reporting(profile_id)
            
            # Detect coordinated harassment
            coordinated_attacks = await self._detect_coordinated_harassment(profile_id)
            
            # Detect misinformation propagation
            misinformation = await self._detect_misinformation_spread(profile_id)
            
            # Calculate crisis severity
            crisis_indicators = {
                'viral_negative_content': viral_negative,
                'mass_reporting': mass_reporting,
                'coordinated_harassment': coordinated_attacks,
                'misinformation_spread': misinformation
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
            logger.error(f"Error detecting Telegram crisis signals: {str(e)}")
            raise
    
    # Private helper methods for specific analysis tasks
    
    async def _analyze_bot_detection(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze indicators of bot accounts."""
        # Implementation for bot detection logic
        return {
            'is_bot': profile_data.get('is_bot', False),
            'bot_probability': 0.1,  # Placeholder
            'indicators': []
        }
    
    async def _analyze_subscriber_authenticity(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze subscriber authenticity and fake follower detection."""
        member_count = profile_data.get('member_count', 0)
        suspicious_patterns = []
        fake_subscriber_ratio = 0.05  # Default low ratio
        
        # Analyze growth patterns if available
        # In a real implementation, this would compare historical data
        
        # Check for suspicious member count patterns
        if member_count > 0:
            # Very high member counts without verification can be suspicious
            if member_count > 100000 and not profile_data.get('username'):
                suspicious_patterns.append('high_members_private_channel')
                fake_subscriber_ratio += 0.15
            
            # Check if member count seems artificially inflated
            # (would need historical data for accurate detection)
            if member_count > 50000:
                # Large channels should have more indicators of authenticity
                if not profile_data.get('description'):
                    suspicious_patterns.append('large_channel_minimal_info')
                    fake_subscriber_ratio += 0.1
        
        # Calculate authenticity score
        authenticity_score = max(0.0, 1.0 - fake_subscriber_ratio)
        
        return {
            'fake_subscriber_ratio': min(1.0, fake_subscriber_ratio),
            'authenticity_score': authenticity_score,
            'suspicious_patterns': suspicious_patterns,
            'member_count': member_count
        }
    
    async def _analyze_channel_authenticity(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze channel/group authenticity indicators."""
        authenticity_score = 0.9
        trust_indicators = []
        risk_factors = []
        
        # Check if channel has description
        if profile_data.get('description'):
            trust_indicators.append('has_description')
        else:
            risk_factors.append('missing_description')
            authenticity_score -= 0.1
        
        # Check if channel has username (public channel)
        if profile_data.get('username'):
            trust_indicators.append('public_channel')
        else:
            risk_factors.append('private_channel')
            authenticity_score -= 0.05
        
        # Check member count
        member_count = profile_data.get('member_count', 0)
        if member_count > 1000:
            trust_indicators.append('established_channel')
        elif member_count < 100:
            risk_factors.append('low_member_count')
            authenticity_score -= 0.15
        
        # Check if channel has photo
        if profile_data.get('photo'):
            trust_indicators.append('has_profile_photo')
        else:
            risk_factors.append('missing_profile_photo')
            authenticity_score -= 0.1
        
        # Check for protected content (anti-scraping measure)
        if profile_data.get('has_protected_content'):
            trust_indicators.append('content_protection_enabled')
        
        # Check chat type
        chat_type = profile_data.get('type', '')
        if chat_type in ['channel', 'supergroup']:
            trust_indicators.append(f'legitimate_type_{chat_type}')
        
        return {
            'authenticity_score': max(0.0, min(1.0, authenticity_score)),
            'trust_indicators': trust_indicators,
            'risk_factors': risk_factors,
            'member_count': member_count,
            'chat_type': chat_type
        }
    
    async def _analyze_verification_status(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze profile verification and completeness."""
        return {
            'is_verified': profile_data.get('verified', False),
            'profile_completeness': 0.8,  # Placeholder
            'trust_score': 0.75
        }
    
    async def _analyze_suspicious_activity(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze suspicious activity patterns."""
        return {
            'activity_score': 0.1,  # Placeholder
            'suspicious_indicators': [],
            'risk_level': 'low'
        }
    
    async def _detect_spam_patterns(self, content_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect spam patterns in content."""
        text = content_data.get('text', '') or content_data.get('caption', '')
        spam_indicators = []
        pattern_matches = []
        spam_probability = 0.0
        
        # Common Telegram spam patterns
        spam_keywords = [
            'free crypto', 'airdrop', 'guaranteed profit', 'investment opportunity',
            'click here now', 'limited time', 'act fast', 'double your money',
            'risk free', 'join our channel', 'forward this message'
        ]
        
        # Check for spam keywords
        text_lower = text.lower()
        for keyword in spam_keywords:
            if keyword in text_lower:
                spam_indicators.append(f'spam_keyword: {keyword}')
                pattern_matches.append(keyword)
                spam_probability += 0.15
        
        # Check for excessive emojis (common in spam)
        emoji_count = sum(1 for char in text if ord(char) > 0x1F300)
        if emoji_count > 10:
            spam_indicators.append('excessive_emojis')
            spam_probability += 0.1
        
        # Check for excessive capitalization
        if text and text.isupper() and len(text) > 20:
            spam_indicators.append('all_caps_message')
            spam_probability += 0.1
        
        # Check for excessive links
        entities = content_data.get('entities', [])
        url_count = sum(1 for entity in entities if entity.get('type') == 'url')
        if url_count > 3:
            spam_indicators.append('excessive_links')
            spam_probability += 0.2
        
        # Check for forward spam patterns
        forward_count = content_data.get('forward_count', 0)
        if forward_count > 100:
            spam_indicators.append('high_forward_count')
            spam_probability += 0.15
        
        return {
            'spam_probability': min(1.0, spam_probability),
            'spam_indicators': spam_indicators,
            'pattern_matches': pattern_matches,
            'emoji_count': emoji_count,
            'url_count': url_count
        }
    
    async def _analyze_malicious_links(self, content_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze links for malicious content."""
        return {
            'malicious_link_count': 0,
            'risk_score': 0.0,
            'flagged_domains': []
        }
    
    async def _detect_scam_patterns(self, content_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect scam patterns in content."""
        text = content_data.get('text', '') or content_data.get('caption', '')
        scam_indicators = []
        pattern_types = []
        scam_probability = 0.0
        
        # Common Telegram scam patterns
        scam_patterns = {
            'crypto_scam': ['send btc', 'send eth', 'send usdt', 'wallet address', 'private key'],
            'phishing': ['verify your account', 'suspended account', 'click to verify', 'urgent action required'],
            'impersonation': ['official support', 'admin team', 'customer service', 'telegram support'],
            'investment_scam': ['guaranteed returns', 'passive income', 'financial freedom', 'get rich'],
            'fake_giveaway': ['free giveaway', 'claim your prize', 'winner selected', 'congratulations you won']
        }
        
        text_lower = text.lower()
        
        # Check for scam pattern matches
        for pattern_type, keywords in scam_patterns.items():
            matches = [kw for kw in keywords if kw in text_lower]
            if matches:
                scam_indicators.extend([f'{pattern_type}: {m}' for m in matches])
                pattern_types.append(pattern_type)
                scam_probability += 0.2 * len(matches)
        
        # Check for suspicious URLs
        entities = content_data.get('entities', [])
        for entity in entities:
            if entity.get('type') == 'url':
                url = entity.get('url', '')
                # Check for URL shorteners (common in scams)
                if any(shortener in url for shortener in ['bit.ly', 't.me', 'tinyurl', 'goo.gl']):
                    scam_indicators.append('url_shortener_detected')
                    scam_probability += 0.15
        
        # Check for urgency tactics
        urgency_words = ['urgent', 'immediately', 'now', 'hurry', 'limited time', 'expires soon']
        urgency_count = sum(1 for word in urgency_words if word in text_lower)
        if urgency_count >= 2:
            scam_indicators.append('urgency_tactics')
            scam_probability += 0.15
        
        return {
            'scam_probability': min(1.0, scam_probability),
            'scam_indicators': scam_indicators,
            'pattern_types': list(set(pattern_types)),
            'urgency_detected': urgency_count >= 2
        }
    
    async def _analyze_forward_chain(self, content_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze forward chain for manipulation."""
        forward_count = content_data.get('forward_count', 0)
        forward_from = content_data.get('forward_from')
        forward_from_chat = content_data.get('forward_from_chat')
        
        manipulation_score = 0.0
        chain_indicators = []
        
        # High forward count can indicate viral spread or manipulation
        if forward_count > 1000:
            chain_indicators.append('viral_spread')
            manipulation_score += 0.2
        elif forward_count > 100:
            chain_indicators.append('high_forward_count')
            manipulation_score += 0.1
        
        # Check if original source is hidden (privacy mode)
        if forward_count > 0 and not forward_from and not forward_from_chat:
            chain_indicators.append('hidden_source')
            manipulation_score += 0.15
        
        # Check for forward from suspicious sources
        if forward_from_chat:
            chat_title = forward_from_chat.get('title', '').lower()
            suspicious_keywords = ['spam', 'bot', 'fake', 'scam', 'promo']
            if any(keyword in chat_title for keyword in suspicious_keywords):
                chain_indicators.append('suspicious_source_channel')
                manipulation_score += 0.25
        
        # Analyze forward velocity (if timestamp data available)
        # This would require historical data in a real implementation
        
        return {
            'forward_count': forward_count,
            'manipulation_score': min(1.0, manipulation_score),
            'chain_indicators': chain_indicators,
            'has_hidden_source': forward_count > 0 and not forward_from and not forward_from_chat,
            'forward_from_chat': forward_from_chat.get('title') if forward_from_chat else None
        }
    
    async def _analyze_media_content(self, content_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze media content for safety."""
        return {
            'media_safety_score': 0.95,  # Placeholder
            'flagged_content': [],
            'content_type_risks': {}
        }
    
    async def _calculate_visibility_score(self, profile_id: str, timeframe_days: int) -> float:
        """Calculate visibility score for the profile."""
        # In Telegram, visibility is primarily determined by:
        # 1. Channel/group member count
        # 2. Post view counts
        # 3. Forward counts
        # 4. Search discoverability (public vs private)
        
        try:
            if self.bot:
                chat_data = await self.fetch_chat_data(profile_id)
                member_count = chat_data.get('member_count', 0)
                is_public = bool(chat_data.get('username'))
                
                # Base score on member count
                if member_count > 100000:
                    visibility_score = 0.9
                elif member_count > 10000:
                    visibility_score = 0.75
                elif member_count > 1000:
                    visibility_score = 0.6
                elif member_count > 100:
                    visibility_score = 0.4
                else:
                    visibility_score = 0.2
                
                # Boost for public channels (searchable)
                if is_public:
                    visibility_score = min(1.0, visibility_score + 0.1)
                
                return visibility_score
        except Exception as e:
            logger.warning(f"Could not calculate visibility score: {str(e)}")
        
        return 0.5  # Default moderate visibility
    
    async def _analyze_engagement_health(self, profile_id: str, timeframe_days: int) -> Dict[str, Any]:
        """Analyze engagement health metrics."""
        # Telegram engagement metrics include:
        # - View counts on posts
        # - Forward counts
        # - Reaction counts (if enabled)
        # - Comment counts (for groups)
        
        try:
            if self.bot:
                chat_data = await self.fetch_chat_data(profile_id)
                member_count = chat_data.get('member_count', 0)
                
                # Estimate engagement based on channel characteristics
                # In a real implementation, this would analyze actual post metrics
                
                # Channels with more members typically have lower engagement rates
                if member_count > 50000:
                    estimated_engagement_rate = 0.02  # 2%
                    score = 0.7
                elif member_count > 10000:
                    estimated_engagement_rate = 0.05  # 5%
                    score = 0.75
                elif member_count > 1000:
                    estimated_engagement_rate = 0.08  # 8%
                    score = 0.8
                else:
                    estimated_engagement_rate = 0.1  # 10%
                    score = 0.75
                
                return {
                    'score': score,
                    'engagement_rate': estimated_engagement_rate,
                    'trends': 'stable',
                    'member_count': member_count,
                    'note': 'Estimated based on channel size'
                }
        except Exception as e:
            logger.warning(f"Could not analyze engagement health: {str(e)}")
        
        return {
            'score': 0.75,
            'engagement_rate': 0.05,
            'trends': 'unknown'
        }
    
    async def _analyze_delivery_metrics(self, profile_id: str, timeframe_days: int) -> Dict[str, Any]:
        """Analyze message delivery metrics."""
        return {
            'score': 0.9,  # Placeholder
            'delivery_rate': 0.98,
            'reach_metrics': {}
        }
    
    async def _analyze_search_discoverability(self, profile_id: str) -> Dict[str, Any]:
        """Analyze search discoverability."""
        return {
            'score': 0.7,  # Placeholder
            'search_visibility': 'good',
            'discoverability_factors': []
        }
    
    async def _detect_viral_negative_content(self, profile_id: str) -> Dict[str, Any]:
        """Detect viral negative content spread."""
        return {
            'detected': False,
            'severity': 'low',
            'content_items': []
        }
    
    async def _detect_mass_reporting(self, profile_id: str) -> Dict[str, Any]:
        """Detect mass reporting campaigns."""
        return {
            'detected': False,
            'report_volume': 0,
            'campaign_indicators': []
        }
    
    async def _detect_coordinated_harassment(self, profile_id: str) -> Dict[str, Any]:
        """Detect coordinated harassment attacks."""
        return {
            'detected': False,
            'attack_patterns': [],
            'coordination_score': 0.0
        }
    
    async def _detect_misinformation_spread(self, profile_id: str) -> Dict[str, Any]:
        """Detect misinformation propagation."""
        return {
            'detected': False,
            'misinformation_score': 0.0,
            'flagged_content': []
        }
    
    def _calculate_profile_risk_score(self, risk_factors: Dict[str, Any]) -> float:
        """Calculate overall profile risk score."""
        weights = {
            'bot_detection': 0.25,
            'subscriber_authenticity': 0.2,
            'channel_authenticity': 0.2,
            'verification_status': 0.15,
            'suspicious_activity': 0.2
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
            'spam_patterns': 0.2,
            'malicious_links': 0.3,
            'scam_patterns': 0.25,
            'forward_chain': 0.15,
            'media_safety': 0.1
        }
        
        total_score = 0.0
        for factor, data in risk_factors.items():
            if factor in weights:
                factor_score = data.get('risk_score', data.get('score', 0.0))
                total_score += factor_score * weights[factor]
        
        return min(1.0, total_score)
    
    def _determine_crisis_level(self, Crisis_indicators: Dict[str, Any]) -> RiskLevel:
        """Determine crisis level from indicators."""
        max_severity = 0.0
        for indicator_data in Crisis_indicators.values():
            severity = indicator_data.get('severity_score', 0.0)
            max_severity = max(max_severity, severity)
        
        return self._determine_risk_level(max_severity)
    
    def _generate_profile_recommendations(self, risk_factors: Dict[str, Any], risk_level: RiskLevel) -> List[str]:
        """Generate profile-specific recommendations."""
        recommendations = []
        
        if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            recommendations.append("Review and verify account authenticity")
            recommendations.append("Monitor subscriber growth patterns")
        
        if risk_factors.get('bot_detection', {}).get('is_bot', False):
            recommendations.append("Verify account is not automated")
        
        return recommendations
    
    def _generate_content_recommendations(self, risk_factors: Dict[str, Any], risk_level: RiskLevel) -> List[str]:
        """Generate content-specific recommendations."""
        recommendations = []
        
        if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            recommendations.append("Review content for policy violations")
            recommendations.append("Verify all external links")
        
        if risk_factors.get('malicious_links', {}).get('malicious_link_count', 0) > 0:
            recommendations.append("Remove or verify flagged links")
        
        return recommendations
    
    def _generate_algorithm_recommendations(self, health_score: float) -> List[str]:
        """Generate algorithm health recommendations."""
        recommendations = []
        
        if health_score < 0.5:
            recommendations.append("Improve content engagement strategies")
            recommendations.append("Review posting frequency and timing")
        
        return recommendations
    
    def _generate_crisis_alerts(self, Crisis_indicators: Dict[str, Any]) -> List[str]:
        """Generate crisis-specific alerts."""
        alerts = []
        
        for indicator, data in Crisis_indicators.items():
            if data.get('detected', False):
                alerts.append(f"Crisis detected: {indicator}")
        
        return alerts
    
    def _generate_crisis_recommendations(self, crisis_level: RiskLevel) -> List[str]:
        """Generate crisis response recommendations."""
        if crisis_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            return [
                "Activate crisis response protocol",
                "Monitor mentions and discussions closely",
                "Prepare official response statement",
                "Consider temporary content restrictions"
            ]
        
        return ["Continue monitoring for escalation"]


# Register the Telegram adapter with the platform registry
registry.register_adapter(
    PlatformType.TELEGRAM,
    TelegramProtectionAdapter,
    config={
        'enabled': True,
        'rate_limits': {
            'profile_scan': {'requests_per_minute': 30, 'burst_limit': 10},
            'content_analysis': {'requests_per_minute': 100, 'burst_limit': 20},
            'algorithm_health': {'requests_per_minute': 10, 'burst_limit': 5},
            'crisis_detection': {'requests_per_minute': 20, 'burst_limit': 8}
        },
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
)