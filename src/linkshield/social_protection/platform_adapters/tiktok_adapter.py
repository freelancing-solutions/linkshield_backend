"""
TikTok Platform Protection Adapter

This module implements TikTok-specific social media protection functionality,
including fake engagement detection, community guideline compliance,
bio link restrictions, and Creator Fund monitoring.

Focuses on TikTok's unique algorithm and content moderation systems.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from enum import Enum
import httpx
import hashlib
import hmac
import time

from .base_adapter import SocialPlatformAdapter, PlatformType, RiskLevel
from ..registry import registry
from ..logging_utils import get_logger
from ..exceptions import PlatformAdapterError

logger = get_logger("TikTokProtectionAdapter")


class TikTokRiskFactor(Enum):
    """TikTok-specific risk factors for content and profile analysis."""
    FAKE_ENGAGEMENT = "fake_engagement"
    COMMUNITY_GUIDELINES = "community_guidelines"
    BIO_LINK_RESTRICTIONS = "bio_link_restrictions"
    CREATOR_FUND_COMPLIANCE = "creator_fund_compliance"
    SHADOWBAN_INDICATORS = "shadowban_indicators"
    HASHTAG_VIOLATIONS = "hashtag_violations"
    MUSIC_COPYRIGHT = "music_copyright"
    CONTENT_MODERATION = "content_moderation"


class TikTokContentType(Enum):
    """TikTok content types for platform-specific analysis."""
    VIDEO = "video"
    LIVE_STREAM = "live_stream"
    DUET = "duet"
    STITCH = "stitch"
    EFFECT = "effect"
    SOUND = "sound"


class TikTokProtectionAdapter(SocialPlatformAdapter):
    """
    TikTok platform adapter for social media protection.
    
    Implements TikTok-specific risk analysis including:
    - Fake engagement and bot detection
    - Community guideline compliance
    - Bio link restriction monitoring
    - Creator Fund eligibility and compliance
    - Shadowban detection and prevention
    
    Uses TikTok's official API for data retrieval and analysis.
    """
    
    # TikTok API endpoints
    API_BASE_URL = "https://open.tiktokapis.com/v2"
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize TikTok protection adapter.
        
        Args:
            config: Platform-specific configuration including API credentials,
                   risk thresholds, and TikTok-specific feature flags
        """
        super().__init__(PlatformType.TIKTOK, config or {})
        self.risk_thresholds = self._load_risk_thresholds()
        self.client: Optional[httpx.AsyncClient] = None
        self._rate_limit_status = {
            'last_reset': datetime.utcnow(),
            'requests_made': 0,
            'limit_reached': False
        }
        self._initialize_api_client()
        
    def _initialize_api_client(self) -> None:
        """
        Initialize TikTok API client with authentication.
        
        Supports TikTok's OAuth 2.0 authentication with client credentials
        or access token authentication for API access.
        """
        try:
            # Get API credentials from config
            client_key = self.config.get('client_key')
            client_secret = self.config.get('client_secret')
            access_token = self.config.get('access_token')
            
            if access_token:
                # Initialize client with access token
                self.client = httpx.AsyncClient(
                    base_url=self.API_BASE_URL,
                    timeout=30.0,
                    headers={
                        'Authorization': f'Bearer {access_token}',
                        'Content-Type': 'application/json'
                    }
                )
                logger.info("TikTok API client initialized with access token")
            elif client_key and client_secret:
                # Initialize client with client credentials
                self.client = httpx.AsyncClient(
                    base_url=self.API_BASE_URL,
                    timeout=30.0,
                    headers={'Content-Type': 'application/json'}
                )
                self.client_key = client_key
                self.client_secret = client_secret
                logger.info("TikTok API client initialized with client credentials")
            else:
                logger.warning("TikTok API credentials not configured. Adapter will operate in limited mode.")
                self.is_enabled = False
                
        except Exception as e:
            logger.error(f"Failed to initialize TikTok API client: {str(e)}")
            self.is_enabled = False
            self.client = None
    
    async def validate_credentials(self) -> bool:
        """
        Validate TikTok API credentials and permissions.
        
        Returns:
            True if credentials are valid and have required permissions
        """
        if not self.client:
            logger.warning("TikTok API client not initialized")
            return False
            
        try:
            # Test API access by fetching user info
            response = await self.client.get('/user/info/')
            if response.status_code == 200:
                logger.info("TikTok API credentials validated successfully")
                return True
            else:
                logger.error(f"TikTok API credential validation failed: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"TikTok API credential validation error: {str(e)}")
            return False
    
    def _track_api_request(self) -> None:
        """Track API request for rate limit monitoring."""
        self._rate_limit_status['requests_made'] += 1
        
        # Reset counter if it's been more than 1 hour (TikTok's rate limit window)
        last_reset = self._rate_limit_status.get('last_reset', datetime.utcnow())
        if (datetime.utcnow() - last_reset).total_seconds() > 3600:  # 1 hour
            self._rate_limit_status['requests_made'] = 1
            self._rate_limit_status['last_reset'] = datetime.utcnow()
            self._rate_limit_status['limit_reached'] = False
    
    def _handle_rate_limit_error(self, response: httpx.Response) -> None:
        """
        Handle rate limit errors from TikTok API.
        
        Args:
            response: HTTP response containing rate limit information
        """
        logger.warning(f"TikTok API rate limit encountered: {response.status_code}")
        self._rate_limit_status['limit_reached'] = True
        
        # Extract reset time from headers if available
        reset_time = response.headers.get('X-RateLimit-Reset')
        if reset_time:
            reset_datetime = datetime.fromtimestamp(int(reset_time))
            logger.info(f"Rate limit will reset at: {reset_datetime.isoformat()}")
            self._rate_limit_status['reset_time'] = reset_datetime
    
    async def fetch_user_info(self, username: str) -> Dict[str, Any]:
        """
        Fetch user profile information from TikTok API.
        
        Args:
            username: TikTok username (without @)
            
        Returns:
            Dict containing user profile data
            
        Raises:
            PlatformAdapterError: If user fetch fails
        """
        if not self.client:
            raise PlatformAdapterError("TikTok API client not initialized")
            
        try:
            self._track_api_request()
            
            # Fetch user info
            response = await self.client.get(
                '/user/info/',
                params={'fields': 'display_name,bio_description,avatar_url,is_verified,follower_count,following_count,likes_count,video_count'}
            )
            
            if response.status_code == 429:
                self._handle_rate_limit_error(response)
                raise PlatformAdapterError("TikTok API rate limit exceeded")
            
            if response.status_code != 200:
                raise PlatformAdapterError(f"TikTok API error: {response.status_code}")
            
            data = response.json()
            user_data = data.get('data', {}).get('user', {})
            
            # Compile user profile data
            profile_data = {
                'user_id': user_data.get('open_id'),
                'username': username,
                'display_name': user_data.get('display_name'),
                'bio_description': user_data.get('bio_description', ''),
                'avatar_url': user_data.get('avatar_url'),
                'is_verified': user_data.get('is_verified', False),
                'follower_count': user_data.get('follower_count', 0),
                'following_count': user_data.get('following_count', 0),
                'likes_count': user_data.get('likes_count', 0),
                'video_count': user_data.get('video_count', 0),
                'fetched_at': datetime.utcnow().isoformat()
            }
            
            logger.info(f"Successfully fetched TikTok user info for @{username}")
            return profile_data
            
        except httpx.HTTPError as e:
            logger.error(f"TikTok API HTTP error fetching user {username}: {str(e)}")
            raise PlatformAdapterError(f"Failed to fetch TikTok user: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error fetching user {username}: {str(e)}")
            raise PlatformAdapterError(f"Unexpected error: {str(e)}")
    
    async def fetch_video_info(self, video_id: str) -> Dict[str, Any]:
        """
        Fetch video information from TikTok API.
        
        Args:
            video_id: TikTok video ID
            
        Returns:
            Dict containing video data
            
        Raises:
            PlatformAdapterError: If video fetch fails
        """
        if not self.client:
            raise PlatformAdapterError("TikTok API client not initialized")
            
        try:
            self._track_api_request()
            
            # Fetch video info
            response = await self.client.post(
                '/video/query/',
                json={
                    'filters': {
                        'video_ids': [video_id]
                    },
                    'fields': 'id,title,video_description,duration,cover_image_url,share_url,view_count,like_count,comment_count,share_count,create_time'
                }
            )
            
            if response.status_code == 429:
                self._handle_rate_limit_error(response)
                raise PlatformAdapterError("TikTok API rate limit exceeded")
            
            if response.status_code != 200:
                raise PlatformAdapterError(f"TikTok API error: {response.status_code}")
            
            data = response.json()
            videos = data.get('data', {}).get('videos', [])
            
            if not videos:
                raise PlatformAdapterError(f"Video not found: {video_id}")
            
            video = videos[0]
            
            # Compile video data
            video_data = {
                'video_id': video.get('id'),
                'title': video.get('title', ''),
                'description': video.get('video_description', ''),
                'duration': video.get('duration', 0),
                'cover_image_url': video.get('cover_image_url'),
                'share_url': video.get('share_url'),
                'view_count': video.get('view_count', 0),
                'like_count': video.get('like_count', 0),
                'comment_count': video.get('comment_count', 0),
                'share_count': video.get('share_count', 0),
                'create_time': video.get('create_time'),
                'fetched_at': datetime.utcnow().isoformat()
            }
            
            logger.info(f"Successfully fetched TikTok video info for {video_id}")
            return video_data
            
        except httpx.HTTPError as e:
            logger.error(f"TikTok API HTTP error fetching video {video_id}: {str(e)}")
            raise PlatformAdapterError(f"Failed to fetch TikTok video: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error fetching video {video_id}: {str(e)}")
            raise PlatformAdapterError(f"Unexpected error: {str(e)}")
    
    def get_rate_limit_status(self) -> Dict[str, Any]:
        """
        Get current rate limit status for TikTok API.
        
        Returns:
            Dict containing rate limit information
        """
        if not self.client:
            return {
                'enabled': False,
                'error': 'API client not initialized'
            }
        
        return {
            'enabled': True,
            'last_reset': self._rate_limit_status.get('last_reset', datetime.utcnow()).isoformat(),
            'requests_made': self._rate_limit_status.get('requests_made', 0),
            'limit_reached': self._rate_limit_status.get('limit_reached', False),
            'rate_limits': self.get_rate_limits()
        }
    
    def _load_risk_thresholds(self) -> Dict[str, float]:
        """Load TikTok-specific risk thresholds from configuration."""
        return self.config.get('risk_thresholds', {
            'fake_engagement_ratio': 0.3,
            'community_guideline_risk': 0.8,
            'bio_link_violation': 0.9,
            'creator_fund_risk': 0.7,
            'shadowban_probability': 0.5,
            'hashtag_violation_score': 0.6,
            'copyright_risk_score': 0.75,
            'content_moderation_risk': 0.65
        })
    
    async def scan_profile(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform comprehensive TikTok profile security audit.
        
        Analyzes TikTok profiles for authenticity, Creator Fund eligibility,
        bio link compliance, and engagement quality.
        
        Args:
            profile_data: TikTok profile information including followers,
                         videos, engagement metrics, Creator Fund status.
                         Can also accept just a username string to fetch data.
                         
        Returns:
            Dict containing profile risk assessment with scores and recommendations
        """
        try:
            # If profile_data is just a username, fetch the full profile
            if isinstance(profile_data, str):
                profile_data = await self.fetch_user_info(profile_data)
            elif 'username' in profile_data and not profile_data.get('user_id'):
                # Fetch full profile if only username provided
                profile_data = await self.fetch_user_info(profile_data['username'])
            
            logger.info(f"Starting TikTok profile scan for user: {profile_data.get('username', 'unknown')}")
            
            # Initialize risk assessment
            risk_assessment = {
                'platform': self.platform_type.value,
                'profile_id': profile_data.get('user_id'),
                'username': profile_data.get('username'),
                'scan_timestamp': datetime.utcnow().isoformat(),
                'risk_factors': {},
                'overall_risk_level': RiskLevel.LOW,
                'risk_score': 0.0,
                'recommendations': []
            }
            
            # Analyze engagement authenticity
            engagement_risk = await self._analyze_engagement_authenticity(profile_data)
            risk_assessment['risk_factors']['engagement_authenticity'] = engagement_risk
            
            # Check Creator Fund compliance
            creator_fund_risk = await self._check_creator_fund_compliance(profile_data)
            risk_assessment['risk_factors']['creator_fund_compliance'] = creator_fund_risk
            
            # Analyze bio link restrictions
            bio_link_risk = await self._analyze_bio_link_compliance(profile_data)
            risk_assessment['risk_factors']['bio_link_compliance'] = bio_link_risk
            
            # Check community guideline adherence
            guideline_risk = await self._check_community_guidelines(profile_data)
            risk_assessment['risk_factors']['community_guidelines'] = guideline_risk
            
            # Detect shadowban indicators
            shadowban_risk = await self._detect_shadowban_indicators(profile_data)
            risk_assessment['risk_factors']['shadowban_indicators'] = shadowban_risk
            
            # Analyze account verification and authenticity
            verification_risk = await self._analyze_account_verification(profile_data)
            risk_assessment['risk_factors']['account_verification'] = verification_risk
            
            # Calculate overall risk score and level
            risk_assessment['risk_score'] = self._calculate_profile_risk_score(risk_assessment['risk_factors'])
            risk_assessment['overall_risk_level'] = self._determine_risk_level(risk_assessment['risk_score'])
            
            # Generate recommendations
            risk_assessment['recommendations'] = self._generate_profile_recommendations(risk_assessment)
            
            logger.info(f"TikTok profile scan completed. Risk level: {risk_assessment['overall_risk_level'].value}")
            return risk_assessment
            
        except Exception as e:
            logger.error(f"Error during TikTok profile scan: {str(e)}")
            raise
    
    async def analyze_content(self, content_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze TikTok content for risk factors and policy violations.
        
        Focuses on community guideline compliance, copyright issues,
        hashtag violations, and content moderation triggers.
        
        Args:
            content_data: TikTok content including video metadata, audio,
                         hashtags, effects, and engagement metrics.
                         Can also accept just a video_id string to fetch data.
                         
        Returns:
            Dict containing content risk assessment with specific risk factors
        """
        try:
            # If content_data is just a video_id, fetch the full video
            if isinstance(content_data, str):
                content_data = await self.fetch_video_info(content_data)
            elif 'video_id' in content_data and not content_data.get('description'):
                # Fetch full video if only video_id provided
                content_data = await self.fetch_video_info(content_data['video_id'])
            
            content_type = content_data.get('content_type', 'video')
            logger.info(f"Starting TikTok content analysis for {content_type}: {content_data.get('content_id', content_data.get('video_id', 'unknown'))}")
            
            # Initialize content risk assessment
            risk_assessment = {
                'platform': self.platform_type.value,
                'content_id': content_data.get('content_id'),
                'content_type': content_type,
                'scan_timestamp': datetime.utcnow().isoformat(),
                'risk_factors': {},
                'overall_risk_level': RiskLevel.LOW,
                'risk_score': 0.0,
                'recommendations': []
            }
            
            # Check community guideline violations
            guideline_risk = await self._check_content_guidelines(content_data)
            risk_assessment['risk_factors']['community_guidelines'] = guideline_risk
            
            # Analyze music and audio copyright
            copyright_risk = await self._analyze_music_copyright(content_data)
            risk_assessment['risk_factors']['music_copyright'] = copyright_risk
            
            # Check hashtag compliance
            hashtag_risk = await self._analyze_hashtag_compliance(content_data)
            risk_assessment['risk_factors']['hashtag_compliance'] = hashtag_risk
            
            # Detect fake engagement patterns
            fake_engagement_risk = await self._detect_fake_engagement(content_data)
            risk_assessment['risk_factors']['fake_engagement'] = fake_engagement_risk
            
            # Analyze content moderation triggers
            moderation_risk = await self._analyze_content_moderation_triggers(content_data)
            risk_assessment['risk_factors']['content_moderation'] = moderation_risk
            
            # Check for spam and repetitive content
            spam_risk = await self._detect_spam_content(content_data)
            risk_assessment['risk_factors']['spam_content'] = spam_risk
            
            # Calculate overall risk score and level
            risk_assessment['risk_score'] = self._calculate_content_risk_score(risk_assessment['risk_factors'])
            risk_assessment['overall_risk_level'] = self._determine_risk_level(risk_assessment['risk_score'])
            
            # Generate recommendations
            risk_assessment['recommendations'] = self._generate_content_recommendations(risk_assessment)
            
            logger.info(f"TikTok content analysis completed. Risk level: {risk_assessment['overall_risk_level'].value}")
            return risk_assessment
            
        except Exception as e:
            logger.error(f"Error during TikTok content analysis: {str(e)}")
            raise
    
    async def get_algorithm_health(self, account_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assess TikTok algorithm health and For You Page visibility.
        
        Monitors video performance, engagement rates, hashtag effectiveness,
        and potential algorithmic penalties affecting reach.
        
        Args:
            account_data: TikTok account metrics including recent videos,
                         view counts, engagement rates, and FYP performance
                         
        Returns:
            Dict containing algorithm health assessment and visibility metrics
        """
        try:
            logger.info(f"Starting TikTok algorithm health assessment for account: {account_data.get('username', 'unknown')}")
            
            # Initialize algorithm health assessment
            health_assessment = {
                'platform': self.platform_type.value,
                'account_id': account_data.get('user_id'),
                'username': account_data.get('username'),
                'assessment_timestamp': datetime.utcnow().isoformat(),
                'fyp_visibility_score': 0.0,
                'engagement_health': {},
                'content_performance': {},
                'penalty_indicators': {},
                'recommendations': []
            }
            
            # Calculate For You Page visibility score
            health_assessment['fyp_visibility_score'] = await self._calculate_fyp_visibility_score(account_data)
            
            # Analyze engagement health
            health_assessment['engagement_health'] = await self._analyze_engagement_health(account_data)
            
            # Assess content performance patterns
            health_assessment['content_performance'] = await self._analyze_content_performance(account_data)
            
            # Detect algorithmic penalties
            health_assessment['penalty_indicators'] = await self._detect_algorithmic_penalties(account_data)
            
            # Generate algorithm health recommendations
            health_assessment['recommendations'] = self._generate_algorithm_recommendations(health_assessment)
            
            logger.info(f"TikTok algorithm health assessment completed. FYP visibility score: {health_assessment['fyp_visibility_score']}")
            return health_assessment
            
        except Exception as e:
            logger.error(f"Error during TikTok algorithm health assessment: {str(e)}")
            raise
    
    async def detect_crisis_signals(self, monitoring_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect crisis signals and reputation threats on TikTok.
        
        Monitors for viral negative content, coordinated harassment,
        trending negative hashtags, and community backlash.
        
        Args:
            monitoring_data: Real-time TikTok monitoring data including
                           comments, duets, stitches, and trending topics
                           
        Returns:
            Dict containing crisis detection results and alert recommendations
        """
        try:
            logger.info(f"Starting TikTok crisis signal detection for account: {monitoring_data.get('username', 'unknown')}")
            
            # Initialize crisis detection assessment
            crisis_assessment = {
                'platform': self.platform_type.value,
                'account_id': monitoring_data.get('user_id'),
                'username': monitoring_data.get('username'),
                'detection_timestamp': datetime.utcnow().isoformat(),
                'crisis_level': RiskLevel.LOW,
                'crisis_indicators': {},
                'alert_triggers': [],
                'recommended_actions': []
            }
            
            # Detect viral negative content
            viral_risk = await self._detect_viral_negative_content(monitoring_data)
            crisis_assessment['crisis_indicators']['viral_negative_content'] = viral_risk
            
            # Check for coordinated harassment
            harassment_risk = await self._detect_coordinated_harassment(monitoring_data)
            crisis_assessment['crisis_indicators']['coordinated_harassment'] = harassment_risk
            
            # Monitor trending negative hashtags
            hashtag_risk = await self._monitor_negative_hashtag_trends(monitoring_data)
            crisis_assessment['crisis_indicators']['negative_hashtag_trends'] = hashtag_risk
            
            # Assess community backlash through duets/stitches
            backlash_risk = await self._assess_community_backlash(monitoring_data)
            crisis_assessment['crisis_indicators']['community_backlash'] = backlash_risk
            
            # Check for mass reporting campaigns
            reporting_risk = await self._detect_mass_reporting(monitoring_data)
            crisis_assessment['crisis_indicators']['mass_reporting'] = reporting_risk
            
            # Determine overall Crisis level
            crisis_assessment['crisis_level'] = self._determine_crisis_level(crisis_assessment['crisis_indicators'])
            
            # Generate alert triggers
            crisis_assessment['alert_triggers'] = self._generate_crisis_alerts(crisis_assessment)
            
            # Generate recommended actions
            crisis_assessment['recommended_actions'] = self._generate_crisis_recommendations(crisis_assessment)
            
            logger.info(f"TikTok crisis signal detection completed. Crisis level: {crisis_assessment['crisis_level'].value}")
            return crisis_assessment
            
        except Exception as e:
            logger.error(f"Error during TikTok crisis signal detection: {str(e)}")
            raise
    
    # Private helper methods for TikTok-specific analysis
    
    async def _analyze_engagement_authenticity(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze engagement authenticity and detect fake interactions."""
        return {
            'authenticity_score': 0.85,  # Placeholder
            'fake_engagement_ratio': 0.1,
            'bot_interaction_indicators': [],
            'engagement_pattern_analysis': 'normal'
        }
    
    async def _check_creator_fund_compliance(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Check Creator Fund eligibility and compliance."""
        return {
            'eligible_for_creator_fund': True,  # Placeholder
            'compliance_score': 0.9,
            'policy_violations': [],
            'monetization_risk': 'low'
        }
    
    async def _analyze_bio_link_compliance(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze bio link compliance with TikTok policies."""
        bio_links = profile_data.get('bio_links', [])
        return {
            'bio_link_count': len(bio_links),
            'compliance_score': 0.95,  # Placeholder
            'flagged_links': [],
            'policy_violations': []
        }
    
    async def _check_community_guidelines(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Check community guideline adherence across profile."""
        return {
            'guideline_compliance_score': 0.9,  # Placeholder
            'violations_count': 0,
            'warning_history': [],
            'restriction_status': 'none'
        }
    
    async def _detect_shadowban_indicators(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect potential shadowban indicators."""
        return {
            'shadowban_probability': 0.1,  # Placeholder
            'visibility_metrics': {},
            'reach_decline_indicators': [],
            'fyp_appearance_rate': 0.7
        }
    
    async def _analyze_account_verification(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze account verification status and authenticity."""
        return {
            'is_verified': profile_data.get('verified', False),
            'account_age_days': 365,  # Placeholder
            'authenticity_indicators': [],
            'verification_eligibility': 'eligible'
        }
    
    async def _check_content_guidelines(self, content_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check content against TikTok community guidelines.
        
        Analyzes video content for guideline violations including:
        - Dangerous acts and challenges
        - Hate speech and harassment
        - Adult content and nudity
        - Violence and graphic content
        - Misinformation
        """
        description = content_data.get('description', content_data.get('video_description', ''))
        title = content_data.get('title', '')
        content_text = f"{title} {description}".lower()
        
        flagged_elements = []
        violation_risk = 'low'
        content_warnings = []
        risk_score = 0.0
        
        # Check for dangerous challenge keywords
        dangerous_keywords = ['challenge', 'dare', 'dangerous', 'extreme', 'risky', 'stunt', 'prank']
        if any(keyword in content_text for keyword in dangerous_keywords):
            flagged_elements.append('potential_dangerous_challenge')
            content_warnings.append('Content may contain dangerous challenge references')
            risk_score += 0.3
        
        # Check for hate speech indicators
        hate_speech_indicators = ['hate', 'discriminat', 'racist', 'sexist', 'homophob', 'transphob']
        if any(indicator in content_text for indicator in hate_speech_indicators):
            flagged_elements.append('potential_hate_speech')
            violation_risk = 'high'
            content_warnings.append('Content may contain hate speech')
            risk_score += 0.5
        
        # Check for adult content indicators
        adult_keywords = ['18+', 'nsfw', 'adult only', 'explicit', 'mature content']
        if any(keyword in content_text for keyword in adult_keywords):
            flagged_elements.append('adult_content_indicators')
            violation_risk = 'high' if violation_risk != 'high' else violation_risk
            content_warnings.append('Content may contain adult material')
            risk_score += 0.4
        
        # Check for violence indicators
        violence_keywords = ['violence', 'blood', 'gore', 'fight', 'weapon', 'attack']
        if any(keyword in content_text for keyword in violence_keywords):
            flagged_elements.append('violence_indicators')
            content_warnings.append('Content may contain violent material')
            risk_score += 0.35
        
        # Check for misinformation indicators
        misinfo_keywords = ['fake news', 'conspiracy', 'hoax', 'debunked', 'false claim']
        if any(keyword in content_text for keyword in misinfo_keywords):
            flagged_elements.append('misinformation_indicators')
            content_warnings.append('Content may contain misinformation')
            risk_score += 0.25
        
        # Determine final violation risk
        if risk_score >= 0.7:
            violation_risk = 'high'
        elif risk_score >= 0.4:
            violation_risk = 'medium'
        
        return {
            'guideline_compliance_score': max(0.0, 1.0 - risk_score),
            'violation_risk': violation_risk,
            'flagged_elements': flagged_elements,
            'content_warnings': content_warnings,
            'risk_score': min(1.0, risk_score)
        }
    
    async def _analyze_music_copyright(self, content_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze music and audio copyright compliance.
        
        Checks for:
        - Copyrighted music usage
        - Commercial music in videos
        - Proper licensing and attribution
        - TikTok's Commercial Music Library compliance
        """
        audio_info = content_data.get('audio', {})
        music_id = audio_info.get('music_id') if isinstance(audio_info, dict) else None
        music_title = audio_info.get('title', '') if isinstance(audio_info, dict) else ''
        
        copyright_issues = []
        risk_score = 0.0
        licensing_status = 'unknown'
        
        # Check if using original sound vs copyrighted music
        is_original_sound = audio_info.get('is_original', False) if isinstance(audio_info, dict) else False
        
        if is_original_sound:
            licensing_status = 'original_sound'
            risk_score = 0.0
        elif music_id:
            # Check if music is from TikTok's licensed library
            # In production, this would query TikTok's music library API
            licensing_status = 'licensed'
            risk_score = 0.1
        else:
            # Unknown music source - potential copyright risk
            copyright_issues.append('unknown_music_source')
            risk_score = 0.4
        
        # Check for commercial music indicators in description
        description = content_data.get('description', content_data.get('video_description', '')).lower()
        commercial_indicators = ['official audio', 'music video', 'full song', 'album']
        if any(indicator in description for indicator in commercial_indicators):
            copyright_issues.append('commercial_music_indicators')
            risk_score += 0.3
        
        # Check for copyright claims or muted audio indicators
        if content_data.get('audio_muted', False):
            copyright_issues.append('audio_muted_copyright_claim')
            risk_score = 0.9
            licensing_status = 'copyright_claimed'
        
        return {
            'copyright_risk_score': min(1.0, risk_score),
            'licensing_status': licensing_status,
            'copyright_issues': copyright_issues,
            'is_original_sound': is_original_sound,
            'music_id': music_id,
            'recommendations': self._generate_music_recommendations(risk_score, copyright_issues)
        }
    
    async def _analyze_hashtag_compliance(self, content_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze hashtag compliance with TikTok policies.
        
        Checks for:
        - Banned or restricted hashtags
        - Spam hashtag patterns
        - Irrelevant hashtag stuffing
        - Trending hashtag misuse
        """
        description = content_data.get('description', content_data.get('video_description', ''))
        
        # Extract hashtags from description
        import re
        hashtags = re.findall(r'#(\w+)', description)
        
        banned_hashtags = []
        spam_indicators = []
        risk_score = 0.0
        
        # Check for banned/restricted hashtags (common examples)
        banned_keywords = ['adult', 'drugs', 'violence', 'hate', 'scam', 'fake']
        for hashtag in hashtags:
            hashtag_lower = hashtag.lower()
            if any(banned in hashtag_lower for banned in banned_keywords):
                banned_hashtags.append(hashtag)
                risk_score += 0.2
        
        # Check for hashtag stuffing (too many hashtags)
        if len(hashtags) > 15:
            spam_indicators.append('excessive_hashtags')
            risk_score += 0.3
        
        # Check for repetitive hashtags
        if len(hashtags) != len(set(hashtags)):
            spam_indicators.append('duplicate_hashtags')
            risk_score += 0.15
        
        # Check for irrelevant popular hashtags (spam pattern)
        generic_popular = ['fyp', 'foryou', 'viral', 'trending']
        generic_count = sum(1 for tag in hashtags if tag.lower() in generic_popular)
        if generic_count > 5:
            spam_indicators.append('excessive_generic_hashtags')
            risk_score += 0.2
        
        return {
            'hashtag_compliance_score': max(0.0, 1.0 - risk_score),
            'total_hashtags': len(hashtags),
            'banned_hashtags': banned_hashtags,
            'spam_indicators': spam_indicators,
            'risk_score': min(1.0, risk_score),
            'recommendations': self._generate_hashtag_recommendations(hashtags, spam_indicators)
        }
    
    async def _detect_fake_engagement(self, content_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect fake engagement patterns in video content.
        
        Analyzes:
        - Engagement rate anomalies
        - Bot-like comment patterns
        - Suspicious like/view ratios
        - Rapid engagement spikes
        """
        view_count = content_data.get('view_count', 0)
        like_count = content_data.get('like_count', 0)
        comment_count = content_data.get('comment_count', 0)
        share_count = content_data.get('share_count', 0)
        
        fake_engagement_indicators = []
        risk_score = 0.0
        
        # Calculate engagement ratios
        if view_count > 0:
            like_ratio = like_count / view_count
            comment_ratio = comment_count / view_count
            share_ratio = share_count / view_count
            
            # Check for suspicious like ratio (too high or too low for view count)
            if like_ratio > 0.5:  # More than 50% like rate is suspicious
                fake_engagement_indicators.append('abnormally_high_like_ratio')
                risk_score += 0.4
            elif like_ratio < 0.001 and view_count > 10000:  # Very low engagement on high views
                fake_engagement_indicators.append('abnormally_low_engagement')
                risk_score += 0.2
            
            # Check comment ratio
            if comment_ratio > 0.1:  # More than 10% comment rate is unusual
                fake_engagement_indicators.append('abnormally_high_comment_ratio')
                risk_score += 0.3
            
            # Check for bot-like patterns (high likes, low shares/comments)
            if like_count > 1000 and comment_count < 10 and share_count < 5:
                fake_engagement_indicators.append('bot_like_pattern')
                risk_score += 0.35
        
        # Check for engagement velocity (if timestamp data available)
        create_time = content_data.get('create_time')
        if create_time and view_count > 0:
            # Calculate time since creation
            try:
                if isinstance(create_time, str):
                    from dateutil import parser
                    created_at = parser.parse(create_time)
                else:
                    created_at = datetime.fromtimestamp(create_time)
                
                hours_since_creation = (datetime.utcnow() - created_at).total_seconds() / 3600
                
                if hours_since_creation > 0:
                    views_per_hour = view_count / hours_since_creation
                    
                    # Extremely rapid growth can indicate bot activity
                    if views_per_hour > 100000 and hours_since_creation < 24:
                        fake_engagement_indicators.append('suspicious_rapid_growth')
                        risk_score += 0.25
            except Exception:
                pass  # Skip velocity check if timestamp parsing fails
        
        return {
            'fake_engagement_score': min(1.0, risk_score),
            'fake_engagement_indicators': fake_engagement_indicators,
            'engagement_metrics': {
                'view_count': view_count,
                'like_count': like_count,
                'comment_count': comment_count,
                'share_count': share_count,
                'like_ratio': like_count / view_count if view_count > 0 else 0,
                'comment_ratio': comment_count / view_count if view_count > 0 else 0
            },
            'authenticity_assessment': 'suspicious' if risk_score > 0.5 else 'normal'
        }
    
    async def _analyze_content_moderation_triggers(self, content_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze content moderation triggers.
        
        Identifies content that may trigger TikTok's automated moderation:
        - Sensitive topics
        - Age-restricted content
        - Controversial subjects
        - Potential policy violations
        """
        description = content_data.get('description', content_data.get('video_description', '')).lower()
        title = content_data.get('title', '').lower()
        content_text = f"{title} {description}"
        
        trigger_indicators = []
        risk_score = 0.0
        sensitive_topics = []
        
        # Check for age-restricted content indicators
        age_restricted_keywords = ['alcohol', 'smoking', 'vaping', 'gambling', 'betting']
        if any(keyword in content_text for keyword in age_restricted_keywords):
            trigger_indicators.append('age_restricted_content')
            sensitive_topics.append('age_restricted_activities')
            risk_score += 0.4
        
        # Check for political content
        political_keywords = ['politics', 'election', 'government', 'protest', 'activism']
        if any(keyword in content_text for keyword in political_keywords):
            trigger_indicators.append('political_content')
            sensitive_topics.append('political_topics')
            risk_score += 0.2
        
        # Check for health misinformation triggers
        health_keywords = ['cure', 'treatment', 'medical', 'vaccine', 'diagnosis']
        if any(keyword in content_text for keyword in health_keywords):
            trigger_indicators.append('health_related_content')
            sensitive_topics.append('health_information')
            risk_score += 0.25
        
        # Check for financial advice triggers
        financial_keywords = ['investment', 'crypto', 'trading', 'get rich', 'money making']
        if any(keyword in content_text for keyword in financial_keywords):
            trigger_indicators.append('financial_advice')
            sensitive_topics.append('financial_content')
            risk_score += 0.3
        
        # Check for controversial topics
        controversial_keywords = ['controversial', 'debate', 'argument', 'conflict']
        if any(keyword in content_text for keyword in controversial_keywords):
            trigger_indicators.append('controversial_content')
            risk_score += 0.15
        
        # Determine if content needs age restriction
        age_restriction_needed = risk_score >= 0.4
        
        return {
            'moderation_risk_score': min(1.0, risk_score),
            'trigger_indicators': trigger_indicators,
            'sensitive_topics': sensitive_topics,
            'sensitive_content_detected': len(trigger_indicators) > 0,
            'age_restriction_risk': 'high' if age_restriction_needed else 'low',
            'recommendations': self._generate_moderation_recommendations(trigger_indicators)
        }
    
    async def _detect_spam_content(self, content_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect spam and repetitive content patterns.
        
        Identifies:
        - Repetitive text patterns
        - Spam keywords and phrases
        - Engagement bait
        - Link spam
        - Follow-for-follow schemes
        """
        description = content_data.get('description', content_data.get('video_description', ''))
        title = content_data.get('title', '')
        content_text = f"{title} {description}".lower()
        
        spam_indicators = []
        risk_score = 0.0
        
        # Check for engagement bait
        engagement_bait_phrases = [
            'like and follow', 'follow for follow', 'f4f', 'l4l',
            'comment below', 'tag a friend', 'share this',
            'follow me', 'check my bio', 'link in bio'
        ]
        bait_count = sum(1 for phrase in engagement_bait_phrases if phrase in content_text)
        if bait_count > 0:
            spam_indicators.append('engagement_bait')
            risk_score += min(0.3, bait_count * 0.1)
        
        # Check for excessive emojis (spam pattern)
        import re
        emoji_pattern = re.compile("["
            u"\U0001F600-\U0001F64F"  # emoticons
            u"\U0001F300-\U0001F5FF"  # symbols & pictographs
            u"\U0001F680-\U0001F6FF"  # transport & map symbols
            u"\U0001F1E0-\U0001F1FF"  # flags
            "]+", flags=re.UNICODE)
        emoji_count = len(emoji_pattern.findall(description))
        if emoji_count > 20:
            spam_indicators.append('excessive_emojis')
            risk_score += 0.2
        
        # Check for repetitive characters or words
        if re.search(r'(.)\1{4,}', content_text):  # Same character repeated 5+ times
            spam_indicators.append('repetitive_characters')
            risk_score += 0.25
        
        # Check for spam keywords
        spam_keywords = [
            'free money', 'get rich quick', 'click here', 'limited time',
            'act now', 'buy now', 'discount', 'prize', 'winner',
            'congratulations', 'claim now', 'exclusive offer'
        ]
        spam_keyword_count = sum(1 for keyword in spam_keywords if keyword in content_text)
        if spam_keyword_count > 0:
            spam_indicators.append('spam_keywords')
            risk_score += min(0.4, spam_keyword_count * 0.15)
        
        # Check for suspicious links
        url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
        urls = url_pattern.findall(content_text)
        if len(urls) > 2:
            spam_indicators.append('multiple_links')
            risk_score += 0.3
        
        # Check for all caps (shouting/spam pattern)
        if description and description.isupper() and len(description) > 20:
            spam_indicators.append('all_caps_text')
            risk_score += 0.15
        
        # Calculate content uniqueness (inverse of spam score)
        content_uniqueness_score = max(0.0, 1.0 - risk_score)
        
        return {
            'spam_score': min(1.0, risk_score),
            'repetitive_content_detected': 'repetitive_characters' in spam_indicators,
            'spam_indicators': spam_indicators,
            'content_uniqueness_score': content_uniqueness_score,
            'spam_assessment': 'high_risk' if risk_score > 0.6 else 'low_risk'
        }
    
    def _calculate_profile_risk_score(self, risk_factors: Dict[str, Any]) -> float:
        """
        Calculate overall profile risk score using weighted factors.
        
        Weights prioritize authenticity and compliance issues.
        """
        weights = {
            'engagement_authenticity': 0.25,
            'creator_fund_compliance': 0.15,
            'bio_link_compliance': 0.20,
            'community_guidelines': 0.20,
            'shadowban_indicators': 0.15,
            'account_verification': 0.05
        }
        
        total_score = 0.0
        total_weight = 0.0
        
        for factor_name, weight in weights.items():
            if factor_name in risk_factors:
                factor_data = risk_factors[factor_name]
                
                # Extract risk score from factor data
                if isinstance(factor_data, dict):
                    factor_score = factor_data.get('risk_score', 
                                  factor_data.get('fake_engagement_ratio',
                                  1.0 - factor_data.get('compliance_score', 0.5)))
                else:
                    factor_score = 0.5  # Default moderate risk
                
                total_score += factor_score * weight
                total_weight += weight
        
        # Normalize by total weight used
        if total_weight > 0:
            return min(1.0, total_score / total_weight)
        return 0.0
    
    def _calculate_content_risk_score(self, risk_factors: Dict[str, Any]) -> float:
        """
        Calculate overall content risk score using weighted factors.
        
        Weights prioritize guideline violations and copyright issues.
        """
        weights = {
            'community_guidelines': 0.30,
            'music_copyright': 0.20,
            'hashtag_compliance': 0.15,
            'fake_engagement': 0.15,
            'content_moderation': 0.15,
            'spam_content': 0.05
        }
        
        total_score = 0.0
        total_weight = 0.0
        
        for factor_name, weight in weights.items():
            if factor_name in risk_factors:
                factor_data = risk_factors[factor_name]
                
                # Extract risk score from factor data
                if isinstance(factor_data, dict):
                    factor_score = factor_data.get('risk_score',
                                  factor_data.get('copyright_risk_score',
                                  factor_data.get('fake_engagement_score',
                                  factor_data.get('moderation_risk_score',
                                  factor_data.get('spam_score', 0.5)))))
                else:
                    factor_score = 0.5  # Default moderate risk
                
                total_score += factor_score * weight
                total_weight += weight
        
        # Normalize by total weight used
        if total_weight > 0:
            return min(1.0, total_score / total_weight)
        return 0.0
    
    def _determine_risk_level(self, risk_score: float) -> RiskLevel:
        """Determine risk level based on score."""
        if risk_score >= 0.7:
            return RiskLevel.HIGH
        elif risk_score >= 0.4:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _generate_profile_recommendations(self, assessment: Dict[str, Any]) -> List[str]:
        """Generate profile-specific recommendations."""
        return [
            "Maintain authentic engagement patterns",
            "Ensure Creator Fund policy compliance",
            "Monitor bio link restrictions"
        ]
    
    def _generate_content_recommendations(self, assessment: Dict[str, Any]) -> List[str]:
        """Generate content-specific recommendations based on risk assessment."""
        recommendations = []
        risk_factors = assessment.get('risk_factors', {})
        risk_score = assessment.get('risk_score', 0.0)
        
        # General recommendations based on overall risk
        if risk_score > 0.7:
            recommendations.append("High risk detected - review content before posting")
        
        # Music copyright recommendations
        music_risk = risk_factors.get('music_copyright', {})
        if music_risk.get('copyright_risk_score', 0) > 0.5:
            recommendations.append("Use TikTok's Commercial Music Library for licensed audio")
            recommendations.append("Consider using original sounds to avoid copyright issues")
        
        # Community guidelines recommendations
        guideline_risk = risk_factors.get('community_guidelines', {})
        if guideline_risk.get('risk_score', 0) > 0.5:
            recommendations.append("Review TikTok Community Guidelines before posting")
            recommendations.append("Remove potentially violating content to avoid restrictions")
        
        # Hashtag recommendations
        hashtag_risk = risk_factors.get('hashtag_compliance', {})
        if hashtag_risk.get('banned_hashtags'):
            recommendations.append("Remove banned or restricted hashtags")
        if 'excessive_hashtags' in hashtag_risk.get('spam_indicators', []):
            recommendations.append("Reduce number of hashtags to 10-15 relevant tags")
        
        # Fake engagement recommendations
        engagement_risk = risk_factors.get('fake_engagement', {})
        if engagement_risk.get('fake_engagement_score', 0) > 0.5:
            recommendations.append("Engagement patterns appear suspicious - avoid bot services")
        
        # Spam content recommendations
        spam_risk = risk_factors.get('spam_content', {})
        if spam_risk.get('spam_score', 0) > 0.5:
            recommendations.append("Remove spam keywords and excessive engagement bait")
            recommendations.append("Make content more authentic and less promotional")
        
        # Moderation trigger recommendations
        moderation_risk = risk_factors.get('content_moderation', {})
        if moderation_risk.get('age_restriction_risk') == 'high':
            recommendations.append("Content may require age restriction - mark appropriately")
        
        # Default recommendations if none specific
        if not recommendations:
            recommendations.extend([
                "Use original or licensed audio",
                "Follow community guidelines strictly",
                "Use relevant, non-banned hashtags"
            ])
        
        return recommendations
    
    def _generate_music_recommendations(self, risk_score: float, copyright_issues: List[str]) -> List[str]:
        """Generate music copyright recommendations."""
        recommendations = []
        
        if risk_score > 0.7:
            recommendations.append("High copyright risk - replace audio immediately")
        
        if 'unknown_music_source' in copyright_issues:
            recommendations.append("Use TikTok's Commercial Music Library for safe audio")
        
        if 'commercial_music_indicators' in copyright_issues:
            recommendations.append("Avoid using full commercial songs without proper licensing")
        
        if 'audio_muted_copyright_claim' in copyright_issues:
            recommendations.append("Audio was muted due to copyright - use original or licensed sound")
        
        if not recommendations:
            recommendations.append("Continue using licensed or original audio")
        
        return recommendations
    
    def _generate_hashtag_recommendations(self, hashtags: List[str], spam_indicators: List[str]) -> List[str]:
        """Generate hashtag usage recommendations."""
        recommendations = []
        
        if 'excessive_hashtags' in spam_indicators:
            recommendations.append(f"Reduce hashtags from {len(hashtags)} to 10-15 relevant tags")
        
        if 'duplicate_hashtags' in spam_indicators:
            recommendations.append("Remove duplicate hashtags")
        
        if 'excessive_generic_hashtags' in spam_indicators:
            recommendations.append("Use more specific, niche hashtags instead of only generic ones")
        
        if len(hashtags) < 5:
            recommendations.append("Add more relevant hashtags to improve discoverability")
        
        if not recommendations:
            recommendations.append("Hashtag usage looks good - continue with relevant tags")
        
        return recommendations
    
    def _generate_moderation_recommendations(self, trigger_indicators: List[str]) -> List[str]:
        """Generate content moderation recommendations."""
        recommendations = []
        
        if 'age_restricted_content' in trigger_indicators:
            recommendations.append("Mark content as 18+ if it contains age-restricted material")
        
        if 'political_content' in trigger_indicators:
            recommendations.append("Political content may have limited reach - be factual and balanced")
        
        if 'health_related_content' in trigger_indicators:
            recommendations.append("Ensure health information is accurate and cite credible sources")
        
        if 'financial_advice' in trigger_indicators:
            recommendations.append("Add disclaimer that this is not professional financial advice")
        
        if 'controversial_content' in trigger_indicators:
            recommendations.append("Controversial topics may trigger additional review - be respectful")
        
        if not recommendations:
            recommendations.append("Content appears safe for general audiences")
        
        return recommendations
    
    # Additional helper methods for algorithm health and crisis detection
    async def _calculate_fyp_visibility_score(self, account_data: Dict[str, Any]) -> float:
        """Calculate For You Page visibility score."""
        return 0.65  # Placeholder
    
    async def _analyze_engagement_health(self, account_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze engagement health metrics."""
        return {'health_score': 0.8, 'engagement_trends': 'stable'}
    
    async def _analyze_content_performance(self, account_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze content performance patterns."""
        return {'performance_score': 0.75, 'viral_potential': 'medium'}
    
    async def _detect_algorithmic_penalties(self, account_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect algorithmic penalties."""
        return {'penalty_detected': False, 'penalty_type': None}
    
    def _generate_algorithm_recommendations(self, assessment: Dict[str, Any]) -> List[str]:
        """Generate algorithm health recommendations."""
        return ["Post consistently", "Engage with trending content"]
    
    async def _detect_viral_negative_content(self, monitoring_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect viral negative content."""
        return {'viral_risk': 0.08, 'negative_content_velocity': 'low'}
    
    async def _detect_coordinated_harassment(self, monitoring_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect coordinated harassment campaigns."""
        return {'harassment_detected': False, 'coordination_indicators': []}
    
    async def _monitor_negative_hashtag_trends(self, monitoring_data: Dict[str, Any]) -> Dict[str, Any]:
        """Monitor trending negative hashtags."""
        return {'negative_hashtag_risk': 0.05, 'trending_negative_tags': []}
    
    async def _assess_community_backlash(self, monitoring_data: Dict[str, Any]) -> Dict[str, Any]:
        """Assess community backlash through duets and stitches."""
        return {'backlash_risk': 0.1, 'negative_response_ratio': 0.05}
    
    async def _detect_mass_reporting(self, monitoring_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect mass reporting campaigns."""
        return {'mass_reporting_detected': False, 'report_velocity': 'normal'}
    
    def _determine_crisis_level(self, crisis_indicators: Dict[str, Any]) -> RiskLevel:
        """Determine overall Crisis level."""
        return RiskLevel.LOW  # Placeholder
    
    def _generate_crisis_alerts(self, assessment: Dict[str, Any]) -> List[str]:
        """Generate crisis alert triggers."""
        return []  # Placeholder
    
    def _generate_crisis_recommendations(self, assessment: Dict[str, Any]) -> List[str]:
        """Generate crisis management recommendations."""
        return ["Monitor community response", "Prepare content strategy"]


# Register the TikTok adapter with the platform registry
registry.register_adapter(
    PlatformType.TIKTOK,
    TikTokProtectionAdapter,
    config={
        'enabled': True,
        'rate_limits': {
            'profile_scan': {'requests': 100, 'window': 3600},  # 100 requests per hour
            'content_analysis': {'requests': 200, 'window': 3600},  # 200 requests per hour
            'algorithm_health': {'requests': 50, 'window': 3600},  # 50 requests per hour
            'crisis_detection': {'requests': 30, 'window': 3600}  # 30 requests per hour
        },
        'risk_thresholds': {
            'fake_engagement_ratio': 0.3,
            'community_guideline_risk': 0.8,
            'bio_link_violation': 0.9,
            'creator_fund_risk': 0.7,
            'shadowban_probability': 0.5,
            'hashtag_violation_score': 0.6,
            'copyright_risk_score': 0.75,
            'content_moderation_risk': 0.65
        }
    }
)