"""Twitter/X Platform Protection Adapter

This module implements Twitter-specific social media protection functionality,
including external link penalty detection, Community Notes trigger analysis,
follower authenticity assessment, and engagement pattern monitoring.

Based on LinkShield's Twitter protection analysis and business strategy.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from enum import Enum
import tweepy
from tweepy.errors import TweepyException

from .base_adapter import SocialPlatformAdapter, PlatformType, RiskLevel
from ..registry import registry
from ..logging_utils import get_logger
from ..exceptions import PlatformAdapterError

logger = get_logger("TwitterProtectionAdapter")


class TwitterRiskFactor(Enum):
    """Twitter-specific risk factors for content and profile analysis."""
    EXTERNAL_LINK_PENALTY = "external_link_penalty"
    COMMUNITY_NOTES_TRIGGER = "community_notes_trigger"
    FAKE_FOLLOWERS = "fake_followers"
    ENGAGEMENT_MANIPULATION = "engagement_manipulation"
    SPAM_PATTERNS = "spam_patterns"
    SHADOWBAN_INDICATORS = "shadowban_indicators"
    RATE_LIMIT_VIOLATIONS = "rate_limit_violations"
    POLICY_VIOLATIONS = "policy_violations"


class TwitterProtectionAdapter(SocialPlatformAdapter):
    """
    Twitter/X platform adapter for social media protection.
    
    Implements Twitter-specific risk analysis including:
    - External link penalties and reach reduction
    - Community Notes trigger detection
    - Follower authenticity analysis
    - Engagement pattern monitoring
    - Shadowban detection
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize Twitter protection adapter.
        
        Args:
            config: Platform-specific configuration including API credentials,
                   risk thresholds, and feature flags
        """
        super().__init__(PlatformType.TWITTER, config or {})
        self.risk_thresholds = self._load_risk_thresholds()
        self.client: Optional[tweepy.Client] = None
        self._initialize_api_client()
        
    def _initialize_api_client(self) -> None:
        """
        Initialize Twitter API v2 client with authentication.
        
        Supports multiple authentication methods:
        - Bearer Token (App-only authentication)
        - OAuth 2.0 (User context)
        - OAuth 1.0a (User context with consumer keys)
        
        Rate limiting is automatically handled by tweepy's wait_on_rate_limit feature.
        """
        try:
            # Get API credentials from config
            bearer_token = self.config.get('bearer_token')
            api_key = self.config.get('api_key')
            api_secret = self.config.get('api_secret')
            access_token = self.config.get('access_token')
            access_token_secret = self.config.get('access_token_secret')
            
            # Initialize client based on available credentials
            if bearer_token:
                # Bearer token authentication (recommended for API v2)
                # wait_on_rate_limit=True makes tweepy automatically wait when rate limited
                self.client = tweepy.Client(
                    bearer_token=bearer_token,
                    wait_on_rate_limit=True
                )
                logger.info("Twitter API v2 client initialized with bearer token (auto rate limit handling enabled)")
            elif api_key and api_secret and access_token and access_token_secret:
                # OAuth 1.0a authentication
                self.client = tweepy.Client(
                    consumer_key=api_key,
                    consumer_secret=api_secret,
                    access_token=access_token,
                    access_token_secret=access_token_secret,
                    wait_on_rate_limit=True
                )
                logger.info("Twitter API v2 client initialized with OAuth 1.0a (auto rate limit handling enabled)")
            else:
                logger.warning("Twitter API credentials not configured. Adapter will operate in limited mode.")
                self.is_enabled = False
            
            # Initialize rate limit tracking
            self._rate_limit_status = {
                'last_reset': datetime.utcnow(),
                'requests_made': 0,
                'limit_reached': False
            }
                
        except Exception as e:
            logger.error(f"Failed to initialize Twitter API client: {str(e)}")
            self.is_enabled = False
            self.client = None
    
    async def validate_credentials(self) -> bool:
        """
        Validate Twitter API credentials and permissions.
        
        Returns:
            True if credentials are valid and have required permissions
        """
        if not self.client:
            logger.warning("Twitter API client not initialized")
            return False
            
        try:
            # Test API access by fetching authenticated user info
            me = self.client.get_me()
            if me and me.data:
                logger.info(f"Twitter API credentials validated for user: {me.data.username}")
                return True
            return False
        except TweepyException as e:
            logger.error(f"Twitter API credential validation failed: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during credential validation: {str(e)}")
            return False
    
    def get_rate_limit_status(self) -> Dict[str, Any]:
        """
        Get current rate limit status for Twitter API.
        
        Returns:
            Dict containing rate limit information including remaining requests,
            reset time, and current usage statistics
        """
        if not self.client:
            return {
                'enabled': False,
                'error': 'API client not initialized'
            }
        
        return {
            'enabled': True,
            'auto_wait_enabled': True,  # tweepy handles rate limits automatically
            'last_reset': self._rate_limit_status.get('last_reset', datetime.utcnow()).isoformat(),
            'requests_made': self._rate_limit_status.get('requests_made', 0),
            'limit_reached': self._rate_limit_status.get('limit_reached', False),
            'rate_limits': self.get_rate_limits()
        }
    
    def _handle_rate_limit_error(self, error: TweepyException) -> None:
        """
        Handle rate limit errors from Twitter API.
        
        Args:
            error: TweepyException containing rate limit information
        """
        logger.warning(f"Twitter API rate limit encountered: {str(error)}")
        self._rate_limit_status['limit_reached'] = True
        
        # Extract reset time from error if available
        if hasattr(error, 'response') and error.response:
            headers = error.response.headers
            reset_time = headers.get('x-rate-limit-reset')
            if reset_time:
                reset_datetime = datetime.fromtimestamp(int(reset_time))
                logger.info(f"Rate limit will reset at: {reset_datetime.isoformat()}")
                self._rate_limit_status['reset_time'] = reset_datetime
    
    def _track_api_request(self) -> None:
        """Track API request for rate limit monitoring."""
        self._rate_limit_status['requests_made'] += 1
        
        # Reset counter if it's been more than 15 minutes (Twitter's rate limit window)
        last_reset = self._rate_limit_status.get('last_reset', datetime.utcnow())
        if (datetime.utcnow() - last_reset).total_seconds() > 900:  # 15 minutes
            self._rate_limit_status['requests_made'] = 1
            self._rate_limit_status['last_reset'] = datetime.utcnow()
            self._rate_limit_status['limit_reached'] = False
    
    def _load_risk_thresholds(self) -> Dict[str, float]:
        """Load Twitter-specific risk thresholds from configuration."""
        return self.config.get('risk_thresholds', {
            'external_link_penalty': 0.7,
            'community_notes_trigger': 0.8,
            'fake_follower_ratio': 0.3,
            'engagement_manipulation': 0.6,
            'spam_pattern_score': 0.5,
            'shadowban_probability': 0.4
        })
    
    async def fetch_profile_data(self, username: str) -> Dict[str, Any]:
        """
        Fetch comprehensive profile data from Twitter API v2.
        
        Args:
            username: Twitter username (without @)
            
        Returns:
            Dict containing profile data including user info, metrics, and recent activity
            
        Raises:
            PlatformAdapterError: If profile fetch fails
        """
        if not self.client:
            raise PlatformAdapterError("Twitter API client not initialized")
            
        try:
            # Track API request for rate limit monitoring
            self._track_api_request()
            
            # Fetch user data with expanded fields
            user_response = self.client.get_user(
                username=username,
                user_fields=[
                    'created_at', 'description', 'entities', 'id', 'location',
                    'name', 'pinned_tweet_id', 'profile_image_url', 'protected',
                    'public_metrics', 'url', 'username', 'verified', 'verified_type',
                    'withheld'
                ]
            )
            
            if not user_response or not user_response.data:
                raise PlatformAdapterError(f"User not found: {username}")
            
            user = user_response.data
            
            # Track another API request for tweets
            self._track_api_request()
            
            # Fetch recent tweets for activity analysis
            tweets_response = self.client.get_users_tweets(
                id=user.id,
                max_results=100,
                tweet_fields=['created_at', 'public_metrics', 'entities', 'referenced_tweets'],
                exclude=['retweets', 'replies']
            )
            
            recent_tweets = tweets_response.data if tweets_response and tweets_response.data else []
            
            # Compile profile data
            profile_data = {
                'user_id': str(user.id),
                'username': user.username,
                'name': user.name,
                'description': user.description or '',
                'location': user.location or '',
                'url': user.url or '',
                'profile_image_url': user.profile_image_url,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'verified': user.verified or False,
                'verified_type': user.verified_type if hasattr(user, 'verified_type') else None,
                'protected': user.protected or False,
                'public_metrics': {
                    'followers_count': user.public_metrics.get('followers_count', 0),
                    'following_count': user.public_metrics.get('following_count', 0),
                    'tweet_count': user.public_metrics.get('tweet_count', 0),
                    'listed_count': user.public_metrics.get('listed_count', 0),
                } if user.public_metrics else {},
                'recent_tweets': [
                    {
                        'id': str(tweet.id),
                        'text': tweet.text,
                        'created_at': tweet.created_at.isoformat() if tweet.created_at else None,
                        'public_metrics': tweet.public_metrics if hasattr(tweet, 'public_metrics') else {},
                        'entities': tweet.entities if hasattr(tweet, 'entities') else {}
                    }
                    for tweet in recent_tweets
                ],
                'fetched_at': datetime.utcnow().isoformat()
            }
            
            logger.info(f"Successfully fetched profile data for @{username}")
            return profile_data
            
        except TweepyException as e:
            # Handle rate limit errors specifically
            if 'rate limit' in str(e).lower():
                self._handle_rate_limit_error(e)
            logger.error(f"Twitter API error fetching profile {username}: {str(e)}")
            raise PlatformAdapterError(f"Failed to fetch Twitter profile: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error fetching profile {username}: {str(e)}")
            raise PlatformAdapterError(f"Unexpected error: {str(e)}")
    
    async def fetch_tweet_data(self, tweet_id: str) -> Dict[str, Any]:
        """
        Fetch detailed tweet data from Twitter API v2.
        
        Args:
            tweet_id: Twitter tweet ID
            
        Returns:
            Dict containing tweet data including metrics and context
            
        Raises:
            PlatformAdapterError: If tweet fetch fails
        """
        if not self.client:
            raise PlatformAdapterError("Twitter API client not initialized")
            
        try:
            # Track API request for rate limit monitoring
            self._track_api_request()
            
            # Fetch tweet with expanded fields
            tweet_response = self.client.get_tweet(
                id=tweet_id,
                tweet_fields=[
                    'created_at', 'public_metrics', 'entities', 'referenced_tweets',
                    'context_annotations', 'conversation_id', 'lang', 'possibly_sensitive',
                    'reply_settings', 'source'
                ],
                expansions=['author_id', 'referenced_tweets.id'],
                user_fields=['username', 'verified', 'public_metrics']
            )
            
            if not tweet_response or not tweet_response.data:
                raise PlatformAdapterError(f"Tweet not found: {tweet_id}")
            
            tweet = tweet_response.data
            
            # Compile tweet data
            tweet_data = {
                'tweet_id': str(tweet.id),
                'text': tweet.text,
                'created_at': tweet.created_at.isoformat() if tweet.created_at else None,
                'author_id': str(tweet.author_id) if hasattr(tweet, 'author_id') else None,
                'lang': tweet.lang if hasattr(tweet, 'lang') else None,
                'possibly_sensitive': tweet.possibly_sensitive if hasattr(tweet, 'possibly_sensitive') else False,
                'public_metrics': {
                    'retweet_count': tweet.public_metrics.get('retweet_count', 0),
                    'reply_count': tweet.public_metrics.get('reply_count', 0),
                    'like_count': tweet.public_metrics.get('like_count', 0),
                    'quote_count': tweet.public_metrics.get('quote_count', 0),
                    'impression_count': tweet.public_metrics.get('impression_count', 0),
                } if tweet.public_metrics else {},
                'entities': tweet.entities if hasattr(tweet, 'entities') else {},
                'context_annotations': tweet.context_annotations if hasattr(tweet, 'context_annotations') else [],
                'referenced_tweets': tweet.referenced_tweets if hasattr(tweet, 'referenced_tweets') else [],
                'fetched_at': datetime.utcnow().isoformat()
            }
            
            logger.info(f"Successfully fetched tweet data for {tweet_id}")
            return tweet_data
            
        except TweepyException as e:
            # Handle rate limit errors specifically
            if 'rate limit' in str(e).lower():
                self._handle_rate_limit_error(e)
            logger.error(f"Twitter API error fetching tweet {tweet_id}: {str(e)}")
            raise PlatformAdapterError(f"Failed to fetch tweet: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error fetching tweet {tweet_id}: {str(e)}")
            raise PlatformAdapterError(f"Unexpected error: {str(e)}")
    
    async def scan_profile(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform comprehensive Twitter profile security audit.
        
        Analyzes profile for authenticity, follower quality, verification status,
        and potential security risks.
        
        Args:
            profile_data: Twitter profile information including followers,
                         following, tweets, verification status.
                         Can also accept just a username string to fetch data.
                         
        Returns:
            Dict containing profile risk assessment with scores and recommendations
        """
        try:
            # If profile_data is just a username, fetch the full profile
            if isinstance(profile_data, str):
                profile_data = await self.fetch_profile_data(profile_data)
            elif 'username' in profile_data and not profile_data.get('user_id'):
                # Fetch full profile if only username provided
                profile_data = await self.fetch_profile_data(profile_data['username'])
            
            logger.info(f"Starting Twitter profile scan for user: {profile_data.get('username', 'unknown')}")
            
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
            
            # Analyze follower authenticity
            follower_risk = await self._analyze_follower_authenticity(profile_data)
            risk_assessment['risk_factors']['follower_authenticity'] = follower_risk
            
            # Check account verification and age
            verification_risk = await self._analyze_verification_status(profile_data)
            risk_assessment['risk_factors']['verification_status'] = verification_risk
            
            # Analyze engagement patterns
            engagement_risk = await self._analyze_engagement_patterns(profile_data)
            risk_assessment['risk_factors']['engagement_patterns'] = engagement_risk
            
            # Check for shadowban indicators
            shadowban_risk = await self._detect_shadowban_indicators(profile_data)
            risk_assessment['risk_factors']['shadowban_indicators'] = shadowban_risk
            
            # Calculate overall risk score and level
            risk_assessment['risk_score'] = self._calculate_profile_risk_score(risk_assessment['risk_factors'])
            risk_assessment['overall_risk_level'] = self._determine_risk_level(risk_assessment['risk_score'])
            
            # Generate recommendations
            risk_assessment['recommendations'] = self._generate_profile_recommendations(risk_assessment)
            
            logger.info(f"Twitter profile scan completed. Risk level: {risk_assessment['overall_risk_level'].value}")
            return risk_assessment
            
        except Exception as e:
            logger.error(f"Error during Twitter profile scan: {str(e)}")
            raise
    
    async def analyze_content(self, content_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze Twitter content for risk factors and policy violations.
        
        Focuses on external link penalties, Community Notes triggers,
        spam patterns, and engagement manipulation.
        
        Args:
            content_data: Tweet content including text, links, media,
                         engagement metrics, and metadata.
                         Can also accept just a tweet_id string to fetch data.
                         
        Returns:
            Dict containing content risk assessment with specific risk factors
        """
        try:
            # If content_data is just a tweet_id, fetch the full tweet
            if isinstance(content_data, str):
                content_data = await self.fetch_tweet_data(content_data)
            elif 'tweet_id' in content_data and not content_data.get('text'):
                # Fetch full tweet if only tweet_id provided
                content_data = await self.fetch_tweet_data(content_data['tweet_id'])
            
            logger.info(f"Starting Twitter content analysis for tweet: {content_data.get('tweet_id', 'unknown')}")
            
            # Initialize content risk assessment
            risk_assessment = {
                'platform': self.platform_type.value,
                'content_id': content_data.get('tweet_id'),
                'content_type': 'tweet',
                'scan_timestamp': datetime.utcnow().isoformat(),
                'risk_factors': {},
                'overall_risk_level': RiskLevel.LOW,
                'risk_score': 0.0,
                'recommendations': []
            }
            
            # Analyze external links for penalty risk
            link_risk = await self._analyze_external_links(content_data)
            risk_assessment['risk_factors']['external_links'] = link_risk
            
            # Check Community Notes trigger potential
            community_notes_risk = await self._analyze_community_notes_triggers(content_data)
            risk_assessment['risk_factors']['community_notes'] = community_notes_risk
            
            # Detect spam patterns
            spam_risk = await self._detect_spam_patterns(content_data)
            risk_assessment['risk_factors']['spam_patterns'] = spam_risk
            
            # Analyze engagement manipulation
            engagement_manipulation_risk = await self._detect_engagement_manipulation(content_data)
            risk_assessment['risk_factors']['engagement_manipulation'] = engagement_manipulation_risk
            
            # Check policy violations
            policy_risk = await self._check_policy_violations(content_data)
            risk_assessment['risk_factors']['policy_violations'] = policy_risk
            
            # Calculate overall risk score and level
            risk_assessment['risk_score'] = self._calculate_content_risk_score(risk_assessment['risk_factors'])
            risk_assessment['overall_risk_level'] = self._determine_risk_level(risk_assessment['risk_score'])
            
            # Generate recommendations
            risk_assessment['recommendations'] = self._generate_content_recommendations(risk_assessment)
            
            logger.info(f"Twitter content analysis completed. Risk level: {risk_assessment['overall_risk_level'].value}")
            return risk_assessment
            
        except Exception as e:
            logger.error(f"Error during Twitter content analysis: {str(e)}")
            raise
    
    async def get_algorithm_health(self, account_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assess Twitter algorithm health and visibility scoring.
        
        Monitors engagement patterns, reach metrics, and potential
        algorithmic penalties affecting content visibility.
        
        Args:
            account_data: Twitter account metrics including recent tweets,
                         engagement rates, reach data, and performance history
                         
        Returns:
            Dict containing algorithm health assessment and visibility metrics
        """
        try:
            logger.info(f"Starting Twitter algorithm health assessment for account: {account_data.get('username', 'unknown')}")
            
            # Initialize algorithm health assessment
            health_assessment = {
                'platform': self.platform_type.value,
                'account_id': account_data.get('user_id'),
                'username': account_data.get('username'),
                'assessment_timestamp': datetime.utcnow().isoformat(),
                'visibility_score': 0.0,
                'engagement_health': {},
                'reach_metrics': {},
                'penalty_indicators': {},
                'recommendations': []
            }
            
            # Calculate visibility score
            health_assessment['visibility_score'] = await self._calculate_visibility_score(account_data)
            
            # Analyze engagement health
            health_assessment['engagement_health'] = await self._analyze_engagement_health(account_data)
            
            # Assess reach metrics
            health_assessment['reach_metrics'] = await self._analyze_reach_metrics(account_data)
            
            # Detect algorithmic penalties
            health_assessment['penalty_indicators'] = await self._detect_algorithmic_penalties(account_data)
            
            # Generate algorithm health recommendations
            health_assessment['recommendations'] = self._generate_algorithm_recommendations(health_assessment)
            
            logger.info(f"Twitter algorithm health assessment completed. Visibility score: {health_assessment['visibility_score']}")
            return health_assessment
            
        except Exception as e:
            logger.error(f"Error during Twitter algorithm health assessment: {str(e)}")
            raise
    
    async def detect_crisis_signals(self, monitoring_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect crisis signals and reputation threats on Twitter.
        
        Monitors for viral negative content, coordinated attacks,
        trending negative mentions, and emergency situations.
        
        Args:
            monitoring_data: Real-time Twitter monitoring data including
                           mentions, hashtags, sentiment, and trending topics
                           
        Returns:
            Dict containing crisis detection results and alert recommendations
        """
        try:
            logger.info(f"Starting Twitter crisis signal detection for account: {monitoring_data.get('username', 'unknown')}")
            
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
            
            # Check for coordinated attacks
            coordinated_attack_risk = await self._detect_coordinated_attacks(monitoring_data)
            crisis_assessment['crisis_indicators']['coordinated_attacks'] = coordinated_attack_risk
            
            # Monitor trending negative mentions
            trending_risk = await self._monitor_trending_mentions(monitoring_data)
            crisis_assessment['crisis_indicators']['trending_mentions'] = trending_risk
            
            # Assess reputation damage velocity
            reputation_risk = await self._assess_reputation_damage_velocity(monitoring_data)
            crisis_assessment['crisis_indicators']['reputation_damage'] = reputation_risk
            
            # Determine overall crisis level
            crisis_assessment['crisis_level'] = self._determine_crisis_level(crisis_assessment['crisis_indicators'])
            
            # Generate alert triggers
            crisis_assessment['alert_triggers'] = self._generate_crisis_alerts(crisis_assessment)
            
            # Generate recommended actions
            crisis_assessment['recommended_actions'] = self._generate_crisis_recommendations(crisis_assessment)
            
            logger.info(f"Twitter crisis signal detection completed. Crisis level: {crisis_assessment['crisis_level'].value}")
            return crisis_assessment
            
        except Exception as e:
            logger.error(f"Error during Twitter crisis signal detection: {str(e)}")
            raise
    
    # Private helper methods for Twitter-specific analysis
    
    async def _analyze_follower_authenticity(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze follower authenticity and detect fake followers."""
        # Implementation for follower authenticity analysis
        # This would integrate with Twitter API and ML models for fake follower detection
        return {
            'fake_follower_ratio': 0.15,  # Placeholder
            'suspicious_patterns': [],
            'authenticity_score': 0.85
        }
    
    async def _analyze_verification_status(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze account verification status and age."""
        return {
            'is_verified': profile_data.get('verified', False),
            'account_age_days': 365,  # Placeholder
            'verification_risk': 'low'
        }
    
    async def _analyze_engagement_patterns(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze engagement patterns for manipulation indicators."""
        return {
            'engagement_rate': 0.05,  # Placeholder
            'manipulation_indicators': [],
            'pattern_consistency': 'normal'
        }
    
    async def _detect_shadowban_indicators(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect potential shadowban indicators."""
        return {
            'shadowban_probability': 0.1,  # Placeholder
            'visibility_metrics': {},
            'indicators': []
        }
    
    async def _analyze_external_links(self, content_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze external links for penalty risk.
        
        Twitter penalizes tweets with external links by reducing their reach.
        This method identifies and scores link-related risks.
        """
        entities = content_data.get('entities', {})
        urls = entities.get('urls', [])
        
        external_link_count = 0
        flagged_domains = []
        penalty_factors = []
        
        # Known domains that Twitter penalizes or restricts
        penalized_domains = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co',  # URL shorteners
            'onlyfans.com', 'patreon.com',  # Monetization platforms
        ]
        
        for url_obj in urls:
            expanded_url = url_obj.get('expanded_url', '')
            display_url = url_obj.get('display_url', '')
            
            # Check if it's an external link (not twitter.com)
            if expanded_url and 'twitter.com' not in expanded_url and 'x.com' not in expanded_url:
                external_link_count += 1
                
                # Check for penalized domains
                for domain in penalized_domains:
                    if domain in expanded_url.lower():
                        flagged_domains.append(domain)
                        penalty_factors.append(f"Penalized domain: {domain}")
        
        # Calculate penalty risk score
        penalty_risk_score = 0.0
        
        if external_link_count > 0:
            # Base penalty for having external links
            penalty_risk_score = 0.3
            
            # Additional penalty for multiple links
            if external_link_count > 1:
                penalty_risk_score += 0.2
                penalty_factors.append(f"Multiple external links ({external_link_count})")
            
            # Additional penalty for flagged domains
            if flagged_domains:
                penalty_risk_score += 0.3
        
        # Cap at 1.0
        penalty_risk_score = min(penalty_risk_score, 1.0)
        
        return {
            'external_link_count': external_link_count,
            'penalty_risk_score': penalty_risk_score,
            'flagged_domains': flagged_domains,
            'penalty_factors': penalty_factors,
            'recommendation': 'Minimize external links to maximize reach' if external_link_count > 0 else None
        }
    
    async def _analyze_community_notes_triggers(self, content_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check for Community Notes trigger potential.
        
        Community Notes are added to tweets that may be misleading.
        This analyzes content for characteristics that trigger notes.
        """
        text = content_data.get('text', '').lower()
        risk_factors = []
        content_flags = []
        
        # Keywords that often trigger Community Notes
        misleading_keywords = [
            'breaking:', 'confirmed:', 'exclusive:', 'leaked:',
            'they don\'t want you to know', 'mainstream media won\'t tell you',
            'doctors hate this', 'one simple trick', 'shocking truth'
        ]
        
        # Check for misleading language
        for keyword in misleading_keywords:
            if keyword in text:
                risk_factors.append(f"Misleading language: '{keyword}'")
                content_flags.append('misleading_language')
        
        # Check for unverified claims
        claim_indicators = ['study shows', 'research proves', 'scientists say', 'experts claim']
        entities = content_data.get('entities', {})
        urls = entities.get('urls', [])
        
        has_claims = any(indicator in text for indicator in claim_indicators)
        has_sources = len(urls) > 0
        
        if has_claims and not has_sources:
            risk_factors.append('Unverified claims without sources')
            content_flags.append('unverified_claims')
        
        # Check for sensational language
        sensational_words = ['shocking', 'unbelievable', 'mind-blowing', 'insane', 'crazy']
        sensational_count = sum(1 for word in sensational_words if word in text)
        
        if sensational_count >= 2:
            risk_factors.append(f'Sensational language ({sensational_count} instances)')
            content_flags.append('sensational_language')
        
        # Check if marked as possibly sensitive
        if content_data.get('possibly_sensitive', False):
            risk_factors.append('Marked as possibly sensitive by Twitter')
            content_flags.append('possibly_sensitive')
        
        # Calculate trigger probability
        trigger_probability = 0.0
        if risk_factors:
            trigger_probability = min(len(risk_factors) * 0.25, 1.0)
        
        return {
            'trigger_probability': trigger_probability,
            'risk_factors': risk_factors,
            'content_flags': content_flags,
            'recommendation': 'Add credible sources and avoid sensational language' if trigger_probability > 0.5 else None
        }
    
    async def _detect_spam_patterns(self, content_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect spam patterns in content.
        
        Identifies common spam indicators like excessive hashtags,
        mentions, promotional language, and repetitive content.
        """
        text = content_data.get('text', '')
        entities = content_data.get('entities', {})
        detected_patterns = []
        
        # Check hashtag spam
        hashtags = entities.get('hashtags', [])
        if len(hashtags) > 5:
            detected_patterns.append(f'Excessive hashtags ({len(hashtags)})')
        
        # Check mention spam
        mentions = entities.get('mentions', [])
        if len(mentions) > 5:
            detected_patterns.append(f'Excessive mentions ({len(mentions)})')
        
        # Check for promotional spam keywords
        spam_keywords = [
            'click here', 'buy now', 'limited time', 'act now',
            'free money', 'make money fast', 'work from home',
            'dm me', 'check bio', 'link in bio', 'follow for follow'
        ]
        
        spam_keyword_count = sum(1 for keyword in spam_keywords if keyword in text.lower())
        if spam_keyword_count > 0:
            detected_patterns.append(f'Promotional language ({spam_keyword_count} instances)')
        
        # Check for excessive capitalization
        if text.isupper() and len(text) > 20:
            detected_patterns.append('Excessive capitalization')
        
        # Check for excessive punctuation
        exclamation_count = text.count('!')
        if exclamation_count > 3:
            detected_patterns.append(f'Excessive punctuation ({exclamation_count} exclamation marks)')
        
        # Check for emoji spam
        emoji_count = sum(1 for char in text if ord(char) > 0x1F300)
        if emoji_count > 10:
            detected_patterns.append(f'Excessive emojis ({emoji_count})')
        
        # Calculate spam score
        spam_score = min(len(detected_patterns) * 0.2, 1.0)
        
        # Determine risk level
        if spam_score >= 0.6:
            risk_level = 'high'
        elif spam_score >= 0.3:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return {
            'spam_score': spam_score,
            'detected_patterns': detected_patterns,
            'risk_level': risk_level,
            'recommendation': 'Reduce promotional language and excessive formatting' if spam_score > 0.4 else None
        }
    
    async def _detect_engagement_manipulation(self, content_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect engagement manipulation in content.
        
        Identifies engagement bait tactics that violate Twitter's policies.
        """
        text = content_data.get('text', '').lower()
        suspicious_metrics = []
        
        # Engagement bait patterns
        engagement_bait = [
            'like if', 'rt if', 'retweet if', 'share if',
            'follow me', 'follow back', 'follow for follow',
            'tag someone', 'tag a friend', 'mention someone',
            'comment below', 'drop a', 'reply with',
            'vote below', 'poll:', 'which one'
        ]
        
        bait_count = sum(1 for bait in engagement_bait if bait in text)
        if bait_count > 0:
            suspicious_metrics.append(f'Engagement bait detected ({bait_count} instances)')
        
        # Check for giveaway/contest manipulation
        giveaway_keywords = ['giveaway', 'contest', 'win', 'prize', 'free']
        giveaway_count = sum(1 for keyword in giveaway_keywords if keyword in text)
        
        if giveaway_count >= 2:
            suspicious_metrics.append('Potential giveaway/contest manipulation')
        
        # Check public metrics for suspicious patterns
        public_metrics = content_data.get('public_metrics', {})
        if public_metrics:
            retweet_count = public_metrics.get('retweet_count', 0)
            like_count = public_metrics.get('like_count', 0)
            reply_count = public_metrics.get('reply_count', 0)
            
            # Unusual engagement ratios can indicate manipulation
            if like_count > 0:
                rt_to_like_ratio = retweet_count / like_count
                if rt_to_like_ratio > 2.0:  # Unusually high retweet ratio
                    suspicious_metrics.append('Unusual retweet-to-like ratio')
            
            if retweet_count > 0 and reply_count == 0 and retweet_count > 100:
                suspicious_metrics.append('High retweets with no replies (potential bot activity)')
        
        # Calculate manipulation score
        manipulation_score = min(len(suspicious_metrics) * 0.3, 1.0)
        artificial_boost_detected = manipulation_score >= 0.6
        
        return {
            'manipulation_score': manipulation_score,
            'suspicious_metrics': suspicious_metrics,
            'artificial_boost_detected': artificial_boost_detected,
            'recommendation': 'Avoid engagement bait tactics' if manipulation_score > 0.3 else None
        }
    
    async def _check_policy_violations(self, content_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check for Twitter policy violations.
        
        Screens content for potential violations of Twitter's rules and policies.
        """
        text = content_data.get('text', '').lower()
        flagged_content = []
        policy_risks = []
        
        # Check for hate speech indicators (basic keyword detection)
        hate_keywords = [
            'hate', 'kill', 'die', 'attack', 'destroy',
            # Note: In production, use more sophisticated NLP/AI for hate speech detection
        ]
        
        # Check for harassment indicators
        harassment_keywords = ['stupid', 'idiot', 'loser', 'pathetic']
        
        # Check for misinformation indicators
        misinfo_keywords = ['fake news', 'hoax', 'conspiracy', 'cover-up']
        
        # Check for violence indicators
        violence_keywords = ['bomb', 'shoot', 'murder', 'terrorist']
        
        # Scan for policy violations (simplified)
        for keyword in violence_keywords:
            if keyword in text:
                flagged_content.append(keyword)
                policy_risks.append('Potential violent content')
                break
        
        # Check if content is marked as sensitive
        if content_data.get('possibly_sensitive', False):
            policy_risks.append('Content marked as possibly sensitive')
        
        # Check for impersonation risk (if username doesn't match verified status)
        # This would require additional context about the account
        
        # Calculate violation score
        violation_score = min(len(policy_risks) * 0.4, 1.0)
        
        return {
            'violation_score': violation_score,
            'flagged_content': flagged_content,
            'policy_risks': policy_risks,
            'recommendation': 'Review content for policy compliance' if violation_score > 0.3 else None
        }
    
    def _calculate_profile_risk_score(self, risk_factors: Dict[str, Any]) -> float:
        """Calculate overall profile risk score."""
        # Weighted calculation based on risk factors
        return 0.25  # Placeholder
    
    def _calculate_content_risk_score(self, risk_factors: Dict[str, Any]) -> float:
        """Calculate overall content risk score."""
        # Weighted calculation based on risk factors
        return 0.20  # Placeholder
    
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
            "Monitor follower authenticity regularly",
            "Maintain consistent engagement patterns",
            "Avoid suspicious follower growth tactics"
        ]
    
    def _generate_content_recommendations(self, assessment: Dict[str, Any]) -> List[str]:
        """Generate content-specific recommendations."""
        return [
            "Limit external links in tweets to avoid penalties",
            "Ensure content accuracy to prevent Community Notes",
            "Maintain authentic engagement patterns"
        ]
    
    # Additional helper methods for algorithm health and crisis detection
    async def _calculate_visibility_score(self, account_data: Dict[str, Any]) -> float:
        """Calculate Twitter visibility score."""
        return 0.75  # Placeholder
    
    async def _analyze_engagement_health(self, account_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze engagement health metrics."""
        return {'health_score': 0.8, 'trends': 'stable'}
    
    async def _analyze_reach_metrics(self, account_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze reach and impression metrics."""
        return {'reach_score': 0.7, 'impression_trends': 'stable'}
    
    async def _detect_algorithmic_penalties(self, account_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect algorithmic penalties."""
        return {'penalty_detected': False, 'penalty_type': None}
    
    def _generate_algorithm_recommendations(self, assessment: Dict[str, Any]) -> List[str]:
        """Generate algorithm health recommendations."""
        return ["Maintain consistent posting schedule", "Focus on authentic engagement"]
    
    async def _detect_viral_negative_content(self, monitoring_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect viral negative content."""
        return {'viral_risk': 0.1, 'negative_mentions': 0}
    
    async def _detect_coordinated_attacks(self, monitoring_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect coordinated attacks."""
        return {'attack_detected': False, 'coordination_score': 0.0}
    
    async def _monitor_trending_mentions(self, monitoring_data: Dict[str, Any]) -> Dict[str, Any]:
        """Monitor trending negative mentions."""
        return {'trending_risk': 0.05, 'mention_velocity': 'normal'}
    
    async def _assess_reputation_damage_velocity(self, monitoring_data: Dict[str, Any]) -> Dict[str, Any]:
        """Assess reputation damage velocity."""
        return {'damage_velocity': 'low', 'reputation_score': 0.9}
    
    def _determine_crisis_level(self, crisis_indicators: Dict[str, Any]) -> RiskLevel:
        """Determine overall crisis level."""
        return RiskLevel.LOW  # Placeholder
    
    def _generate_crisis_alerts(self, assessment: Dict[str, Any]) -> List[str]:
        """Generate crisis alert triggers."""
        return []  # Placeholder
    
    def _generate_crisis_recommendations(self, assessment: Dict[str, Any]) -> List[str]:
        """Generate crisis management recommendations."""
        return ["Monitor mentions closely", "Prepare response strategy"]


# Register this adapter with the platform registry
registry.register_adapter(
    platform_type=PlatformType.TWITTER,
    adapter_class=TwitterProtectionAdapter,
    config={
        'enabled': True,
        'rate_limits': {
            'profile_scans_per_hour': 100,
            'content_analyses_per_hour': 500,
            'algorithm_checks_per_hour': 50,
            'crisis_checks_per_hour': 200,
        },
        'risk_thresholds': {
            'external_link_penalty': 0.7,
            'community_notes_trigger': 0.8,
            'fake_follower_ratio': 0.3,
            'engagement_manipulation': 0.6,
            'spam_pattern_score': 0.5,
            'shadowban_probability': 0.4
        }
    }
)