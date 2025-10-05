"""
Meta Platform Protection Adapter (Facebook & Instagram)

This module implements Meta-specific social media protection functionality,
including link reach reduction detection, content review flagging,
engagement bait detection, and ad policy violation monitoring.

Covers both Facebook and Instagram protection strategies.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from enum import Enum
import httpx
import asyncio

from .base_adapter import SocialPlatformAdapter, PlatformType, RiskLevel
from ..registry import registry
from ..logging_utils import get_logger
from ..exceptions import PlatformAdapterError

logger = get_logger("MetaProtectionAdapter")


class MetaRiskFactor(Enum):
    """Meta-specific risk factors for content and profile analysis."""
    LINK_REACH_REDUCTION = "link_reach_reduction"
    CONTENT_REVIEW_FLAG = "content_review_flag"
    ENGAGEMENT_BAIT = "engagement_bait"
    AD_POLICY_VIOLATION = "ad_policy_violation"
    SPAM_DETECTION = "spam_detection"
    FAKE_ENGAGEMENT = "fake_engagement"
    COMMUNITY_STANDARDS = "community_standards"
    ALGORITHM_PENALTY = "algorithm_penalty"


class MetaContentType(Enum):
    """Meta content types for platform-specific analysis."""
    FACEBOOK_POST = "facebook_post"
    INSTAGRAM_POST = "instagram_post"
    INSTAGRAM_STORY = "instagram_story"
    FACEBOOK_AD = "facebook_ad"
    INSTAGRAM_AD = "instagram_ad"
    REEL = "reel"


class MetaProtectionAdapter(SocialPlatformAdapter):
    """
    Meta platform adapter for Facebook and Instagram protection.
    
    Implements Meta-specific risk analysis including:
    - Link reach reduction algorithms
    - Content review and flagging systems
    - Engagement bait detection
    - Ad policy compliance monitoring
    - Community standards enforcement
    """
    
    # Facebook Graph API endpoints
    GRAPH_API_BASE = "https://graph.facebook.com/v18.0"
    INSTAGRAM_GRAPH_API_BASE = "https://graph.facebook.com/v18.0"
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize Meta protection adapter.
        
        Args:
            config: Platform-specific configuration including API credentials,
                   risk thresholds, and feature flags for both Facebook and Instagram
        """
        super().__init__(PlatformType.META_FACEBOOK, config or {})
        self.risk_thresholds = self._load_risk_thresholds()
        self.fb_client: Optional[httpx.AsyncClient] = None
        self.ig_client: Optional[httpx.AsyncClient] = None
        self._initialize_api_clients()

        
    def _initialize_api_clients(self) -> None:
        """
        Initialize Facebook and Instagram Graph API clients with authentication.
        
        Supports:
        - Facebook Graph API with App Access Token or User Access Token
        - Instagram Graph API with User Access Token
        
        Rate limiting is handled through request tracking and backoff.
        """
        try:
            # Get API credentials from config
            fb_access_token = self.config.get('facebook_access_token')
            fb_app_id = self.config.get('facebook_app_id')
            fb_app_secret = self.config.get('facebook_app_secret')
            ig_access_token = self.config.get('instagram_access_token')
            
            # Initialize Facebook client
            if fb_access_token:
                self.fb_client = httpx.AsyncClient(
                    base_url=self.GRAPH_API_BASE,
                    timeout=30.0,
                    headers={
                        'Authorization': f'Bearer {fb_access_token}',
                        'Content-Type': 'application/json'
                    }
                )
                logger.info("Facebook Graph API client initialized with access token")
            elif fb_app_id and fb_app_secret:
                # Generate app access token
                app_token = f"{fb_app_id}|{fb_app_secret}"
                self.fb_client = httpx.AsyncClient(
                    base_url=self.GRAPH_API_BASE,
                    timeout=30.0,
                    params={'access_token': app_token}
                )
                logger.info("Facebook Graph API client initialized with app token")
            else:
                logger.warning("Facebook API credentials not configured. Facebook features will be disabled.")
                
            # Initialize Instagram client
            if ig_access_token:
                self.ig_client = httpx.AsyncClient(
                    base_url=self.INSTAGRAM_GRAPH_API_BASE,
                    timeout=30.0,
                    headers={
                        'Authorization': f'Bearer {ig_access_token}',
                        'Content-Type': 'application/json'
                    }
                )
                logger.info("Instagram Graph API client initialized with access token")
            else:
                logger.warning("Instagram API credentials not configured. Instagram features will be disabled.")
            
            # Set enabled status based on client availability
            self.is_enabled = (self.fb_client is not None) or (self.ig_client is not None)
            
            # Initialize rate limit tracking
            self._rate_limit_status = {
                'facebook': {
                    'last_reset': datetime.utcnow(),
                    'requests_made': 0,
                    'limit_reached': False
                },
                'instagram': {
                    'last_reset': datetime.utcnow(),
                    'requests_made': 0,
                    'limit_reached': False
                }
            }
                
        except Exception as e:
            logger.error(f"Failed to initialize Meta API clients: {str(e)}")
            self.is_enabled = False
            self.fb_client = None
            self.ig_client = None
    
    async def validate_credentials(self) -> bool:
        """
        Validate Meta API credentials and permissions.
        
        Returns:
            True if credentials are valid and have required permissions
        """
        validation_results = {}
        
        # Validate Facebook credentials
        if self.fb_client:
            try:
                response = await self.fb_client.get('/me', params={'fields': 'id,name'})
                if response.status_code == 200:
                    data = response.json()
                    logger.info(f"Facebook API credentials validated for user/app: {data.get('name', 'unknown')}")
                    validation_results['facebook'] = True
                else:
                    logger.error(f"Facebook API credential validation failed: {response.status_code}")
                    validation_results['facebook'] = False
            except Exception as e:
                logger.error(f"Facebook API credential validation error: {str(e)}")
                validation_results['facebook'] = False
        
        # Validate Instagram credentials
        if self.ig_client:
            try:
                response = await self.ig_client.get('/me', params={'fields': 'id,username'})
                if response.status_code == 200:
                    data = response.json()
                    logger.info(f"Instagram API credentials validated for user: {data.get('username', 'unknown')}")
                    validation_results['instagram'] = True
                else:
                    logger.error(f"Instagram API credential validation failed: {response.status_code}")
                    validation_results['instagram'] = False
            except Exception as e:
                logger.error(f"Instagram API credential validation error: {str(e)}")
                validation_results['instagram'] = False
        
        return any(validation_results.values())
