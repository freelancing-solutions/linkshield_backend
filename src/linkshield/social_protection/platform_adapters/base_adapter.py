"""
Base Platform Adapter

Abstract base class that defines the interface for all social media platform adapters.
Each platform-specific adapter must implement these methods to provide consistent
functionality across different social media platforms.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from datetime import datetime

from ..types import PlatformType, RiskLevel
from ..data_models import (
    ProfileScanRequest,
    ProfileScanResult,
    ContentAnalysisRequest,
    ContentAnalysisResult
)


class SocialPlatformAdapter(ABC):
    """
    Abstract base class for social media platform adapters.
    
    Each platform adapter provides specialized analysis capabilities
    for their respective social media platform, including profile
    security auditing, content risk assessment, algorithm health
    monitoring, and crisis detection.
    """
    
    def __init__(self, platform_type: PlatformType, config: Dict[str, Any]):
        """
        Initialize the platform adapter.
        
        Args:
            platform_type: The type of social media platform
            config: Platform-specific configuration settings
        """
        self.platform_type = platform_type
        self.config = config
        self.is_enabled = config.get("enabled", True)
        
    @property
    def platform_name(self) -> str:
        """Get the human-readable platform name"""
        return self.platform_type.value.replace("_", " ").title()
    
    @abstractmethod
    async def scan_profile(self, request: ProfileScanRequest) -> ProfileScanResult:
        """
        Perform comprehensive profile security audit.
        
        Analyzes profile for:
        - Follower authenticity
        - Account age and verification status
        - Profile completeness
        - Suspicious activity patterns
        
        Args:
            request: Profile scan request with platform-specific data
            
        Returns:
            Detailed profile security assessment
        """
        pass
    
    @abstractmethod
    async def analyze_content(self, request: ContentAnalysisRequest) -> ContentAnalysisResult:
        """
        Analyze content for platform-specific risks.
        
        Evaluates content for:
        - External link penalties
        - Spam pattern detection
        - Community guideline violations
        - Engagement bait identification
        
        Args:
            request: Content analysis request with post data
            
        Returns:
            Content risk assessment with recommendations
        """
        pass
    
    @abstractmethod
    async def get_algorithm_health(self, profile_id: str, timeframe_days: int = 30) -> Dict[str, Any]:
        """
        Assess algorithmic health and visibility metrics.
        
        Analyzes:
        - Platform visibility scoring
        - Engagement pattern changes
        - Potential algorithmic penalties
        - Shadow ban indicators
        
        Args:
            profile_id: Platform-specific profile identifier
            timeframe_days: Analysis timeframe in days
            
        Returns:
            Algorithm health metrics and recommendations
        """
        pass
    
    @abstractmethod
    async def detect_crisis_signals(self, profile_id: str) -> Dict[str, Any]:
        """
        Detect crisis signals and reputation threats.
        
        Monitors for:
        - Sudden negative sentiment spikes
        - Viral negative content
        - Mass reporting campaigns
        - Coordinated attacks
        
        Args:
            profile_id: Platform-specific profile identifier
            
        Returns:
            Crisis detection results with severity assessment
        """
        pass
    
    async def validate_credentials(self) -> bool:
        """
        Validate platform API credentials and permissions.
        
        Returns:
            True if credentials are valid and have required permissions
        """
        # Default implementation - can be overridden by specific adapters
        return self.is_enabled
    
    def get_rate_limits(self) -> Dict[str, int]:
        """
        Get platform-specific rate limits.
        
        Returns:
            Dictionary of rate limits for different operations
        """
        return self.config.get("rate_limits", {
            "profile_scans_per_hour": 100,
            "content_analyses_per_hour": 500,
            "algorithm_checks_per_hour": 50,
            "crisis_checks_per_hour": 200,
        })
    
    def get_supported_features(self) -> List[str]:
        """
        Get list of features supported by this platform adapter.
        
        Returns:
            List of supported feature names
        """
        return [
            "profile_scanning",
            "content_analysis", 
            "algorithm_health",
            "crisis_detection",
        ]
    
    def _calculate_risk_score(self, factors: Dict[str, float], weights: Dict[str, float]) -> float:
        """
        Calculate weighted risk score from multiple factors.
        
        Args:
            factors: Dictionary of risk factors with their values (0.0-1.0)
            weights: Dictionary of weights for each factor
            
        Returns:
            Weighted risk score (0.0-1.0)
        """
        total_score = 0.0
        total_weight = 0.0
        
        for factor, value in factors.items():
            weight = weights.get(factor, 1.0)
            total_score += value * weight
            total_weight += weight
            
        return total_score / total_weight if total_weight > 0 else 0.0
    
    def _determine_risk_level(self, risk_score: float) -> RiskLevel:
        """
        Determine risk level from numerical score.
        
        Args:
            risk_score: Numerical risk score (0.0-1.0)
            
        Returns:
            Corresponding risk level enum
        """
        if risk_score >= 0.8:
            return RiskLevel.CRITICAL
        elif risk_score >= 0.6:
            return RiskLevel.HIGH
        elif risk_score >= 0.3:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW