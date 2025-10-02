#!/usr/bin/env python3
"""
Algorithm Health Dependencies

Dependency injection providers for algorithm health analyzer services.
"""

from .visibility_scorer import VisibilityScorer
from .engagement_analyzer import EngagementAnalyzer
from .penalty_detector import PenaltyDetector
from .shadow_ban_detector import ShadowBanDetector


async def get_visibility_scorer() -> VisibilityScorer:
    """
    Get VisibilityScorer instance for visibility analysis.
    
    Returns:
        VisibilityScorer: Configured scorer instance
    """
    return VisibilityScorer()


async def get_engagement_analyzer() -> EngagementAnalyzer:
    """
    Get EngagementAnalyzer instance for engagement analysis.
    
    Returns:
        EngagementAnalyzer: Configured analyzer instance
    """
    return EngagementAnalyzer()


async def get_penalty_detector() -> PenaltyDetector:
    """
    Get PenaltyDetector instance for penalty detection.
    
    Returns:
        PenaltyDetector: Configured detector instance
    """
    return PenaltyDetector()


async def get_shadow_ban_detector() -> ShadowBanDetector:
    """
    Get ShadowBanDetector instance for shadow ban detection.
    
    Returns:
        ShadowBanDetector: Configured detector instance
    """
    return ShadowBanDetector()
