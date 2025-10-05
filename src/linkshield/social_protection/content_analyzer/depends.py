#!/usr/bin/env python3
"""
Content Analyzer Dependencies

Dependency injection providers for content analyzer services.
"""

from fastapi import Depends

from linkshield.services.ai_service import AIService
from linkshield.services.depends import get_ai_service
from .content_risk_analyzer import ContentRiskAnalyzer
from .link_penalty_detector import LinkPenaltyDetector
from .spam_pattern_detector import SpamPatternDetector
from .community_notes_analyzer import CommunityNotesAnalyzer


async def get_content_risk_analyzer(
    ai_service: AIService = Depends(get_ai_service)
) -> ContentRiskAnalyzer:
    """
    Get ContentRiskAnalyzer instance for content risk assessment.
    
    Args:
        ai_service: AI service for advanced content analysis
        
    Returns:
        ContentRiskAnalyzer: Configured analyzer instance
    """
    return ContentRiskAnalyzer(ai_service=ai_service)


async def get_link_penalty_detector(
    ai_service: AIService = Depends(get_ai_service)
) -> LinkPenaltyDetector:
    """
    Get LinkPenaltyDetector instance for link penalty detection.
    
    Args:
        ai_service: AI service for link analysis
        
    Returns:
        LinkPenaltyDetector: Configured detector instance
    """
    return LinkPenaltyDetector(ai_service=ai_service)


async def get_spam_pattern_detector(
    ai_service: AIService = Depends(get_ai_service)
) -> SpamPatternDetector:
    """
    Get SpamPatternDetector instance for spam pattern detection.
    
    Args:
        ai_service: AI service for spam classification
        
    Returns:
        SpamPatternDetector: Configured detector instance
    """
    return SpamPatternDetector(ai_service=ai_service)


async def get_community_notes_analyzer(
    ai_service: AIService = Depends(get_ai_service)
) -> CommunityNotesAnalyzer:
    """
    Get CommunityNotesAnalyzer instance for community notes analysis.
    
    Args:
        ai_service: AI service for misinformation detection
        
    Returns:
        CommunityNotesAnalyzer: Configured analyzer instance
    """
    return CommunityNotesAnalyzer(ai_service=ai_service)
