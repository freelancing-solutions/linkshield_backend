"""
Content Risk Analyzer for Social Media Protection.

This module provides comprehensive content risk analysis capabilities for social media content,
including risk scoring, pattern detection, and platform-specific analysis.
"""

import re
import asyncio
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timezone

from src.services.ai_service import AIService
from src.config.settings import get_settings


@dataclass
class ContentRiskResult:
    """Result of content risk analysis."""
    risk_score: int  # 0-100
    risk_level: str  # low, medium, high, critical
    risk_factors: List[str]
    recommendations: List[str]
    platform_specific_risks: Dict[str, Any]
    confidence_score: float  # 0.0-1.0
    analysis_timestamp: str


class ContentRiskAnalyzer:
    """
    Analyzes content for various risk factors that could impact social media performance.
    
    This analyzer evaluates content for engagement killers, algorithm penalties,
    credibility risks, and platform violations that could negatively impact
    social media reach and performance.
    """
    
    def __init__(self, ai_service: AIService):
        self.ai_service = ai_service
        self.settings = get_settings()
        
        # Risk pattern definitions
        self.risk_patterns = {
            "engagement_killers": [
                r"click\s+here",
                r"link\s+in\s+bio",
                r"dm\s+me",
                r"follow\s+for\s+follow",
                r"like\s+and\s+share",
                r"comment\s+below",
                r"tag\s+your\s+friends",
                r"swipe\s+up",
                r"check\s+out\s+my\s+profile"
            ],
            "algorithm_penalties": [
                r"buy\s+now",
                r"limited\s+time",
                r"act\s+fast",
                r"don't\s+miss\s+out",
                r"exclusive\s+offer",
                r"guaranteed\s+results",
                r"make\s+money\s+fast",
                r"work\s+from\s+home",
                r"earn\s+\$\d+",
                r"free\s+money"
            ],
            "credibility_risks": [
                r"breaking\s*:",
                r"urgent\s*:",
                r"shocking\s*:",
                r"you\s+won't\s+believe",
                r"doctors\s+hate\s+this",
                r"secret\s+revealed",
                r"this\s+will\s+change\s+everything",
                r"they\s+don't\s+want\s+you\s+to\s+know",
                r"exposed\s*:",
                r"truth\s+revealed"
            ],
            "platform_violations": [
                r"hate\s+speech",
                r"harassment",
                r"bullying",
                r"discrimination",
                r"violence",
                r"self\s+harm",
                r"suicide",
                r"graphic\s+content",
                r"adult\s+content",
                r"nudity"
            ],
            "misinformation_indicators": [
                r"fake\s+news",
                r"conspiracy",
                r"cover\s+up",
                r"mainstream\s+media\s+lies",
                r"wake\s+up\s+sheeple",
                r"do\s+your\s+own\s+research",
                r"they\s+are\s+lying\s+to\s+you"
            ]
        }
        
        # Platform-specific risk factors
        self.platform_risks = {
            "twitter": {
                "hashtag_limit": 2,  # More than 2 hashtags can reduce reach
                "mention_limit": 2,  # Excessive mentions can be flagged as spam
                "link_penalty": True,  # External links reduce organic reach
                "thread_optimization": True
            },
            "facebook": {
                "engagement_bait_penalty": True,
                "external_link_penalty": True,
                "video_preference": True,
                "clickbait_detection": True
            },
            "instagram": {
                "hashtag_limit": 30,
                "story_vs_feed": True,
                "reels_preference": True,
                "shadowban_risks": True
            },
            "linkedin": {
                "professional_tone": True,
                "external_link_penalty": True,
                "native_content_preference": True,
                "industry_relevance": True
            },
            "tiktok": {
                "trend_alignment": True,
                "music_copyright": True,
                "community_guidelines": True,
                "algorithm_sensitivity": True
            }
        }
        
        # Content quality indicators
        self.quality_indicators = {
            "positive": [
                "educational", "informative", "helpful", "valuable",
                "authentic", "original", "creative", "inspiring",
                "professional", "well-researched", "evidence-based"
            ],
            "negative": [
                "clickbait", "misleading", "sensational", "fake",
                "spam", "promotional", "aggressive", "controversial",
                "unverified", "biased", "inflammatory"
            ]
        }
    
    async def analyze_content_risk(self, content: str, platform: str = "general", 
                                 metadata: Optional[Dict[str, Any]] = None) -> ContentRiskResult:
        """
        Analyze content for various risk factors.
        
        Args:
            content: Content text to analyze
            platform: Target platform (twitter, facebook, instagram, etc.)
            metadata: Additional content metadata (hashtags, mentions, links, etc.)
        
        Returns:
            ContentRiskResult with comprehensive risk assessment
        """
        try:
            risk_factors = []
            risk_score = 0
            recommendations = []
            platform_specific_risks = {}
            
            content_lower = content.lower()
            
            # Check for engagement killers
            engagement_killer_count = 0
            for pattern in self.risk_patterns["engagement_killers"]:
                if re.search(pattern, content_lower, re.IGNORECASE):
                    risk_factors.append(f"engagement_killer: {pattern}")
                    engagement_killer_count += 1
                    risk_score += 15
            
            if engagement_killer_count > 0:
                recommendations.append("Avoid direct call-to-action phrases that algorithms penalize")
            
            # Check for algorithm penalty triggers
            penalty_count = 0
            for pattern in self.risk_patterns["algorithm_penalties"]:
                if re.search(pattern, content_lower, re.IGNORECASE):
                    risk_factors.append(f"algorithm_penalty: {pattern}")
                    penalty_count += 1
                    risk_score += 20
            
            if penalty_count > 0:
                recommendations.append("Remove promotional language that triggers algorithm penalties")
            
            # Check for credibility risks
            credibility_risk_count = 0
            for pattern in self.risk_patterns["credibility_risks"]:
                if re.search(pattern, content_lower, re.IGNORECASE):
                    risk_factors.append(f"credibility_risk: {pattern}")
                    credibility_risk_count += 1
                    risk_score += 25
            
            if credibility_risk_count > 0:
                recommendations.append("Avoid sensational language that may trigger fact-checking")
            
            # Check for platform violations
            violation_count = 0
            for pattern in self.risk_patterns["platform_violations"]:
                if re.search(pattern, content_lower, re.IGNORECASE):
                    risk_factors.append(f"platform_violation: {pattern}")
                    violation_count += 1
                    risk_score += 40
            
            if violation_count > 0:
                recommendations.append("Review content for potential community guidelines violations")
            
            # Check for misinformation indicators
            misinfo_count = 0
            for pattern in self.risk_patterns["misinformation_indicators"]:
                if re.search(pattern, content_lower, re.IGNORECASE):
                    risk_factors.append(f"misinformation_indicator: {pattern}")
                    misinfo_count += 1
                    risk_score += 30
            
            if misinfo_count > 0:
                recommendations.append("Ensure claims are backed by credible sources")
            
            # Platform-specific analysis
            if platform in self.platform_risks:
                platform_analysis = await self._analyze_platform_specific_risks(
                    content, platform, metadata
                )
                platform_specific_risks = platform_analysis
                risk_score += platform_analysis.get("penalty_score", 0)
                
                if platform_analysis.get("recommendations"):
                    recommendations.extend(platform_analysis["recommendations"])
            
            # Content quality analysis
            quality_analysis = await self._analyze_content_quality(content)
            risk_score += quality_analysis.get("quality_penalty", 0)
            
            if quality_analysis.get("recommendations"):
                recommendations.extend(quality_analysis["recommendations"])
            
            # AI-powered risk analysis
            if self.ai_service:
                ai_analysis = await self._ai_risk_analysis(content, platform)
                risk_score += ai_analysis.get("ai_risk_score", 0)
                
                if ai_analysis.get("ai_risk_factors"):
                    risk_factors.extend(ai_analysis["ai_risk_factors"])
                
                if ai_analysis.get("ai_recommendations"):
                    recommendations.extend(ai_analysis["ai_recommendations"])
            
            # Normalize risk score
            risk_score = min(100, max(0, risk_score))
            
            # Determine risk level
            if risk_score >= 80:
                risk_level = "critical"
            elif risk_score >= 60:
                risk_level = "high"
            elif risk_score >= 30:
                risk_level = "medium"
            else:
                risk_level = "low"
            
            # Calculate confidence score
            confidence_score = self._calculate_confidence_score(
                len(risk_factors), penalty_count, violation_count
            )
            
            return ContentRiskResult(
                risk_score=risk_score,
                risk_level=risk_level,
                risk_factors=risk_factors,
                recommendations=list(set(recommendations)),  # Remove duplicates
                platform_specific_risks=platform_specific_risks,
                confidence_score=confidence_score,
                analysis_timestamp=datetime.now(timezone.utc).isoformat()
            )
            
        except Exception as e:
            # Return safe default result on error
            return ContentRiskResult(
                risk_score=50,
                risk_level="medium",
                risk_factors=[f"analysis_error: {str(e)}"],
                recommendations=["Manual review recommended due to analysis error"],
                platform_specific_risks={},
                confidence_score=0.0,
                analysis_timestamp=datetime.now(timezone.utc).isoformat()
            )
    
    async def _analyze_platform_specific_risks(self, content: str, platform: str, 
                                             metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Analyze platform-specific risk factors."""
        risks = {}
        penalty_score = 0
        recommendations = []
        
        if not metadata:
            metadata = {}
        
        platform_config = self.platform_risks.get(platform, {})
        
        if platform == "twitter":
            # Check hashtag usage
            hashtag_count = len(metadata.get("hashtags", []))
            if hashtag_count > platform_config.get("hashtag_limit", 2):
                penalty_score += 10
                recommendations.append("Reduce hashtag count to improve reach")
            
            # Check mention usage
            mention_count = len(metadata.get("mentions", []))
            if mention_count > platform_config.get("mention_limit", 2):
                penalty_score += 15
                recommendations.append("Limit mentions to avoid spam detection")
            
            # Check for external links
            if metadata.get("has_external_links", False):
                penalty_score += 5
                recommendations.append("Consider using Twitter's native features instead of external links")
        
        elif platform == "facebook":
            # Check for engagement bait
            engagement_bait_patterns = [
                r"like\s+if\s+you\s+agree",
                r"share\s+if\s+you",
                r"comment\s+your\s+thoughts",
                r"tag\s+someone\s+who"
            ]
            
            for pattern in engagement_bait_patterns:
                if re.search(pattern, content.lower(), re.IGNORECASE):
                    penalty_score += 20
                    recommendations.append("Avoid engagement bait tactics")
                    break
        
        elif platform == "instagram":
            # Check hashtag usage
            hashtag_count = len(metadata.get("hashtags", []))
            if hashtag_count > platform_config.get("hashtag_limit", 30):
                penalty_score += 15
                recommendations.append("Reduce hashtag count to stay within Instagram limits")
            
            # Check for shadowban risk hashtags
            shadowban_risk_hashtags = metadata.get("shadowban_risk_hashtags", [])
            if shadowban_risk_hashtags:
                penalty_score += 25
                recommendations.append("Remove hashtags that may trigger shadowbans")
        
        risks.update({
            "penalty_score": penalty_score,
            "recommendations": recommendations,
            "platform_specific_flags": platform_config
        })
        
        return risks
    
    async def _analyze_content_quality(self, content: str) -> Dict[str, Any]:
        """Analyze content quality indicators."""
        quality_penalty = 0
        recommendations = []
        
        content_lower = content.lower()
        
        # Check for positive quality indicators
        positive_count = sum(1 for indicator in self.quality_indicators["positive"] 
                           if indicator in content_lower)
        
        # Check for negative quality indicators
        negative_count = sum(1 for indicator in self.quality_indicators["negative"] 
                           if indicator in content_lower)
        
        # Calculate quality penalty
        if negative_count > positive_count:
            quality_penalty = (negative_count - positive_count) * 5
            recommendations.append("Improve content quality by removing negative indicators")
        
        # Check content length
        if len(content) < 50:
            quality_penalty += 10
            recommendations.append("Consider adding more substantial content")
        elif len(content) > 2000:
            quality_penalty += 5
            recommendations.append("Consider breaking long content into multiple posts")
        
        # Check for excessive capitalization
        caps_ratio = sum(1 for c in content if c.isupper()) / len(content) if content else 0
        if caps_ratio > 0.3:
            quality_penalty += 15
            recommendations.append("Reduce excessive capitalization")
        
        # Check for excessive punctuation
        exclamation_count = content.count('!')
        if exclamation_count > 3:
            quality_penalty += 10
            recommendations.append("Reduce excessive punctuation")
        
        return {
            "quality_penalty": quality_penalty,
            "recommendations": recommendations,
            "positive_indicators": positive_count,
            "negative_indicators": negative_count
        }
    
    async def _ai_risk_analysis(self, content: str, platform: str) -> Dict[str, Any]:
        """Perform AI-powered risk analysis."""
        try:
            if not self.ai_service:
                return {"ai_risk_score": 0, "ai_risk_factors": [], "ai_recommendations": []}
            
            # Use AI service for advanced analysis
            ai_result = await self.ai_service.analyze_content(content, f"social_media_{platform}")
            
            ai_risk_score = 0
            ai_risk_factors = []
            ai_recommendations = []
            
            # Extract risk information from AI analysis
            if ai_result.get("threat_detected", False):
                ai_risk_score += 30
                ai_risk_factors.extend(ai_result.get("threat_types", []))
                ai_recommendations.append("Review content for potential threats detected by AI")
            
            # Check sentiment analysis
            sentiment_analysis = ai_result.get("detailed_analysis", {}).get("sentiment_analysis", {})
            if sentiment_analysis.get("suspicious", False):
                ai_risk_score += 15
                ai_risk_factors.append("suspicious_sentiment")
                ai_recommendations.append("Consider adjusting content tone")
            
            # Check spam analysis
            spam_analysis = ai_result.get("detailed_analysis", {}).get("spam_analysis", {})
            if spam_analysis.get("spam_detected", False):
                ai_risk_score += 25
                ai_risk_factors.append("spam_patterns_detected")
                ai_recommendations.append("Remove spam-like content patterns")
            
            return {
                "ai_risk_score": ai_risk_score,
                "ai_risk_factors": ai_risk_factors,
                "ai_recommendations": ai_recommendations
            }
            
        except Exception:
            return {"ai_risk_score": 0, "ai_risk_factors": [], "ai_recommendations": []}
    
    def _calculate_confidence_score(self, risk_factor_count: int, penalty_count: int, 
                                  violation_count: int) -> float:
        """Calculate confidence score for the analysis."""
        # Base confidence
        confidence = 0.7
        
        # Increase confidence with more detected patterns
        if risk_factor_count > 0:
            confidence += min(0.2, risk_factor_count * 0.05)
        
        # High confidence for serious violations
        if violation_count > 0:
            confidence = min(0.95, confidence + 0.15)
        
        # High confidence for multiple penalties
        if penalty_count > 2:
            confidence = min(0.9, confidence + 0.1)
        
        return round(confidence, 2)