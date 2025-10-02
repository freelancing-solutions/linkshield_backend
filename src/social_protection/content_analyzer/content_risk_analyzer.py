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
        
        # Risk pattern definitions - comprehensive pattern matching for content analysis
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
                r"check\s+out\s+my\s+profile",
                r"follow\s+back",
                r"f4f",
                r"l4l",
                r"like\s+for\s+like",
                r"follow\s+me\s+and\s+i'll\s+follow\s+you"
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
                r"free\s+money",
                r"get\s+rich\s+quick",
                r"passive\s+income",
                r"financial\s+freedom",
                r"no\s+risk",
                r"100%\s+guaranteed"
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
                r"truth\s+revealed",
                r"what\s+they're\s+hiding",
                r"the\s+real\s+truth",
                r"mainstream\s+media\s+won't\s+tell\s+you"
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
                r"nudity",
                r"sexual\s+content",
                r"explicit\s+material",
                r"gore",
                r"terrorist\s+content"
            ],
            "misinformation_indicators": [
                r"fake\s+news",
                r"conspiracy",
                r"cover\s+up",
                r"mainstream\s+media\s+lies",
                r"wake\s+up\s+sheeple",
                r"do\s+your\s+own\s+research",
                r"they\s+are\s+lying\s+to\s+you",
                r"hoax",
                r"false\s+flag",
                r"deep\s+state",
                r"big\s+pharma\s+doesn't\s+want"
            ],
            "phishing_indicators": [
                r"verify\s+your\s+account",
                r"suspended\s+account",
                r"click\s+here\s+immediately",
                r"urgent\s+action\s+required",
                r"confirm\s+your\s+identity",
                r"update\s+payment\s+information",
                r"security\s+alert",
                r"unusual\s+activity\s+detected",
                r"temporary\s+suspension",
                r"account\s+will\s+be\s+closed"
            ],
            "scam_indicators": [
                r"congratulations.*won",
                r"claim\s+your\s+prize",
                r"you've\s+been\s+selected",
                r"winner\s+notification",
                r"free\s+gift",
                r"no\s+purchase\s+necessary",
                r"risk\s+free",
                r"money\s+back\s+guarantee"
            ]
        }
        
        # Compiled regex patterns for performance
        self._compiled_patterns = {
            category: [re.compile(pattern, re.IGNORECASE) 
                      for pattern in patterns]
            for category, patterns in self.risk_patterns.items()
        }
        
        # Platform-specific risk factors
        self.platform_risks = {
            "twitter": {
                "hashtag_limit": 2,
                "mention_limit": 2,
                "link_penalty": True,
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
    
    def _analyze_patterns(self, content: str) -> Dict[str, Any]:
        """
        Perform comprehensive pattern-based risk analysis.
        
        Args:
            content: Content text to analyze
            
        Returns:
            Dictionary with pattern analysis results
        """
        pattern_results = {}
        total_risk_score = 0
        all_risk_factors = []
        all_recommendations = []
        
        content_lower = content.lower()
        
        # Analyze each pattern category
        for category, compiled_patterns in self._compiled_patterns.items():
            matches = []
            matched_patterns = []
            
            for pattern in compiled_patterns:
                found = pattern.findall(content_lower)
                if found:
                    matches.extend(found)
                    matched_patterns.append(pattern.pattern)
            
            if matches:
                # Calculate category-specific risk score
                category_risk_score = self._calculate_category_risk_score(
                    category, len(matches), len(matched_patterns)
                )
                
                pattern_results[category] = {
                    "match_count": len(matches),
                    "unique_patterns": len(matched_patterns),
                    "matched_patterns": matched_patterns[:5],
                    "risk_score": category_risk_score
                }
                
                total_risk_score += category_risk_score
                all_risk_factors.append(f"{category}_{len(matches)}_matches")
                
                # Add category-specific recommendations
                recommendation = self._get_category_recommendation(category)
                if recommendation:
                    all_recommendations.append(recommendation)
        
        return {
            "pattern_results": pattern_results,
            "total_pattern_risk_score": min(100, total_risk_score),
            "risk_factors": all_risk_factors,
            "recommendations": all_recommendations,
            "patterns_detected": len(pattern_results) > 0
        }
    
    def _calculate_category_risk_score(self, category: str, match_count: int, 
                                      unique_pattern_count: int) -> int:
        """Calculate risk score for a specific pattern category."""
        category_weights = {
            "platform_violations": 40,
            "phishing_indicators": 35,
            "scam_indicators": 30,
            "misinformation_indicators": 30,
            "credibility_risks": 25,
            "algorithm_penalties": 20,
            "engagement_killers": 15
        }
        
        base_score = category_weights.get(category, 10)
        match_multiplier = min(3, 1 + (match_count - 1) * 0.3)
        pattern_multiplier = min(2, 1 + (unique_pattern_count - 1) * 0.2)
        
        return int(base_score * match_multiplier * pattern_multiplier)
    
    def _get_category_recommendation(self, category: str) -> Optional[str]:
        """Get recommendation for a specific risk category."""
        recommendations = {
            "engagement_killers": "Remove direct call-to-action phrases that algorithms penalize",
            "algorithm_penalties": "Eliminate promotional language that triggers algorithm penalties",
            "credibility_risks": "Avoid sensational language that may trigger fact-checking",
            "platform_violations": "Review content for potential community guidelines violations",
            "misinformation_indicators": "Ensure claims are backed by credible sources",
            "phishing_indicators": "Remove suspicious language that resembles phishing attempts",
            "scam_indicators": "Eliminate language patterns associated with scams"
        }
        return recommendations.get(category)
    
    async def _analyze_with_ai(self, content: str, platform: str) -> Dict[str, Any]:
        """
        Perform AI-powered content analysis using the AI service.
        
        Args:
            content: Content text to analyze
            platform: Platform type (twitter, facebook, etc.)
            
        Returns:
            Dictionary with AI analysis results
        """
        try:
            # Use AI service for comprehensive content analysis
            ai_analysis = await self.ai_service.analyze_content(
                content=content,
                url=f"social://{platform}/content"
            )
            
            # Extract relevant risk information from AI analysis
            threat_detected = ai_analysis.get("threat_detected", False)
            threat_types = ai_analysis.get("threat_types", [])
            confidence_score = ai_analysis.get("confidence_score", 0)
            detailed_analysis = ai_analysis.get("detailed_analysis", {})
            
            # Calculate AI-based risk score
            ai_risk_score = 0
            if threat_detected:
                ai_risk_score = confidence_score
            
            # Extract quality score from AI analysis
            quality_analysis = detailed_analysis.get("quality_analysis", {})
            quality_score = quality_analysis.get("quality_score", 50)
            
            # Adjust risk score based on quality
            if quality_score < 30:
                ai_risk_score = max(ai_risk_score, 70)
            elif quality_score < 50:
                ai_risk_score = max(ai_risk_score, 40)
            
            # Extract sentiment information
            sentiment_analysis = detailed_analysis.get("sentiment_analysis", {})
            sentiment = sentiment_analysis.get("sentiment", "neutral")
            sentiment_suspicious = sentiment_analysis.get("suspicious", False)
            
            if sentiment_suspicious:
                ai_risk_score = max(ai_risk_score, 50)
            
            # Extract spam indicators
            spam_analysis = detailed_analysis.get("spam_analysis", {})
            is_spam = spam_analysis.get("is_spam", False)
            spam_confidence = spam_analysis.get("confidence_score", 0)
            
            if is_spam:
                ai_risk_score = max(ai_risk_score, spam_confidence)
            
            # Build risk factors from AI analysis
            ai_risk_factors = []
            if threat_detected:
                ai_risk_factors.extend([f"ai_threat_{t}" for t in threat_types])
            if quality_score < 50:
                ai_risk_factors.append(f"ai_low_quality_{quality_score}")
            if sentiment_suspicious:
                ai_risk_factors.append(f"ai_suspicious_sentiment_{sentiment}")
            if is_spam:
                ai_risk_factors.append("ai_spam_detected")
            
            # Build recommendations from AI analysis
            ai_recommendations = []
            if threat_detected:
                ai_recommendations.append("AI detected potential threats - review content carefully")
            if quality_score < 50:
                ai_recommendations.append("Improve content quality and authenticity")
            if is_spam:
                ai_recommendations.append("Remove spam-like patterns and promotional language")
            if sentiment_suspicious:
                ai_recommendations.append("Review content tone and sentiment")
            
            return {
                "ai_risk_score": min(100, int(ai_risk_score)),
                "ai_risk_factors": ai_risk_factors,
                "ai_recommendations": ai_recommendations,
                "threat_detected": threat_detected,
                "threat_types": threat_types,
                "quality_score": quality_score,
                "sentiment": sentiment,
                "is_spam": is_spam,
                "confidence_score": confidence_score,
                "detailed_analysis": detailed_analysis
            }
        
        except Exception as e:
            # Log error and return safe default
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"AI analysis failed: {str(e)}", exc_info=True)
            
            return {
                "ai_risk_score": 0,
                "ai_risk_factors": [],
                "ai_recommendations": [],
                "threat_detected": False,
                "threat_types": [],
                "quality_score": 50,
                "sentiment": "neutral",
                "is_spam": False,
                "confidence_score": 0,
                "error": str(e)
            }
    
    def _apply_platform_rules(self, content: str, platform: str, metadata: Dict) -> Dict[str, Any]:
        """
        Apply platform-specific content rules and analysis.
        
        Args:
            content: Content text to analyze
            platform: Platform type
            metadata: Additional metadata about the content
            
        Returns:
            Dictionary with platform-specific analysis results
        """
        platform_lower = platform.lower()
        platform_config = self.platform_risks.get(platform_lower, {})
        
        platform_risk_score = 0
        platform_risk_factors = []
        platform_recommendations = []
        
        content_lower = content.lower()
        
        # Twitter/X specific rules
        if platform_lower == "twitter":
            # Check hashtag usage
            hashtag_count = content.count('#')
            if hashtag_count > platform_config.get("hashtag_limit", 2):
                platform_risk_score += 15
                platform_risk_factors.append(f"excessive_hashtags_{hashtag_count}")
                platform_recommendations.append(f"Reduce hashtags to {platform_config.get('hashtag_limit', 2)} or fewer")
            
            # Check mention usage
            mention_count = content.count('@')
            if mention_count > platform_config.get("mention_limit", 2):
                platform_risk_score += 10
                platform_risk_factors.append(f"excessive_mentions_{mention_count}")
                platform_recommendations.append(f"Reduce mentions to {platform_config.get('mention_limit', 2)} or fewer")
            
            # Check for external links (Twitter penalizes these)
            if platform_config.get("link_penalty") and ('http://' in content_lower or 'https://' in content_lower):
                platform_risk_score += 20
                platform_risk_factors.append("external_link_penalty")
                platform_recommendations.append("Consider removing external links or use Twitter Cards")
        
        # Facebook specific rules
        elif platform_lower == "facebook":
            # Check for engagement bait
            if platform_config.get("engagement_bait_penalty"):
                engagement_bait_patterns = [
                    "tag someone", "share if", "like if", "comment below",
                    "vote now", "click like", "share this"
                ]
                for pattern in engagement_bait_patterns:
                    if pattern in content_lower:
                        platform_risk_score += 25
                        platform_risk_factors.append(f"engagement_bait_{pattern.replace(' ', '_')}")
                        platform_recommendations.append("Remove engagement bait language")
                        break
            
            # Check for external links
            if platform_config.get("external_link_penalty") and ('http://' in content_lower or 'https://' in content_lower):
                platform_risk_score += 15
                platform_risk_factors.append("external_link_reduces_reach")
                platform_recommendations.append("Native content performs better than external links")
            
            # Check for clickbait
            if platform_config.get("clickbait_detection"):
                clickbait_patterns = ["you won't believe", "shocking", "what happens next", "number 7 will"]
                for pattern in clickbait_patterns:
                    if pattern in content_lower:
                        platform_risk_score += 30
                        platform_risk_factors.append("clickbait_detected")
                        platform_recommendations.append("Remove clickbait language")
                        break
        
        # Instagram specific rules
        elif platform_lower == "instagram":
            # Check hashtag usage
            hashtag_count = content.count('#')
            if hashtag_count > platform_config.get("hashtag_limit", 30):
                platform_risk_score += 20
                platform_risk_factors.append(f"excessive_hashtags_{hashtag_count}")
                platform_recommendations.append(f"Reduce hashtags to {platform_config.get('hashtag_limit', 30)} or fewer")
            
            # Check for shadowban risk hashtags
            if platform_config.get("shadowban_risks"):
                shadowban_indicators = ["follow for follow", "like for like", "f4f", "l4l"]
                for indicator in shadowban_indicators:
                    if indicator in content_lower:
                        platform_risk_score += 35
                        platform_risk_factors.append("shadowban_risk_hashtag")
                        platform_recommendations.append("Remove hashtags associated with shadowban risk")
                        break
        
        # LinkedIn specific rules
        elif platform_lower == "linkedin":
            # Check professional tone
            if platform_config.get("professional_tone"):
                unprofessional_patterns = ["lol", "omg", "wtf", "lmao", "😂", "🔥"]
                for pattern in unprofessional_patterns:
                    if pattern in content_lower:
                        platform_risk_score += 20
                        platform_risk_factors.append("unprofessional_tone")
                        platform_recommendations.append("Maintain professional tone for LinkedIn")
                        break
            
            # Check for external links
            if platform_config.get("external_link_penalty") and ('http://' in content_lower or 'https://' in content_lower):
                platform_risk_score += 15
                platform_risk_factors.append("external_link_penalty")
                platform_recommendations.append("LinkedIn prefers native content over external links")
        
        # TikTok specific rules
        elif platform_lower == "tiktok":
            # Check for trend alignment (simplified check)
            if platform_config.get("trend_alignment"):
                trend_indicators = ["#fyp", "#foryou", "#viral", "#trending"]
                has_trend_hashtags = any(tag in content_lower for tag in trend_indicators)
                if not has_trend_hashtags:
                    platform_risk_score += 10
                    platform_risk_factors.append("missing_trend_hashtags")
                    platform_recommendations.append("Consider adding trending hashtags for better reach")
        
        return {
            "platform_risk_score": min(100, platform_risk_score),
            "platform_risk_factors": platform_risk_factors,
            "platform_recommendations": platform_recommendations,
            "platform_config_applied": platform_lower
        }
    
    def _calculate_overall_risk_score(self, pattern_score: int, ai_score: int, 
                                     platform_score: int) -> int:
        """
        Calculate overall risk score from component scores.
        
        Uses weighted average with emphasis on AI and pattern analysis.
        """
        # Weights for different analysis types
        pattern_weight = 0.4
        ai_weight = 0.4
        platform_weight = 0.2
        
        overall_score = (
            pattern_score * pattern_weight +
            ai_score * ai_weight +
            platform_score * platform_weight
        )
        
        return min(100, int(overall_score))
    
    def _determine_risk_level(self, risk_score: int) -> str:
        """
        Determine risk level from numeric score.
        
        Args:
            risk_score: Numeric risk score (0-100)
            
        Returns:
            Risk level string: low, medium, high, or critical
        """
        if risk_score < 25:
            return "low"
        elif risk_score < 50:
            return "medium"
        elif risk_score < 75:
            return "high"
        else:
            return "critical"
    
    def _calculate_confidence_score(self, pattern_detected: bool, ai_confidence: int,
                                   platform_rules_applied: bool) -> float:
        """
        Calculate overall confidence score for the analysis.
        
        Args:
            pattern_detected: Whether patterns were detected
            ai_confidence: AI analysis confidence (0-100)
            platform_rules_applied: Whether platform rules were applied
            
        Returns:
            Confidence score (0.0-1.0)
        """
        confidence = 0.5  # Base confidence
        
        if pattern_detected:
            confidence += 0.2
        
        if ai_confidence > 0:
            confidence += (ai_confidence / 100) * 0.2
        
        if platform_rules_applied:
            confidence += 0.1
        
        return min(1.0, confidence)
    
    async def analyze_content_risk(self, content: str, platform: str, 
                                  metadata: Optional[Dict] = None) -> ContentRiskResult:
        """
        Perform comprehensive content risk analysis using AI and pattern matching.
        
        This is the main entry point for content risk analysis. It combines:
        - Pattern-based risk detection
        - AI-powered content analysis
        - Platform-specific rules
        
        Args:
            content: Content text to analyze
            platform: Platform type (twitter, facebook, instagram, linkedin, tiktok, etc.)
            metadata: Optional metadata about the content (author, timestamp, etc.)
            
        Returns:
            ContentRiskResult with comprehensive analysis
        """
        try:
            if metadata is None:
                metadata = {}
            
            # 1. Pattern-based analysis (fast, rule-based)
            pattern_analysis = self._analyze_patterns(content)
            
            # 2. AI-powered analysis (comprehensive, ML-based)
            ai_analysis = await self._analyze_with_ai(content, platform)
            
            # 3. Platform-specific rules
            platform_analysis = self._apply_platform_rules(content, platform, metadata)
            
            # 4. Aggregate scores
            overall_risk_score = self._calculate_overall_risk_score(
                pattern_analysis["total_pattern_risk_score"],
                ai_analysis["ai_risk_score"],
                platform_analysis["platform_risk_score"]
            )
            
            # 5. Determine risk level
            risk_level = self._determine_risk_level(overall_risk_score)
            
            # 6. Aggregate risk factors
            all_risk_factors = (
                pattern_analysis["risk_factors"] +
                ai_analysis["ai_risk_factors"] +
                platform_analysis["platform_risk_factors"]
            )
            
            # 7. Aggregate recommendations
            all_recommendations = (
                pattern_analysis["recommendations"] +
                ai_analysis["ai_recommendations"] +
                platform_analysis["platform_recommendations"]
            )
            
            # Remove duplicates while preserving order
            all_risk_factors = list(dict.fromkeys(all_risk_factors))
            all_recommendations = list(dict.fromkeys(all_recommendations))
            
            # 8. Calculate confidence score
            confidence_score = self._calculate_confidence_score(
                pattern_analysis["patterns_detected"],
                ai_analysis["confidence_score"],
                len(platform_analysis["platform_risk_factors"]) > 0
            )
            
            # 9. Build platform-specific risks dictionary
            platform_specific_risks = {
                "pattern_analysis": pattern_analysis["pattern_results"],
                "ai_analysis": {
                    "threat_detected": ai_analysis["threat_detected"],
                    "threat_types": ai_analysis["threat_types"],
                    "quality_score": ai_analysis["quality_score"],
                    "sentiment": ai_analysis["sentiment"],
                    "is_spam": ai_analysis["is_spam"]
                },
                "platform_rules": {
                    "platform": platform_analysis["platform_config_applied"],
                    "risk_factors": platform_analysis["platform_risk_factors"]
                }
            }
            
            # 10. Create and return result
            return ContentRiskResult(
                risk_score=overall_risk_score,
                risk_level=risk_level,
                risk_factors=all_risk_factors,
                recommendations=all_recommendations,
                platform_specific_risks=platform_specific_risks,
                confidence_score=confidence_score,
                analysis_timestamp=datetime.now(timezone.utc).isoformat()
            )
        
        except Exception as e:
            # Log error and return safe default assessment
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Content risk analysis failed: {str(e)}", exc_info=True)
            
            # Return safe default assessment
            return ContentRiskResult(
                risk_score=50,
                risk_level="medium",
                risk_factors=["analysis_error"],
                recommendations=["Unable to complete full analysis - manual review recommended"],
                platform_specific_risks={"error": str(e)},
                confidence_score=0.0,
                analysis_timestamp=datetime.now(timezone.utc).isoformat()
            )
