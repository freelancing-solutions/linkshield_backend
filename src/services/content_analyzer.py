#!/usr/bin/env python3
"""
LinkShield Backend Content Analyzer Service

Specialized content analysis service for social media protection, including
content risk analysis, link penalty detection, spam pattern recognition,
and community notes analysis.
"""

import asyncio
import re
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse
from dataclasses import dataclass

from src.config.settings import get_settings
from src.services.ai_service import AIService


@dataclass
class ContentRiskResult:
    """Result of content risk analysis."""
    risk_level: str  # low, medium, high, critical
    risk_score: int  # 0-100
    risk_factors: List[str]
    recommendations: List[str]
    confidence: float


@dataclass
class LinkPenaltyResult:
    """Result of link penalty analysis."""
    penalty_detected: bool
    penalty_type: str  # algorithm, manual, shadow_ban, none
    penalty_score: int  # 0-100
    affected_metrics: List[str]
    recovery_suggestions: List[str]


@dataclass
class SpamPatternResult:
    """Result of spam pattern detection."""
    is_spam: bool
    spam_type: str  # promotional, malicious, bot_generated, none
    spam_score: int  # 0-100
    detected_patterns: List[str]
    platform_specific_flags: Dict[str, Any]


@dataclass
class CommunityNotesResult:
    """Result of community notes analysis."""
    notes_present: bool
    note_types: List[str]  # misleading, disputed, context_needed, etc.
    credibility_impact: str  # positive, negative, neutral
    suggested_actions: List[str]


class ContentAnalyzerError(Exception):
    """Base content analyzer error."""
    pass


class ContentRiskAnalyzer:
    """
    Analyzes content for various risk factors that could impact social media performance.
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
                r"tag\s+your\s+friends"
            ],
            "algorithm_penalties": [
                r"buy\s+now",
                r"limited\s+time",
                r"act\s+fast",
                r"don't\s+miss\s+out",
                r"exclusive\s+offer",
                r"guaranteed\s+results",
                r"make\s+money\s+fast"
            ],
            "credibility_risks": [
                r"breaking\s*:",
                r"urgent\s*:",
                r"shocking\s*:",
                r"you\s+won't\s+believe",
                r"doctors\s+hate\s+this",
                r"secret\s+revealed",
                r"this\s+will\s+change\s+everything"
            ],
            "platform_violations": [
                r"hate\s+speech",
                r"harassment",
                r"bullying",
                r"discrimination",
                r"violence",
                r"self\s+harm",
                r"suicide"
            ]
        }
        
        # Content quality indicators
        self.quality_indicators = {
            "positive": [
                "research", "study", "data", "evidence", "source",
                "expert", "professional", "verified", "fact",
                "analysis", "insight", "educational", "informative"
            ],
            "negative": [
                "clickbait", "fake", "hoax", "conspiracy", "rumor",
                "unverified", "speculation", "gossip", "sensational"
            ]
        }
    
    async def analyze_content_risk(self, content: str, platform: str = "general") -> ContentRiskResult:
        """
        Analyze content for various risk factors.
        
        Args:
            content: Content text to analyze
            platform: Target platform (twitter, facebook, instagram, etc.)
        
        Returns:
            ContentRiskResult with risk assessment
        """
        try:
            risk_factors = []
            risk_score = 0
            recommendations = []
            
            content_lower = content.lower()
            
            # Check for engagement killers
            for pattern in self.risk_patterns["engagement_killers"]:
                if re.search(pattern, content_lower, re.IGNORECASE):
                    risk_factors.append(f"engagement_killer: {pattern}")
                    risk_score += 15
                    recommendations.append("Avoid direct call-to-action phrases that algorithms penalize")
            
            # Check for algorithm penalty triggers
            for pattern in self.risk_patterns["algorithm_penalties"]:
                if re.search(pattern, content_lower, re.IGNORECASE):
                    risk_factors.append(f"algorithm_penalty: {pattern}")
                    risk_score += 20
                    recommendations.append("Remove promotional language that triggers algorithm penalties")
            
            # Check for credibility risks
            for pattern in self.risk_patterns["credibility_risks"]:
                if re.search(pattern, content_lower, re.IGNORECASE):
                    risk_factors.append(f"credibility_risk: {pattern}")
                    risk_score += 25
                    recommendations.append("Avoid sensational language that reduces credibility")
            
            # Check for platform violations
            for pattern in self.risk_patterns["platform_violations"]:
                if re.search(pattern, content_lower, re.IGNORECASE):
                    risk_factors.append(f"platform_violation: {pattern}")
                    risk_score += 40
                    recommendations.append("Content may violate platform community guidelines")
            
            # Analyze content quality
            positive_count = sum(1 for indicator in self.quality_indicators["positive"] 
                               if indicator in content_lower)
            negative_count = sum(1 for indicator in self.quality_indicators["negative"] 
                               if indicator in content_lower)
            
            if negative_count > positive_count:
                risk_score += 10
                risk_factors.append("low_quality_indicators")
                recommendations.append("Improve content quality with credible sources and factual information")
            
            # Platform-specific analysis
            if platform == "twitter":
                risk_score += await self._analyze_twitter_specific_risks(content)
            elif platform == "facebook":
                risk_score += await self._analyze_facebook_specific_risks(content)
            elif platform == "instagram":
                risk_score += await self._analyze_instagram_specific_risks(content)
            
            # Determine risk level
            if risk_score >= 80:
                risk_level = "critical"
            elif risk_score >= 60:
                risk_level = "high"
            elif risk_score >= 30:
                risk_level = "medium"
            else:
                risk_level = "low"
            
            # Calculate confidence based on pattern matches and AI analysis
            confidence = min(0.95, len(risk_factors) * 0.1 + 0.5)
            
            return ContentRiskResult(
                risk_level=risk_level,
                risk_score=min(100, risk_score),
                risk_factors=risk_factors,
                recommendations=recommendations,
                confidence=confidence
            )
            
        except Exception as e:
            raise ContentAnalyzerError(f"Content risk analysis failed: {str(e)}")
    
    async def _analyze_twitter_specific_risks(self, content: str) -> int:
        """Analyze Twitter-specific risk factors."""
        risk_score = 0
        
        # Check for excessive hashtags
        hashtag_count = content.count('#')
        if hashtag_count > 3:
            risk_score += 10
        
        # Check for excessive mentions
        mention_count = content.count('@')
        if mention_count > 2:
            risk_score += 5
        
        # Check for thread indicators that might reduce reach
        if any(indicator in content.lower() for indicator in ['thread', '1/', '2/', 'continued']):
            risk_score += 5
        
        return risk_score
    
    async def _analyze_facebook_specific_risks(self, content: str) -> int:
        """Analyze Facebook-specific risk factors."""
        risk_score = 0
        
        # Facebook penalizes external links
        if 'http' in content:
            risk_score += 15
        
        # Check for engagement bait
        engagement_bait = ['like if', 'share if', 'comment if', 'tag someone']
        if any(bait in content.lower() for bait in engagement_bait):
            risk_score += 20
        
        return risk_score
    
    async def _analyze_instagram_specific_risks(self, content: str) -> int:
        """Analyze Instagram-specific risk factors."""
        risk_score = 0
        
        # Instagram allows more hashtags but penalizes banned ones
        hashtag_count = content.count('#')
        if hashtag_count > 30:
            risk_score += 10
        
        # Check for shadowban-prone hashtags (simplified)
        shadowban_hashtags = ['#follow4follow', '#like4like', '#followme', '#tagsforlikes']
        for hashtag in shadowban_hashtags:
            if hashtag in content.lower():
                risk_score += 15
        
        return risk_score


class LinkPenaltyDetector:
    """
    Detects potential link penalties and algorithm restrictions.
    """
    
    def __init__(self, ai_service: AIService):
        self.ai_service = ai_service
        self.settings = get_settings()
        
        # Penalty indicators
        self.penalty_indicators = {
            "algorithm_flags": [
                "sudden_drop_engagement",
                "reduced_reach",
                "limited_distribution",
                "shadow_restriction"
            ],
            "manual_penalties": [
                "community_guidelines_violation",
                "copyright_strike",
                "spam_report",
                "fake_news_flag"
            ],
            "link_penalties": [
                "external_link_penalty",
                "shortened_url_penalty",
                "suspicious_domain_penalty",
                "redirect_chain_penalty"
            ]
        }
    
    async def detect_link_penalty(self, url: str, engagement_data: Dict[str, Any]) -> LinkPenaltyResult:
        """
        Detect potential link penalties based on URL and engagement patterns.
        
        Args:
            url: URL to analyze
            engagement_data: Historical engagement metrics
        
        Returns:
            LinkPenaltyResult with penalty assessment
        """
        try:
            penalty_detected = False
            penalty_type = "none"
            penalty_score = 0
            affected_metrics = []
            recovery_suggestions = []
            
            # Analyze URL characteristics
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            # Check for suspicious domain patterns
            if self._is_suspicious_domain(domain):
                penalty_score += 30
                penalty_detected = True
                penalty_type = "algorithm"
                affected_metrics.append("link_clicks")
                recovery_suggestions.append("Use trusted, established domains")
            
            # Check for URL shorteners (often penalized)
            shortener_domains = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly']
            if any(shortener in domain for shortener in shortener_domains):
                penalty_score += 20
                penalty_detected = True
                penalty_type = "algorithm"
                affected_metrics.append("organic_reach")
                recovery_suggestions.append("Use direct links instead of URL shorteners")
            
            # Analyze engagement patterns for penalty indicators
            if engagement_data:
                penalty_indicators = await self._analyze_engagement_patterns(engagement_data)
                penalty_score += penalty_indicators["score"]
                
                if penalty_indicators["shadow_ban_detected"]:
                    penalty_detected = True
                    penalty_type = "shadow_ban"
                    affected_metrics.extend(["impressions", "reach", "engagement"])
                    recovery_suggestions.append("Review recent content for policy violations")
                
                if penalty_indicators["manual_penalty_detected"]:
                    penalty_detected = True
                    penalty_type = "manual"
                    affected_metrics.extend(["visibility", "distribution"])
                    recovery_suggestions.append("Appeal the penalty through platform channels")
            
            return LinkPenaltyResult(
                penalty_detected=penalty_detected,
                penalty_type=penalty_type,
                penalty_score=min(100, penalty_score),
                affected_metrics=affected_metrics,
                recovery_suggestions=recovery_suggestions
            )
            
        except Exception as e:
            raise ContentAnalyzerError(f"Link penalty detection failed: {str(e)}")
    
    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check if domain has suspicious characteristics."""
        # Check for IP addresses
        if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
            return True
        
        # Check for excessive subdomains
        if len(domain.split('.')) > 4:
            return True
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            return True
        
        return False
    
    async def _analyze_engagement_patterns(self, engagement_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze engagement patterns for penalty indicators."""
        score = 0
        shadow_ban_detected = False
        manual_penalty_detected = False
        
        # Check for sudden drops in engagement
        if "recent_engagement" in engagement_data and "historical_average" in engagement_data:
            recent = engagement_data["recent_engagement"]
            historical = engagement_data["historical_average"]
            
            if recent < historical * 0.3:  # 70% drop
                score += 40
                shadow_ban_detected = True
            elif recent < historical * 0.5:  # 50% drop
                score += 20
        
        # Check for reach limitations
        if "reach_ratio" in engagement_data:
            if engagement_data["reach_ratio"] < 0.1:  # Less than 10% reach
                score += 30
                shadow_ban_detected = True
        
        return {
            "score": score,
            "shadow_ban_detected": shadow_ban_detected,
            "manual_penalty_detected": manual_penalty_detected
        }


class SpamPatternDetector:
    """
    Detects spam patterns in content that could trigger platform restrictions.
    """
    
    def __init__(self, ai_service: AIService):
        self.ai_service = ai_service
        self.settings = get_settings()
        
        # Spam pattern definitions
        self.spam_patterns = {
            "promotional": [
                r"buy\s+now",
                r"limited\s+time\s+offer",
                r"act\s+fast",
                r"don't\s+miss\s+out",
                r"exclusive\s+deal",
                r"special\s+discount",
                r"free\s+trial"
            ],
            "malicious": [
                r"click\s+here\s+to\s+win",
                r"you've\s+won",
                r"claim\s+your\s+prize",
                r"congratulations.*selected",
                r"verify\s+your\s+account",
                r"urgent\s+action\s+required"
            ],
            "bot_generated": [
                r"this\s+is\s+amazing",
                r"wow\s+incredible",
                r"so\s+inspiring",
                r"love\s+this\s+post",
                r"great\s+content",
                r"thanks\s+for\s+sharing"
            ]
        }
        
        # Platform-specific spam indicators
        self.platform_indicators = {
            "twitter": {
                "excessive_hashtags": 5,
                "excessive_mentions": 3,
                "repeated_content_threshold": 0.8
            },
            "facebook": {
                "engagement_bait_threshold": 2,
                "external_link_limit": 1,
                "caps_ratio_threshold": 0.3
            },
            "instagram": {
                "hashtag_limit": 30,
                "banned_hashtag_penalty": 20,
                "follow_unfollow_pattern": True
            }
        }
    
    async def detect_spam_patterns(self, content: str, platform: str = "general") -> SpamPatternResult:
        """
        Detect spam patterns in content.
        
        Args:
            content: Content to analyze
            platform: Target platform
        
        Returns:
            SpamPatternResult with spam assessment
        """
        try:
            is_spam = False
            spam_type = "none"
            spam_score = 0
            detected_patterns = []
            platform_specific_flags = {}
            
            content_lower = content.lower()
            
            # Check promotional spam patterns
            for pattern in self.spam_patterns["promotional"]:
                if re.search(pattern, content_lower, re.IGNORECASE):
                    detected_patterns.append(f"promotional: {pattern}")
                    spam_score += 25
                    spam_type = "promotional"
            
            # Check malicious spam patterns
            for pattern in self.spam_patterns["malicious"]:
                if re.search(pattern, content_lower, re.IGNORECASE):
                    detected_patterns.append(f"malicious: {pattern}")
                    spam_score += 40
                    spam_type = "malicious"
                    is_spam = True
            
            # Check bot-generated patterns
            bot_pattern_count = 0
            for pattern in self.spam_patterns["bot_generated"]:
                if re.search(pattern, content_lower, re.IGNORECASE):
                    bot_pattern_count += 1
                    detected_patterns.append(f"bot_generated: {pattern}")
            
            if bot_pattern_count >= 2:
                spam_score += 30
                spam_type = "bot_generated"
                is_spam = True
            
            # Platform-specific analysis
            if platform in self.platform_indicators:
                platform_flags = await self._analyze_platform_specific_spam(content, platform)
                platform_specific_flags = platform_flags
                spam_score += platform_flags.get("penalty_score", 0)
                
                if platform_flags.get("is_spam", False):
                    is_spam = True
                    if spam_type == "none":
                        spam_type = platform_flags.get("spam_type", "promotional")
            
            # General spam indicators
            caps_ratio = sum(1 for c in content if c.isupper()) / len(content) if content else 0
            if caps_ratio > 0.5:
                spam_score += 15
                detected_patterns.append("excessive_capitalization")
            
            # Check for excessive punctuation
            exclamation_count = content.count('!')
            if exclamation_count > 3:
                spam_score += 10
                detected_patterns.append("excessive_punctuation")
            
            # Determine if content is spam
            if spam_score >= 50:
                is_spam = True
            
            return SpamPatternResult(
                is_spam=is_spam,
                spam_type=spam_type,
                spam_score=min(100, spam_score),
                detected_patterns=detected_patterns,
                platform_specific_flags=platform_specific_flags
            )
            
        except Exception as e:
            raise ContentAnalyzerError(f"Spam pattern detection failed: {str(e)}")
    
    async def _analyze_platform_specific_spam(self, content: str, platform: str) -> Dict[str, Any]:
        """Analyze platform-specific spam indicators."""
        indicators = self.platform_indicators[platform]
        flags = {"penalty_score": 0, "is_spam": False, "spam_type": "none"}
        
        if platform == "twitter":
            hashtag_count = content.count('#')
            mention_count = content.count('@')
            
            if hashtag_count > indicators["excessive_hashtags"]:
                flags["penalty_score"] += 20
                flags["is_spam"] = True
                flags["spam_type"] = "promotional"
            
            if mention_count > indicators["excessive_mentions"]:
                flags["penalty_score"] += 15
        
        elif platform == "facebook":
            engagement_bait = ['like if', 'share if', 'comment if', 'tag someone']
            bait_count = sum(1 for bait in engagement_bait if bait in content.lower())
            
            if bait_count >= indicators["engagement_bait_threshold"]:
                flags["penalty_score"] += 30
                flags["is_spam"] = True
                flags["spam_type"] = "promotional"
            
            if content.count('http') > indicators["external_link_limit"]:
                flags["penalty_score"] += 25
        
        elif platform == "instagram":
            hashtag_count = content.count('#')
            
            if hashtag_count > indicators["hashtag_limit"]:
                flags["penalty_score"] += 15
            
            # Check for banned hashtags (simplified)
            banned_hashtags = ['#follow4follow', '#like4like', '#followme']
            for hashtag in banned_hashtags:
                if hashtag in content.lower():
                    flags["penalty_score"] += indicators["banned_hashtag_penalty"]
                    flags["is_spam"] = True
                    flags["spam_type"] = "promotional"
        
        return flags


class CommunityNotesAnalyzer:
    """
    Analyzes community notes and fact-checking information.
    """
    
    def __init__(self, ai_service: AIService):
        self.ai_service = ai_service
        self.settings = get_settings()
        
        # Community notes categories
        self.note_categories = {
            "misleading": ["misleading", "false", "incorrect", "inaccurate"],
            "disputed": ["disputed", "contested", "debated", "controversial"],
            "context_needed": ["context", "missing_info", "incomplete", "clarification"],
            "satire": ["satire", "parody", "joke", "humor", "comedy"],
            "outdated": ["outdated", "old", "expired", "superseded"]
        }
    
    async def analyze_community_notes(self, content: str, notes_data: Optional[Dict[str, Any]] = None) -> CommunityNotesResult:
        """
        Analyze community notes and their impact on content credibility.
        
        Args:
            content: Original content
            notes_data: Community notes data if available
        
        Returns:
            CommunityNotesResult with analysis
        """
        try:
            notes_present = bool(notes_data)
            note_types = []
            credibility_impact = "neutral"
            suggested_actions = []
            
            if notes_data:
                # Analyze note content
                note_text = notes_data.get("note_text", "").lower()
                
                # Categorize notes
                for category, keywords in self.note_categories.items():
                    if any(keyword in note_text for keyword in keywords):
                        note_types.append(category)
                
                # Determine credibility impact
                if "misleading" in note_types or "false" in note_text:
                    credibility_impact = "negative"
                    suggested_actions.extend([
                        "Review content accuracy",
                        "Provide additional sources",
                        "Consider content correction or removal"
                    ])
                elif "disputed" in note_types:
                    credibility_impact = "negative"
                    suggested_actions.extend([
                        "Acknowledge different perspectives",
                        "Provide balanced information",
                        "Add disclaimers if necessary"
                    ])
                elif "context_needed" in note_types:
                    credibility_impact = "neutral"
                    suggested_actions.extend([
                        "Add missing context",
                        "Provide background information",
                        "Include relevant details"
                    ])
                elif "satire" in note_types:
                    credibility_impact = "positive"
                    suggested_actions.append("Consider adding satire/humor disclaimer")
                
                # Check note helpfulness score
                helpfulness_score = notes_data.get("helpfulness_score", 0)
                if helpfulness_score > 0.7:
                    if credibility_impact == "negative":
                        suggested_actions.append("High-confidence community correction - immediate action recommended")
                    elif credibility_impact == "neutral":
                        suggested_actions.append("Community feedback is well-received - consider incorporating suggestions")
            
            else:
                # Analyze content for potential community note triggers
                potential_triggers = await self._identify_potential_note_triggers(content)
                if potential_triggers:
                    suggested_actions.extend([
                        "Content may attract community notes",
                        "Consider pre-emptive fact-checking",
                        "Add sources and context proactively"
                    ])
            
            return CommunityNotesResult(
                notes_present=notes_present,
                note_types=note_types,
                credibility_impact=credibility_impact,
                suggested_actions=suggested_actions
            )
            
        except Exception as e:
            raise ContentAnalyzerError(f"Community notes analysis failed: {str(e)}")
    
    async def _identify_potential_note_triggers(self, content: str) -> List[str]:
        """Identify content that might trigger community notes."""
        triggers = []
        content_lower = content.lower()
        
        # Claims that often need verification
        claim_patterns = [
            r"studies\s+show",
            r"research\s+proves",
            r"scientists\s+say",
            r"experts\s+agree",
            r"breaking\s*:",
            r"confirmed\s*:",
            r"\d+%\s+of\s+people"
        ]
        
        for pattern in claim_patterns:
            if re.search(pattern, content_lower, re.IGNORECASE):
                triggers.append(f"unverified_claim: {pattern}")
        
        # Controversial topics (simplified)
        controversial_topics = [
            "vaccine", "climate", "election", "conspiracy",
            "government", "politics", "health", "medicine"
        ]
        
        for topic in controversial_topics:
            if topic in content_lower:
                triggers.append(f"controversial_topic: {topic}")
        
        return triggers


class ContentAnalyzerService:
    """
    Main content analyzer service that coordinates all specialized analyzers.
    """
    
    def __init__(self, ai_service: AIService):
        self.ai_service = ai_service
        self.content_risk_analyzer = ContentRiskAnalyzer(ai_service)
        self.link_penalty_detector = LinkPenaltyDetector(ai_service)
        self.spam_pattern_detector = SpamPatternDetector(ai_service)
        self.community_notes_analyzer = CommunityNotesAnalyzer(ai_service)
    
    async def comprehensive_content_analysis(
        self,
        content: str,
        platform: str = "general",
        url: Optional[str] = None,
        engagement_data: Optional[Dict[str, Any]] = None,
        notes_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Perform comprehensive content analysis using all specialized analyzers.
        
        Args:
            content: Content to analyze
            platform: Target platform
            url: Associated URL if any
            engagement_data: Historical engagement metrics
            notes_data: Community notes data
        
        Returns:
            Comprehensive analysis results
        """
        try:
            # Run all analyses concurrently
            analysis_tasks = [
                self.content_risk_analyzer.analyze_content_risk(content, platform),
                self.spam_pattern_detector.detect_spam_patterns(content, platform),
                self.community_notes_analyzer.analyze_community_notes(content, notes_data)
            ]
            
            # Add link penalty analysis if URL is provided
            if url and engagement_data:
                analysis_tasks.append(
                    self.link_penalty_detector.detect_link_penalty(url, engagement_data)
                )
            
            # Execute all analyses
            results = await asyncio.gather(*analysis_tasks, return_exceptions=True)
            
            # Process results
            content_risk = results[0] if not isinstance(results[0], Exception) else None
            spam_analysis = results[1] if not isinstance(results[1], Exception) else None
            community_notes = results[2] if not isinstance(results[2], Exception) else None
            link_penalty = results[3] if len(results) > 3 and not isinstance(results[3], Exception) else None
            
            # Calculate overall assessment
            overall_risk_score = 0
            critical_issues = []
            recommendations = []
            
            if content_risk:
                overall_risk_score += content_risk.risk_score * 0.3
                if content_risk.risk_level in ["high", "critical"]:
                    critical_issues.append(f"Content risk: {content_risk.risk_level}")
                recommendations.extend(content_risk.recommendations)
            
            if spam_analysis and spam_analysis.is_spam:
                overall_risk_score += spam_analysis.spam_score * 0.3
                critical_issues.append(f"Spam detected: {spam_analysis.spam_type}")
            
            if link_penalty and link_penalty.penalty_detected:
                overall_risk_score += link_penalty.penalty_score * 0.2
                critical_issues.append(f"Link penalty: {link_penalty.penalty_type}")
                recommendations.extend(link_penalty.recovery_suggestions)
            
            if community_notes and community_notes.credibility_impact == "negative":
                overall_risk_score += 20
                critical_issues.append("Negative community feedback")
                recommendations.extend(community_notes.suggested_actions)
            
            return {
                "overall_risk_score": min(100, int(overall_risk_score)),
                "critical_issues": critical_issues,
                "recommendations": recommendations,
                "content_risk_analysis": content_risk.__dict__ if content_risk else None,
                "spam_analysis": spam_analysis.__dict__ if spam_analysis else None,
                "link_penalty_analysis": link_penalty.__dict__ if link_penalty else None,
                "community_notes_analysis": community_notes.__dict__ if community_notes else None,
                "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
                "platform": platform
            }
            
        except Exception as e:
            raise ContentAnalyzerError(f"Comprehensive content analysis failed: {str(e)}")