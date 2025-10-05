"""
Spam Pattern Detector for Social Media Protection.

This module provides specialized detection for spam patterns, suspicious behaviors,
and content manipulation tactics commonly used in social media spam campaigns.
"""

import re
import asyncio
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass
from datetime import datetime, timezone
from collections import Counter
import hashlib

from linkshield.services.ai_service import AIService
from linkshield.config.settings import get_settings


@dataclass
class SpamPatternResult:
    """Result of spam pattern detection analysis."""
    is_spam: bool
    spam_score: int  # 0-100
    spam_types: List[str]
    detected_patterns: List[str]
    suspicious_behaviors: List[str]
    recommendations: List[str]
    pattern_analysis: Dict[str, Any]
    confidence_score: float  # 0.0-1.0
    analysis_timestamp: str


class SpamPatternDetector:
    """
    Detects spam patterns and suspicious content behaviors.
    
    This detector analyzes content for common spam indicators including
    excessive repetition, suspicious formatting, engagement manipulation,
    and coordinated inauthentic behavior patterns.
    """
    
    def __init__(self, ai_service: AIService):
        self.ai_service = ai_service
        self.settings = get_settings()
        
        # Spam pattern definitions
        self.spam_patterns = {
            "excessive_caps": {
                "pattern": r"[A-Z]{3,}",
                "threshold": 5,
                "weight": 15
            },
            "excessive_punctuation": {
                "pattern": r"[!?]{3,}",
                "threshold": 3,
                "weight": 20
            },
            "repeated_characters": {
                "pattern": r"(.)\1{4,}",
                "threshold": 2,
                "weight": 25
            },
            "excessive_emojis": {
                "pattern": r"[\U0001F600-\U0001F64F\U0001F300-\U0001F5FF\U0001F680-\U0001F6FF\U0001F1E0-\U0001F1FF]{5,}",
                "threshold": 3,
                "weight": 15
            },
            "money_symbols": {
                "pattern": r"[\$€£¥₹₽₩₪₫₱₡₦₨₴₸₼₾₿]{2,}",
                "threshold": 2,
                "weight": 30
            },
            "phone_numbers": {
                "pattern": r"(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}",
                "threshold": 1,
                "weight": 25
            },
            "email_addresses": {
                "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                "threshold": 1,
                "weight": 20
            },
            "suspicious_urls": {
                "pattern": r"(?:bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|short\.link)",
                "threshold": 1,
                "weight": 25
            }
        }
        
        # Spam keywords and phrases
        self.spam_keywords = {
            "financial_scams": [
                "make money fast", "get rich quick", "easy money", "guaranteed income",
                "work from home", "no experience needed", "earn $", "free money",
                "investment opportunity", "double your money", "risk-free", "guaranteed profit"
            ],
            "fake_urgency": [
                "limited time", "act now", "hurry up", "don't miss out", "expires today",
                "last chance", "urgent", "immediate action", "time sensitive", "deadline"
            ],
            "engagement_bait": [
                "like if you agree", "share if you", "comment below", "tag a friend",
                "retweet if", "follow for follow", "f4f", "l4l", "like for like",
                "share for share", "comment for comment"
            ],
            "fake_giveaways": [
                "free iphone", "free gift card", "win a", "giveaway", "contest",
                "prize", "winner", "congratulations you won", "claim your prize",
                "free stuff", "no purchase necessary"
            ],
            "clickbait": [
                "you won't believe", "shocking truth", "doctors hate", "this one trick",
                "number 7 will shock you", "what happened next", "unbelievable",
                "mind-blowing", "incredible", "amazing secret"
            ],
            "fake_news": [
                "breaking news", "exclusive report", "leaked information", "insider reveals",
                "government doesn't want you to know", "media won't tell you",
                "hidden truth", "conspiracy", "cover-up", "secret agenda"
            ],
            "health_scams": [
                "miracle cure", "doctors hate this", "lose weight fast", "burn fat",
                "anti-aging secret", "fountain of youth", "natural remedy",
                "big pharma", "cure cancer", "lose 30 pounds"
            ],
            "crypto_scams": [
                "bitcoin giveaway", "crypto investment", "trading bot", "guaranteed returns",
                "pump and dump", "moon", "to the moon", "diamond hands", "hodl",
                "get rich with crypto", "free bitcoin", "crypto millionaire"
            ]
        }
        
        # Suspicious behavior patterns
        self.behavior_patterns = {
            "repetitive_content": {
                "description": "Content with excessive repetition",
                "indicators": ["repeated_words", "repeated_phrases", "copy_paste"]
            },
            "artificial_engagement": {
                "description": "Attempts to artificially boost engagement",
                "indicators": ["engagement_bait", "follow_for_follow", "like_for_like"]
            },
            "impersonation": {
                "description": "Potential account impersonation",
                "indicators": ["verified_claim", "official_claim", "celebrity_name"]
            },
            "coordinated_behavior": {
                "description": "Signs of coordinated inauthentic behavior",
                "indicators": ["identical_content", "synchronized_posting", "bot_network"]
            },
            "manipulation_tactics": {
                "description": "Content manipulation and deception",
                "indicators": ["fake_urgency", "false_scarcity", "emotional_manipulation"]
            }
        }
        
        # Platform-specific spam indicators
        self.platform_indicators = {
            "twitter": {
                "hashtag_stuffing": r"#\w+(?:\s+#\w+){5,}",
                "mention_spam": r"@\w+(?:\s+@\w+){5,}",
                "retweet_begging": r"(?:rt|retweet)\s+(?:if|for|to)",
                "follower_begging": r"(?:follow|f4f|followback)"
            },
            "facebook": {
                "tag_spam": r"@\[[\w\s]+\](?:\s+@\[[\w\s]+\]){3,}",
                "share_begging": r"share\s+(?:if|for|to)",
                "like_begging": r"like\s+(?:if|for|to)",
                "comment_begging": r"comment\s+(?:if|for|to)"
            },
            "instagram": {
                "hashtag_limit": r"#\w+(?:\s+#\w+){30,}",
                "follow_for_follow": r"(?:f4f|follow4follow|followforfollow)",
                "like_for_like": r"(?:l4l|like4like|likeforlike)",
                "dm_spam": r"(?:dm|direct\s+message)\s+(?:me|for)"
            },
            "linkedin": {
                "connection_spam": r"connect\s+with\s+me",
                "endorsement_begging": r"endorse\s+(?:me|my\s+skills)",
                "job_scam": r"(?:work\s+from\s+home|easy\s+money|no\s+experience)"
            },
            "tiktok": {
                "duet_spam": r"duet\s+(?:this|me|if)",
                "stitch_spam": r"stitch\s+(?:this|me|if)",
                "follow_spam": r"follow\s+(?:me|for\s+more|back)"
            }
        }
        
        # Content quality indicators
        self.quality_indicators = {
            "low_quality": [
                "poor_grammar", "excessive_typos", "random_characters",
                "incoherent_text", "machine_generated", "template_content"
            ],
            "high_quality": [
                "proper_grammar", "coherent_structure", "original_content",
                "informative", "well_formatted", "engaging"
            ]
        }
    
    async def detect_spam_patterns(self, content: str, platform: str = "general",
                                 metadata: Optional[Dict[str, Any]] = None) -> SpamPatternResult:
        """
        Detect spam patterns in content.
        
        Args:
            content: Content text to analyze
            platform: Target platform (twitter, facebook, instagram, etc.)
            metadata: Additional metadata (author, timestamp, engagement, etc.)
        
        Returns:
            SpamPatternResult with spam assessment
        """
        try:
            is_spam = False
            spam_score = 0
            spam_types = []
            detected_patterns = []
            suspicious_behaviors = []
            recommendations = []
            pattern_analysis = {}
            
            # Basic pattern detection
            pattern_results = await self._detect_basic_patterns(content)
            spam_score += pattern_results["score"]
            detected_patterns.extend(pattern_results["patterns"])
            
            # Keyword analysis
            keyword_results = await self._analyze_spam_keywords(content)
            spam_score += keyword_results["score"]
            spam_types.extend(keyword_results["types"])
            detected_patterns.extend(keyword_results["patterns"])
            
            # Behavior pattern analysis
            behavior_results = await self._analyze_behavior_patterns(content, metadata)
            spam_score += behavior_results["score"]
            suspicious_behaviors.extend(behavior_results["behaviors"])
            
            # Platform-specific analysis
            if platform != "general":
                platform_results = await self._analyze_platform_patterns(content, platform)
                spam_score += platform_results["score"]
                detected_patterns.extend(platform_results["patterns"])
            
            # Content quality analysis
            quality_results = await self._analyze_content_quality(content)
            spam_score += quality_results["score"]
            
            # AI-powered analysis for advanced spam detection
            ai_results = await self._ai_spam_analysis(content)
            spam_score += ai_results["score"]
            if ai_results.get("is_spam"):
                spam_types.append("ai_detected_spam")
                detected_patterns.extend(ai_results.get("patterns", []))
            
            # Repetition analysis
            repetition_results = await self._analyze_repetition(content)
            spam_score += repetition_results["score"]
            if repetition_results["has_excessive_repetition"]:
                suspicious_behaviors.append("excessive_repetition")
                detected_patterns.extend(repetition_results["patterns"])
            
            # Generate recommendations
            recommendations = self._generate_spam_recommendations(
                spam_types, detected_patterns, suspicious_behaviors, platform
            )
            
            # Normalize spam score
            spam_score = min(100, max(0, spam_score))
            
            # Determine if content is spam
            if spam_score >= 60:
                is_spam = True
            
            # Calculate confidence score
            confidence_score = self._calculate_confidence_score(
                len(detected_patterns), len(spam_types), len(suspicious_behaviors)
            )
            
            # Compile pattern analysis
            pattern_analysis = {
                "basic_patterns": pattern_results,
                "keyword_analysis": keyword_results,
                "behavior_analysis": behavior_results,
                "quality_analysis": quality_results,
                "repetition_analysis": repetition_results,
                "ai_analysis": ai_results
            }
            
            if platform != "general":
                pattern_analysis["platform_analysis"] = platform_results
            
            return SpamPatternResult(
                is_spam=is_spam,
                spam_score=spam_score,
                spam_types=list(set(spam_types)),  # Remove duplicates
                detected_patterns=detected_patterns,
                suspicious_behaviors=suspicious_behaviors,
                recommendations=recommendations,
                pattern_analysis=pattern_analysis,
                confidence_score=confidence_score,
                analysis_timestamp=datetime.now(timezone.utc).isoformat()
            )
            
        except Exception as e:
            # Return safe default result on error
            return SpamPatternResult(
                is_spam=True,
                spam_score=75,
                spam_types=["analysis_error"],
                detected_patterns=[f"analysis_error: {str(e)}"],
                suspicious_behaviors=["analysis_failure"],
                recommendations=["Manual review recommended due to analysis error"],
                pattern_analysis={},
                confidence_score=0.0,
                analysis_timestamp=datetime.now(timezone.utc).isoformat()
            )
    
    async def _detect_basic_patterns(self, content: str) -> Dict[str, Any]:
        """Detect basic spam patterns in content."""
        results = {
            "score": 0,
            "patterns": [],
            "details": {}
        }
        
        for pattern_name, pattern_config in self.spam_patterns.items():
            matches = re.findall(pattern_config["pattern"], content, re.IGNORECASE)
            match_count = len(matches)
            
            if match_count >= pattern_config["threshold"]:
                score_addition = min(pattern_config["weight"], match_count * 5)
                results["score"] += score_addition
                results["patterns"].append(f"{pattern_name}: {match_count} occurrences")
                results["details"][pattern_name] = {
                    "count": match_count,
                    "matches": matches[:5],  # Limit to first 5 matches
                    "score_added": score_addition
                }
        
        return results
    
    async def _analyze_spam_keywords(self, content: str) -> Dict[str, Any]:
        """Analyze content for spam keywords and phrases."""
        results = {
            "score": 0,
            "types": [],
            "patterns": [],
            "details": {}
        }
        
        content_lower = content.lower()
        
        for category, keywords in self.spam_keywords.items():
            found_keywords = []
            for keyword in keywords:
                if keyword.lower() in content_lower:
                    found_keywords.append(keyword)
            
            if found_keywords:
                # Score based on number of keywords found and category severity
                category_weights = {
                    "financial_scams": 30,
                    "fake_urgency": 20,
                    "engagement_bait": 25,
                    "fake_giveaways": 35,
                    "clickbait": 15,
                    "fake_news": 40,
                    "health_scams": 35,
                    "crypto_scams": 30
                }
                
                weight = category_weights.get(category, 20)
                score_addition = min(weight, len(found_keywords) * 10)
                results["score"] += score_addition
                results["types"].append(category)
                results["patterns"].append(f"{category}: {len(found_keywords)} keywords")
                results["details"][category] = {
                    "keywords": found_keywords,
                    "count": len(found_keywords),
                    "score_added": score_addition
                }
        
        return results
    
    async def _analyze_behavior_patterns(self, content: str, 
                                       metadata: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze suspicious behavior patterns."""
        results = {
            "score": 0,
            "behaviors": [],
            "details": {}
        }
        
        content_lower = content.lower()
        
        # Check for engagement bait
        engagement_bait_patterns = [
            r"like\s+if\s+you",
            r"share\s+if\s+you",
            r"comment\s+if\s+you",
            r"tag\s+a\s+friend",
            r"follow\s+for\s+follow",
            r"retweet\s+if"
        ]
        
        for pattern in engagement_bait_patterns:
            if re.search(pattern, content_lower):
                results["score"] += 15
                results["behaviors"].append("engagement_bait")
                break
        
        # Check for impersonation indicators
        impersonation_patterns = [
            r"verified\s+account",
            r"official\s+account",
            r"celebrity",
            r"famous\s+person",
            r"blue\s+checkmark"
        ]
        
        for pattern in impersonation_patterns:
            if re.search(pattern, content_lower):
                results["score"] += 25
                results["behaviors"].append("potential_impersonation")
                break
        
        # Check metadata for suspicious patterns
        if metadata:
            # Rapid posting pattern
            if metadata.get("posts_per_hour", 0) > 10:
                results["score"] += 20
                results["behaviors"].append("rapid_posting")
            
            # Low engagement ratio
            engagement_ratio = metadata.get("engagement_ratio", 1.0)
            if engagement_ratio < 0.01:  # Less than 1% engagement
                results["score"] += 15
                results["behaviors"].append("low_engagement")
            
            # New account with high activity
            account_age_days = metadata.get("account_age_days", 365)
            if account_age_days < 30 and metadata.get("posts_count", 0) > 100:
                results["score"] += 30
                results["behaviors"].append("new_account_high_activity")
        
        return results
    
    async def _analyze_platform_patterns(self, content: str, platform: str) -> Dict[str, Any]:
        """Analyze platform-specific spam patterns."""
        results = {
            "score": 0,
            "patterns": [],
            "details": {}
        }
        
        if platform not in self.platform_indicators:
            return results
        
        platform_patterns = self.platform_indicators[platform]
        
        for pattern_name, pattern_regex in platform_patterns.items():
            matches = re.findall(pattern_regex, content, re.IGNORECASE)
            if matches:
                score_addition = min(20, len(matches) * 10)
                results["score"] += score_addition
                results["patterns"].append(f"{platform}_{pattern_name}: {len(matches)} occurrences")
                results["details"][pattern_name] = {
                    "count": len(matches),
                    "matches": matches[:3],  # Limit to first 3 matches
                    "score_added": score_addition
                }
        
        return results
    
    async def _analyze_content_quality(self, content: str) -> Dict[str, Any]:
        """Analyze content quality indicators."""
        results = {
            "score": 0,
            "quality_level": "medium",
            "indicators": []
        }
        
        # Check for poor grammar indicators
        grammar_issues = 0
        
        # Excessive typos (simple heuristic)
        words = content.split()
        if len(words) > 5:
            # Check for words with repeated characters (potential typos)
            typo_pattern = r'\b\w*(.)\1{2,}\w*\b'
            typos = re.findall(typo_pattern, content)
            if len(typos) > len(words) * 0.1:  # More than 10% typos
                grammar_issues += 1
                results["indicators"].append("excessive_typos")
        
        # Check for random character sequences
        random_pattern = r'[a-zA-Z]{1}[0-9]{1}[a-zA-Z]{1}[0-9]{1}'
        if re.search(random_pattern, content):
            grammar_issues += 1
            results["indicators"].append("random_characters")
        
        # Check for coherence (simple heuristic)
        sentences = re.split(r'[.!?]+', content)
        if len(sentences) > 2:
            avg_sentence_length = sum(len(s.split()) for s in sentences) / len(sentences)
            if avg_sentence_length < 3 or avg_sentence_length > 50:
                grammar_issues += 1
                results["indicators"].append("incoherent_structure")
        
        # Calculate quality score
        if grammar_issues >= 2:
            results["score"] += 25
            results["quality_level"] = "low"
        elif grammar_issues == 1:
            results["score"] += 10
            results["quality_level"] = "medium"
        else:
            results["quality_level"] = "high"
        
        return results
    
    async def _analyze_repetition(self, content: str) -> Dict[str, Any]:
        """Analyze content for excessive repetition."""
        results = {
            "score": 0,
            "has_excessive_repetition": False,
            "patterns": [],
            "details": {}
        }
        
        words = content.lower().split()
        if len(words) < 5:
            return results
        
        # Count word frequency
        word_counts = Counter(words)
        total_words = len(words)
        
        # Check for excessive word repetition
        for word, count in word_counts.most_common(5):
            if len(word) > 2 and count > max(3, total_words * 0.2):  # More than 20% or 3 times
                results["score"] += count * 5
                results["has_excessive_repetition"] = True
                results["patterns"].append(f"repeated_word: '{word}' appears {count} times")
        
        # Check for repeated phrases
        phrases = []
        for i in range(len(words) - 2):
            phrase = ' '.join(words[i:i+3])
            phrases.append(phrase)
        
        phrase_counts = Counter(phrases)
        for phrase, count in phrase_counts.most_common(3):
            if count > 2:
                results["score"] += count * 10
                results["has_excessive_repetition"] = True
                results["patterns"].append(f"repeated_phrase: '{phrase}' appears {count} times")
        
        # Check for character repetition patterns
        char_repetition = re.findall(r'(.)\1{5,}', content)
        if char_repetition:
            results["score"] += len(char_repetition) * 15
            results["has_excessive_repetition"] = True
            results["patterns"].append(f"character_repetition: {len(char_repetition)} instances")
        
        return results
    
    async def _ai_spam_analysis(self, content: str) -> Dict[str, Any]:
        """Use AI service for advanced spam detection."""
        try:
            # Use the AI service's spam detection capability
            ai_result = await self.ai_service.detect_spam_patterns(content)
            
            return {
                "score": ai_result.get("spam_score", 0),
                "is_spam": ai_result.get("is_spam", False),
                "patterns": ai_result.get("detected_patterns", []),
                "confidence": ai_result.get("confidence", 0.0)
            }
        except Exception as e:
            # Fallback if AI service is unavailable
            return {
                "score": 0,
                "is_spam": False,
                "patterns": [],
                "confidence": 0.0,
                "error": str(e)
            }
    
    def _generate_spam_recommendations(self, spam_types: List[str], 
                                     detected_patterns: List[str],
                                     suspicious_behaviors: List[str], 
                                     platform: str) -> List[str]:
        """Generate recommendations based on detected spam indicators."""
        recommendations = []
        
        if "financial_scams" in spam_types:
            recommendations.append("Remove financial scam language and unrealistic money promises")
        
        if "engagement_bait" in spam_types:
            recommendations.append("Avoid asking for likes, shares, or follows directly")
        
        if "fake_urgency" in spam_types:
            recommendations.append("Remove artificial urgency and pressure tactics")
        
        if "clickbait" in spam_types:
            recommendations.append("Use descriptive, honest titles instead of clickbait")
        
        if "excessive_repetition" in suspicious_behaviors:
            recommendations.append("Reduce repetitive words and phrases")
        
        if any("excessive" in pattern for pattern in detected_patterns):
            recommendations.append("Reduce excessive use of caps, punctuation, and emojis")
        
        if "artificial_engagement" in suspicious_behaviors:
            recommendations.append("Focus on organic engagement rather than artificial tactics")
        
        # Platform-specific recommendations
        if platform == "twitter":
            recommendations.append("Follow Twitter's spam policy and avoid hashtag stuffing")
        elif platform == "facebook":
            recommendations.append("Create authentic content that encourages genuine interaction")
        elif platform == "instagram":
            recommendations.append("Use relevant hashtags and avoid follow-for-follow schemes")
        elif platform == "linkedin":
            recommendations.append("Maintain professional tone and avoid connection spam")
        elif platform == "tiktok":
            recommendations.append("Focus on creative, original content without spam tactics")
        
        # General recommendations
        recommendations.extend([
            "Write clear, coherent content with proper grammar",
            "Provide genuine value to your audience",
            "Avoid deceptive or misleading claims",
            "Follow platform community guidelines"
        ])
        
        return list(set(recommendations))  # Remove duplicates
    
    def _calculate_confidence_score(self, pattern_count: int, spam_type_count: int, 
                                  behavior_count: int) -> float:
        """Calculate confidence score for the spam analysis."""
        # Base confidence
        confidence = 0.7
        
        # Increase confidence with more detected patterns
        if pattern_count > 0:
            confidence += min(0.15, pattern_count * 0.03)
        
        # Increase confidence with more spam types
        if spam_type_count > 0:
            confidence += min(0.1, spam_type_count * 0.02)
        
        # Increase confidence with more suspicious behaviors
        if behavior_count > 0:
            confidence += min(0.05, behavior_count * 0.01)
        
        # High confidence for multiple indicators
        total_indicators = pattern_count + spam_type_count + behavior_count
        if total_indicators > 5:
            confidence = min(0.95, confidence + 0.05)
        
        return round(confidence, 2)