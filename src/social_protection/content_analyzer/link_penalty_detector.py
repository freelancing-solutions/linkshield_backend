"""
Link Penalty Detector for Social Media Protection.

This module provides specialized detection for external link penalties and algorithmic
restrictions that can impact social media content reach and engagement.
"""

import re
import asyncio
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs
import tldextract

from src.services.ai_service import AIService
from src.config.settings import get_settings


@dataclass
class LinkPenaltyResult:
    """Result of link penalty detection analysis."""
    has_penalty_risk: bool
    penalty_score: int  # 0-100
    penalty_types: List[str]
    detected_issues: List[str]
    recommendations: List[str]
    platform_specific_penalties: Dict[str, Any]
    link_analysis: Dict[str, Any]
    confidence_score: float  # 0.0-1.0
    analysis_timestamp: str


class LinkPenaltyDetector:
    """
    Detects potential link penalties and algorithm restrictions.
    
    This detector analyzes external links within social media content to identify
    patterns that might trigger platform penalties, including suspicious domains,
    redirect chains, and blacklisted URLs.
    """
    
    def __init__(self, ai_service: AIService):
        self.ai_service = ai_service
        self.settings = get_settings()
        
        # Penalty risk patterns
        self.penalty_patterns = {
            "high_risk_domains": [
                r"bit\.ly",
                r"tinyurl\.com",
                r"t\.co",
                r"goo\.gl",
                r"ow\.ly",
                r"short\.link",
                r"tiny\.cc",
                r"is\.gd"
            ],
            "suspicious_parameters": [
                r"utm_source=spam",
                r"ref=affiliate",
                r"clickid=",
                r"fbclid=",
                r"gclid=",
                r"tracking=",
                r"campaign=spam"
            ],
            "penalty_triggers": [
                r"affiliate",
                r"referral",
                r"commission",
                r"cashback",
                r"discount",
                r"promo",
                r"coupon",
                r"deal"
            ],
            "redirect_indicators": [
                r"redirect",
                r"forward",
                r"proxy",
                r"gateway",
                r"bridge",
                r"tunnel"
            ]
        }
        
        # Platform-specific link penalties
        self.platform_penalties = {
            "twitter": {
                "external_link_penalty": 0.3,  # 30% reach reduction
                "shortened_url_penalty": 0.2,   # 20% additional penalty
                "multiple_links_penalty": 0.4,  # 40% penalty for multiple links
                "affiliate_link_penalty": 0.6   # 60% penalty for affiliate links
            },
            "facebook": {
                "external_link_penalty": 0.5,   # 50% reach reduction
                "clickbait_link_penalty": 0.7,  # 70% penalty for clickbait
                "low_quality_domain_penalty": 0.6,  # 60% penalty for low-quality domains
                "engagement_bait_penalty": 0.8   # 80% penalty for engagement bait
            },
            "instagram": {
                "bio_link_preference": True,     # Prefer bio links over post links
                "story_link_penalty": 0.2,      # 20% penalty for story links
                "post_link_penalty": 0.4,       # 40% penalty for post links
                "swipe_up_alternative": True     # Use swipe up alternatives
            },
            "linkedin": {
                "external_link_penalty": 0.4,   # 40% reach reduction
                "native_content_preference": True,  # Prefer native content
                "professional_domain_bonus": 0.2,   # 20% bonus for professional domains
                "spam_link_penalty": 0.8         # 80% penalty for spam links
            },
            "tiktok": {
                "external_link_penalty": 0.6,   # 60% reach reduction
                "bio_link_only": True,           # Only bio links allowed
                "suspicious_link_penalty": 0.9, # 90% penalty for suspicious links
                "affiliate_link_ban": True       # Affiliate links banned
            }
        }
        
        # Known problematic domains
        self.problematic_domains = {
            "spam_domains": [
                "spam-site.com", "fake-news.net", "clickbait.org",
                "scam-alert.info", "phishing-site.co"
            ],
            "low_quality_domains": [
                "content-farm.com", "ad-heavy.net", "popup-hell.org",
                "malware-risk.info", "suspicious-redirect.co"
            ],
            "affiliate_networks": [
                "amazon.com", "clickbank.com", "commission-junction.com",
                "shareasale.com", "rakuten.com", "impact.com"
            ],
            "url_shorteners": [
                "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co",
                "short.link", "tiny.cc", "is.gd", "buff.ly"
            ]
        }
        
        # Link quality indicators
        self.quality_indicators = {
            "positive": [
                "https://", "ssl", "secure", "verified", "official",
                "gov", "edu", "org", "wikipedia", "reuters",
                "bbc", "cnn", "nytimes", "wsj"
            ],
            "negative": [
                "http://", "suspicious", "fake", "scam", "phishing",
                "malware", "virus", "spam", "clickbait", "ad-heavy"
            ]
        }
    
    async def detect_link_penalties(self, content: str, platform: str = "general",
                                  links: Optional[List[str]] = None) -> LinkPenaltyResult:
        """
        Detect potential link penalties in content.
        
        Args:
            content: Content text to analyze
            platform: Target platform (twitter, facebook, instagram, etc.)
            links: List of extracted links (if not provided, will extract from content)
        
        Returns:
            LinkPenaltyResult with penalty assessment
        """
        try:
            # Extract links if not provided
            if links is None:
                links = self._extract_links(content)
            
            has_penalty_risk = False
            penalty_score = 0
            penalty_types = []
            detected_issues = []
            recommendations = []
            platform_specific_penalties = {}
            link_analysis = {}
            
            if not links:
                return LinkPenaltyResult(
                    has_penalty_risk=False,
                    penalty_score=0,
                    penalty_types=[],
                    detected_issues=[],
                    recommendations=[],
                    platform_specific_penalties={},
                    link_analysis={"total_links": 0},
                    confidence_score=1.0,
                    analysis_timestamp=datetime.now(timezone.utc).isoformat()
                )
            
            # Analyze each link
            link_analyses = []
            for link in links:
                link_result = await self._analyze_single_link(link, platform)
                link_analyses.append(link_result)
                
                penalty_score += link_result.get("penalty_score", 0)
                
                if link_result.get("has_penalty_risk", False):
                    has_penalty_risk = True
                    penalty_types.extend(link_result.get("penalty_types", []))
                    detected_issues.extend(link_result.get("issues", []))
            
            # Platform-specific analysis
            if platform in self.platform_penalties:
                platform_analysis = await self._analyze_platform_penalties(
                    links, platform, content
                )
                platform_specific_penalties = platform_analysis
                penalty_score += platform_analysis.get("additional_penalty", 0)
                
                if platform_analysis.get("recommendations"):
                    recommendations.extend(platform_analysis["recommendations"])
            
            # Multiple links penalty
            if len(links) > 1:
                penalty_score += len(links) * 10
                detected_issues.append(f"multiple_links: {len(links)} links detected")
                recommendations.append("Consider reducing the number of external links")
            
            # Generate general recommendations
            if penalty_score > 0:
                recommendations.extend(self._generate_recommendations(penalty_types, platform))
            
            # Normalize penalty score
            penalty_score = min(100, max(0, penalty_score))
            
            # Determine if penalty risk exists
            if penalty_score >= 30:
                has_penalty_risk = True
            
            # Calculate confidence score
            confidence_score = self._calculate_confidence_score(
                len(links), len(penalty_types), len(detected_issues)
            )
            
            link_analysis = {
                "total_links": len(links),
                "analyzed_links": link_analyses,
                "average_penalty_score": penalty_score / len(links) if links else 0
            }
            
            return LinkPenaltyResult(
                has_penalty_risk=has_penalty_risk,
                penalty_score=penalty_score,
                penalty_types=list(set(penalty_types)),  # Remove duplicates
                detected_issues=detected_issues,
                recommendations=list(set(recommendations)),  # Remove duplicates
                platform_specific_penalties=platform_specific_penalties,
                link_analysis=link_analysis,
                confidence_score=confidence_score,
                analysis_timestamp=datetime.now(timezone.utc).isoformat()
            )
            
        except Exception as e:
            # Return safe default result on error
            return LinkPenaltyResult(
                has_penalty_risk=True,
                penalty_score=50,
                penalty_types=["analysis_error"],
                detected_issues=[f"analysis_error: {str(e)}"],
                recommendations=["Manual review recommended due to analysis error"],
                platform_specific_penalties={},
                link_analysis={},
                confidence_score=0.0,
                analysis_timestamp=datetime.now(timezone.utc).isoformat()
            )
    
    def _extract_links(self, content: str) -> List[str]:
        """Extract URLs from content."""
        # URL regex pattern
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        links = re.findall(url_pattern, content)
        
        # Also check for common URL patterns without protocol
        domain_pattern = r'(?:www\.)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?'
        potential_links = re.findall(domain_pattern, content)
        
        # Add http:// to potential links that don't have protocol
        for link in potential_links:
            if not link.startswith(('http://', 'https://')):
                full_link = f"https://{link}"
                if full_link not in links:
                    links.append(full_link)
        
        return links
    
    async def _analyze_single_link(self, link: str, platform: str) -> Dict[str, Any]:
        """Analyze a single link for penalty risks."""
        analysis = {
            "url": link,
            "has_penalty_risk": False,
            "penalty_score": 0,
            "penalty_types": [],
            "issues": []
        }
        
        try:
            # Parse URL
            parsed_url = urlparse(link)
            domain = parsed_url.netloc.lower()
            path = parsed_url.path.lower()
            query = parsed_url.query.lower()
            
            # Extract domain information
            extracted = tldextract.extract(link)
            domain_name = f"{extracted.domain}.{extracted.suffix}".lower()
            
            # Check for URL shorteners
            if any(shortener in domain for shortener in self.problematic_domains["url_shorteners"]):
                analysis["penalty_score"] += 20
                analysis["penalty_types"].append("url_shortener")
                analysis["issues"].append(f"URL shortener detected: {domain}")
                analysis["has_penalty_risk"] = True
            
            # Check for spam domains
            if any(spam_domain in domain for spam_domain in self.problematic_domains["spam_domains"]):
                analysis["penalty_score"] += 40
                analysis["penalty_types"].append("spam_domain")
                analysis["issues"].append(f"Spam domain detected: {domain}")
                analysis["has_penalty_risk"] = True
            
            # Check for low-quality domains
            if any(lq_domain in domain for lq_domain in self.problematic_domains["low_quality_domains"]):
                analysis["penalty_score"] += 30
                analysis["penalty_types"].append("low_quality_domain")
                analysis["issues"].append(f"Low-quality domain detected: {domain}")
                analysis["has_penalty_risk"] = True
            
            # Check for affiliate networks
            if any(affiliate in domain for affiliate in self.problematic_domains["affiliate_networks"]):
                analysis["penalty_score"] += 25
                analysis["penalty_types"].append("affiliate_link")
                analysis["issues"].append(f"Affiliate network detected: {domain}")
                analysis["has_penalty_risk"] = True
            
            # Check for suspicious parameters
            for pattern in self.penalty_patterns["suspicious_parameters"]:
                if re.search(pattern, query, re.IGNORECASE):
                    analysis["penalty_score"] += 15
                    analysis["penalty_types"].append("suspicious_parameters")
                    analysis["issues"].append(f"Suspicious parameter: {pattern}")
                    analysis["has_penalty_risk"] = True
            
            # Check for penalty triggers in URL
            for pattern in self.penalty_patterns["penalty_triggers"]:
                if re.search(pattern, link.lower(), re.IGNORECASE):
                    analysis["penalty_score"] += 10
                    analysis["penalty_types"].append("penalty_trigger")
                    analysis["issues"].append(f"Penalty trigger in URL: {pattern}")
            
            # Check for redirect indicators
            for pattern in self.penalty_patterns["redirect_indicators"]:
                if re.search(pattern, path, re.IGNORECASE):
                    analysis["penalty_score"] += 15
                    analysis["penalty_types"].append("redirect_chain")
                    analysis["issues"].append(f"Redirect indicator: {pattern}")
            
            # Check protocol security
            if not link.startswith("https://"):
                analysis["penalty_score"] += 10
                analysis["penalty_types"].append("insecure_protocol")
                analysis["issues"].append("Non-HTTPS URL detected")
            
            # Check for quality indicators
            positive_indicators = sum(1 for indicator in self.quality_indicators["positive"] 
                                    if indicator in link.lower())
            negative_indicators = sum(1 for indicator in self.quality_indicators["negative"] 
                                    if indicator in link.lower())
            
            if negative_indicators > positive_indicators:
                analysis["penalty_score"] += (negative_indicators - positive_indicators) * 5
                analysis["penalty_types"].append("negative_quality_indicators")
                analysis["issues"].append("Negative quality indicators detected")
            
            # Determine penalty risk
            if analysis["penalty_score"] >= 20:
                analysis["has_penalty_risk"] = True
            
        except Exception as e:
            analysis["penalty_score"] = 30
            analysis["penalty_types"].append("analysis_error")
            analysis["issues"].append(f"Link analysis error: {str(e)}")
            analysis["has_penalty_risk"] = True
        
        return analysis
    
    async def _analyze_platform_penalties(self, links: List[str], platform: str, 
                                        content: str) -> Dict[str, Any]:
        """Analyze platform-specific link penalties."""
        penalties = {}
        additional_penalty = 0
        recommendations = []
        
        platform_config = self.platform_penalties.get(platform, {})
        
        if platform == "twitter":
            # External link penalty
            if links:
                additional_penalty += int(len(links) * 20 * platform_config.get("external_link_penalty", 0.3))
                recommendations.append("Consider using Twitter Cards to reduce link penalty")
            
            # Multiple links penalty
            if len(links) > 1:
                additional_penalty += int(30 * platform_config.get("multiple_links_penalty", 0.4))
                recommendations.append("Limit to one external link per tweet")
        
        elif platform == "facebook":
            # Check for clickbait patterns in content
            clickbait_patterns = [
                r"you\s+won't\s+believe",
                r"this\s+will\s+shock\s+you",
                r"number\s+\d+\s+will\s+amaze\s+you",
                r"what\s+happened\s+next"
            ]
            
            for pattern in clickbait_patterns:
                if re.search(pattern, content.lower(), re.IGNORECASE):
                    additional_penalty += int(40 * platform_config.get("clickbait_link_penalty", 0.7))
                    recommendations.append("Avoid clickbait language with external links")
                    break
        
        elif platform == "instagram":
            # Post link penalty
            if links:
                additional_penalty += int(25 * platform_config.get("post_link_penalty", 0.4))
                recommendations.append("Consider using link in bio instead of post links")
        
        elif platform == "linkedin":
            # Check for professional domains
            professional_domains = [".edu", ".gov", ".org", "linkedin.com", "microsoft.com"]
            has_professional_link = any(domain in link.lower() for link in links 
                                      for domain in professional_domains)
            
            if has_professional_link:
                additional_penalty -= int(10 * platform_config.get("professional_domain_bonus", 0.2))
            else:
                additional_penalty += int(20 * platform_config.get("external_link_penalty", 0.4))
                recommendations.append("Use professional domains when possible")
        
        elif platform == "tiktok":
            # TikTok heavily penalizes external links
            if links:
                additional_penalty += int(50 * platform_config.get("external_link_penalty", 0.6))
                recommendations.append("Remove external links - use bio link instead")
        
        penalties.update({
            "additional_penalty": additional_penalty,
            "recommendations": recommendations,
            "platform_config": platform_config
        })
        
        return penalties
    
    def _generate_recommendations(self, penalty_types: List[str], platform: str) -> List[str]:
        """Generate recommendations based on detected penalty types."""
        recommendations = []
        
        if "url_shortener" in penalty_types:
            recommendations.append("Use full URLs instead of shortened links when possible")
        
        if "affiliate_link" in penalty_types:
            recommendations.append("Disclose affiliate relationships and consider native alternatives")
        
        if "spam_domain" in penalty_types:
            recommendations.append("Avoid linking to known spam or low-quality domains")
        
        if "suspicious_parameters" in penalty_types:
            recommendations.append("Clean up URL parameters to remove tracking codes")
        
        if "redirect_chain" in penalty_types:
            recommendations.append("Use direct links instead of redirect chains")
        
        if "insecure_protocol" in penalty_types:
            recommendations.append("Use HTTPS URLs for better security and trust")
        
        # Platform-specific recommendations
        if platform == "twitter":
            recommendations.append("Consider using Twitter Cards for better link presentation")
        elif platform == "facebook":
            recommendations.append("Use Facebook's native sharing features when possible")
        elif platform == "instagram":
            recommendations.append("Utilize Instagram's link in bio feature")
        elif platform == "linkedin":
            recommendations.append("Share professional and industry-relevant links")
        elif platform == "tiktok":
            recommendations.append("Focus on native content - avoid external links in posts")
        
        return recommendations
    
    def _calculate_confidence_score(self, link_count: int, penalty_type_count: int, 
                                  issue_count: int) -> float:
        """Calculate confidence score for the analysis."""
        # Base confidence
        confidence = 0.8
        
        # Increase confidence with more links analyzed
        if link_count > 0:
            confidence += min(0.1, link_count * 0.02)
        
        # Increase confidence with more detected issues
        if issue_count > 0:
            confidence += min(0.1, issue_count * 0.02)
        
        # High confidence for multiple penalty types
        if penalty_type_count > 2:
            confidence = min(0.95, confidence + 0.05)
        
        return round(confidence, 2)