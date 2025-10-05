"""
Link Penalty Detector for Social Media Protection.

This module provides specialized detection for external link penalties and algorithmic
restrictions that can impact social media content reach and engagement.
"""

import re
import asyncio
import aiohttp
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs
import tldextract

from linkshield.services.ai_service import AIService
from linkshield.config.settings import get_settings


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
                "affiliate_link_penalty": 0.6,   # 60% penalty for affiliate links
                "allowed_domains": ["twitter.com", "x.com", "t.co"],
                "max_links": 1,  # Optimal number of links
                "rules": {
                    "avoid_url_shorteners": True,
                    "prefer_twitter_cards": True,
                    "limit_external_links": True
                }
            },
            "facebook": {
                "external_link_penalty": 0.5,   # 50% reach reduction
                "clickbait_link_penalty": 0.7,  # 70% penalty for clickbait
                "low_quality_domain_penalty": 0.6,  # 60% penalty for low-quality domains
                "engagement_bait_penalty": 0.8,   # 80% penalty for engagement bait
                "allowed_domains": ["facebook.com", "fb.com", "instagram.com"],
                "max_links": 1,
                "rules": {
                    "avoid_clickbait": True,
                    "prefer_native_video": True,
                    "avoid_link_farms": True,
                    "check_domain_quality": True
                }
            },
            "instagram": {
                "bio_link_preference": True,     # Prefer bio links over post links
                "story_link_penalty": 0.2,      # 20% penalty for story links
                "post_link_penalty": 0.4,       # 40% penalty for post links
                "swipe_up_alternative": True,     # Use swipe up alternatives
                "allowed_domains": ["instagram.com", "facebook.com"],
                "max_links": 0,  # No links in posts (bio only)
                "rules": {
                    "bio_link_only": True,
                    "no_post_links": True,
                    "story_swipe_up_10k": True  # Need 10k followers for swipe up
                }
            },
            "linkedin": {
                "external_link_penalty": 0.4,   # 40% reach reduction
                "native_content_preference": True,  # Prefer native content
                "professional_domain_bonus": 0.2,   # 20% bonus for professional domains
                "spam_link_penalty": 0.8,         # 80% penalty for spam links
                "allowed_domains": ["linkedin.com"],
                "professional_domains": [".edu", ".gov", ".org"],
                "max_links": 1,
                "rules": {
                    "prefer_professional_domains": True,
                    "avoid_promotional_links": True,
                    "native_content_bonus": True
                }
            },
            "tiktok": {
                "external_link_penalty": 0.6,   # 60% reach reduction
                "bio_link_only": True,           # Only bio links allowed
                "suspicious_link_penalty": 0.9, # 90% penalty for suspicious links
                "affiliate_link_ban": True,       # Affiliate links banned
                "allowed_domains": ["tiktok.com"],
                "max_links": 0,  # No links in posts
                "rules": {
                    "bio_link_only": True,
                    "no_external_links": True,
                    "ban_affiliate_links": True
                }
            },
            "discord": {
                "external_link_penalty": 0.2,   # 20% penalty (more lenient)
                "phishing_link_penalty": 0.9,   # 90% penalty for phishing
                "allowed_domains": ["discord.com", "discord.gg"],
                "max_links": 5,  # More lenient
                "rules": {
                    "check_phishing": True,
                    "allow_external_links": True,
                    "warn_suspicious": True
                }
            },
            "telegram": {
                "external_link_penalty": 0.3,   # 30% penalty
                "spam_link_penalty": 0.8,       # 80% penalty for spam
                "allowed_domains": ["t.me", "telegram.org"],
                "max_links": 3,
                "rules": {
                    "check_spam": True,
                    "allow_external_links": True,
                    "warn_suspicious": True
                }
            }
        }
        
        # Platform-specific link rule checkers
        self.platform_rule_checkers = {
            "twitter": self._check_twitter_link_rules,
            "facebook": self._check_facebook_link_rules,
            "instagram": self._check_instagram_link_rules,
            "linkedin": self._check_linkedin_link_rules,
            "tiktok": self._check_tiktok_link_rules,
            "discord": self._check_discord_link_rules,
            "telegram": self._check_telegram_link_rules
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
                # Popular URL shorteners
                "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co",
                "short.link", "tiny.cc", "is.gd", "buff.ly", "adf.ly",
                "bl.ink", "clicky.me", "db.tt", "filoops.info", "fun.ly",
                "fzy.co", "git.io", "goo.gl", "ht.ly", "ity.im",
                "j.mp", "lnkd.in", "oe.cd", "ow.ly", "po.st",
                "q.gs", "qr.ae", "qr.net", "s.id", "scrnch.me",
                "short.io", "shorturl.at", "soo.gd", "t.co", "t2m.io",
                "tinycc.com", "tr.im", "trib.al", "u.to", "v.gd",
                "x.co", "y2u.be", "youtu.be", "zip.net", "zpr.io",
                # Social media shorteners
                "fb.me", "ig.me", "ln.is", "lnk.to", "sptfy.com",
                # Regional shorteners
                "bc.vc", "chilp.it", "clck.ru", "cutt.ly", "hyperurl.co",
                "kl.am", "mcaf.ee", "moourl.com", "qlnk.io", "rb.gy",
                "rebrand.ly", "short.cm", "shorturl.com", "snip.ly", "surl.li",
                "t1p.de", "tinu.be", "tiny.one", "url.ie", "urlz.fr"
            ]
        }
        
        # URL shortener patterns (for detection beyond known domains)
        self.shortener_patterns = [
            r"^https?://[a-z0-9-]{1,10}\.[a-z]{2,3}/[a-zA-Z0-9]+$",  # Short domain with short path
            r"^https?://[a-z]{2,5}\.(ly|me|co|io|gl|gd|to)/.+$",  # Common shortener TLDs
        ]
        
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
                
                # Always extend penalty types and issues from individual links
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
    
    async def _check_domain_reputation(self, link: str) -> Dict[str, Any]:
        """
        Check domain reputation using external services.
        
        Args:
            link: URL to check
            
        Returns:
            Dictionary with reputation data
        """
        reputation_data = {
            "has_reputation_issues": False,
            "reputation_score": 50,  # Neutral default
            "penalty_score": 0,
            "issues": []
        }
        
        try:
            # Extract domain
            parsed_url = urlparse(link)
            domain = parsed_url.netloc.lower()
            
            # Check if we have VirusTotal API key
            if self.settings.VIRUSTOTAL_API_KEY:
                vt_result = await self._check_virustotal_reputation(domain)
                if vt_result.get("malicious_count", 0) > 0:
                    reputation_data["has_reputation_issues"] = True
                    reputation_data["penalty_score"] += 40
                    reputation_data["issues"].append(
                        f"VirusTotal flagged by {vt_result['malicious_count']} engines"
                    )
                    reputation_data["reputation_score"] = max(
                        0, 100 - (vt_result["malicious_count"] * 10)
                    )
            
            # Check Google Safe Browsing if available
            if self.settings.GOOGLE_SAFE_BROWSING_API_KEY:
                gsb_result = await self._check_safe_browsing(link)
                if gsb_result.get("threat_detected", False):
                    reputation_data["has_reputation_issues"] = True
                    reputation_data["penalty_score"] += 50
                    reputation_data["issues"].append(
                        f"Google Safe Browsing: {', '.join(gsb_result.get('threat_types', []))}"
                    )
                    reputation_data["reputation_score"] = 0
            
        except Exception as e:
            reputation_data["issues"].append(f"Reputation check error: {str(e)}")
        
        return reputation_data
    
    async def _check_virustotal_reputation(self, domain: str) -> Dict[str, Any]:
        """Check domain reputation on VirusTotal."""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://www.virustotal.com/vtapi/v2/domain/report"
                params = {
                    "apikey": self.settings.VIRUSTOTAL_API_KEY,
                    "domain": domain
                }
                
                async with session.get(url, params=params, timeout=5) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Count malicious detections
                        detected_urls = data.get("detected_urls", [])
                        malicious_count = sum(
                            1 for url_data in detected_urls 
                            if url_data.get("positives", 0) > 0
                        )
                        
                        return {
                            "malicious_count": malicious_count,
                            "total_urls": len(detected_urls),
                            "categories": data.get("categories", [])
                        }
        except Exception:
            pass
        
        return {"malicious_count": 0, "total_urls": 0}
    
    async def _check_safe_browsing(self, url: str) -> Dict[str, Any]:
        """Check URL against Google Safe Browsing."""
        try:
            async with aiohttp.ClientSession() as session:
                api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
                
                payload = {
                    "client": {
                        "clientId": "linkshield-social-protection",
                        "clientVersion": "1.0"
                    },
                    "threatInfo": {
                        "threatTypes": [
                            "MALWARE",
                            "SOCIAL_ENGINEERING",
                            "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"
                        ],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": url}]
                    }
                }
                
                params = {"key": self.settings.GOOGLE_SAFE_BROWSING_API_KEY}
                
                async with session.post(api_url, json=payload, params=params, timeout=5) as response:
                    if response.status == 200:
                        result = await response.json()
                        matches = result.get("matches", [])
                        
                        if matches:
                            threat_types = [
                                match.get("threatType", "unknown").lower() 
                                for match in matches
                            ]
                            return {
                                "threat_detected": True,
                                "threat_types": threat_types
                            }
        except Exception:
            pass
        
        return {"threat_detected": False, "threat_types": []}
    
    def _detect_url_shortener(self, link: str) -> Dict[str, Any]:
        """
        Detect if a URL is a shortener and identify the service.
        
        Args:
            link: URL to check
            
        Returns:
            Dictionary with shortener detection results
        """
        result = {
            "is_shortener": False,
            "shortener_service": None,
            "confidence": 0.0,
            "penalty_score": 0
        }
        
        try:
            parsed_url = urlparse(link)
            domain = parsed_url.netloc.lower()
            path = parsed_url.path
            
            # Check against known shortener domains
            for shortener in self.problematic_domains["url_shorteners"]:
                if shortener in domain:
                    result["is_shortener"] = True
                    result["shortener_service"] = shortener
                    result["confidence"] = 1.0
                    result["penalty_score"] = 20
                    return result
            
            # Check against shortener patterns
            for pattern in self.shortener_patterns:
                if re.match(pattern, link):
                    result["is_shortener"] = True
                    result["shortener_service"] = "unknown_shortener"
                    result["confidence"] = 0.7
                    result["penalty_score"] = 15
                    return result
            
            # Heuristic checks for shortener-like URLs
            # Short domain + short path often indicates a shortener
            domain_parts = domain.split('.')
            if len(domain_parts) >= 2:
                domain_name = domain_parts[-2]
                
                # Very short domain name (2-5 chars) with short path
                if len(domain_name) <= 5 and len(path) <= 10 and len(path) > 1:
                    result["is_shortener"] = True
                    result["shortener_service"] = "suspected_shortener"
                    result["confidence"] = 0.5
                    result["penalty_score"] = 10
                    return result
            
            # Check for common shortener TLDs
            shortener_tlds = [".ly", ".me", ".co", ".io", ".gl", ".gd", ".to"]
            if any(domain.endswith(tld) for tld in shortener_tlds):
                # If it's a short domain with these TLDs, likely a shortener
                if len(domain) <= 15:
                    result["is_shortener"] = True
                    result["shortener_service"] = "suspected_shortener"
                    result["confidence"] = 0.6
                    result["penalty_score"] = 12
                    return result
        
        except Exception:
            pass
        
        return result
    
    async def _analyze_redirect_chain(self, link: str, max_redirects: int = 5) -> Dict[str, Any]:
        """
        Analyze redirect chain for a URL.
        
        Args:
            link: URL to analyze
            max_redirects: Maximum number of redirects to follow
            
        Returns:
            Dictionary with redirect chain analysis
        """
        result = {
            "has_redirects": False,
            "redirect_count": 0,
            "redirect_chain": [],
            "final_url": link,
            "suspicious_redirects": False,
            "penalty_score": 0,
            "issues": []
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                current_url = link
                visited_urls = [link]
                redirect_count = 0
                
                # Follow redirects manually to track the chain
                for i in range(max_redirects):
                    try:
                        async with session.head(
                            current_url,
                            allow_redirects=False,
                            timeout=aiohttp.ClientTimeout(total=5)
                        ) as response:
                            # Check if there's a redirect
                            if response.status in (301, 302, 303, 307, 308):
                                redirect_count += 1
                                next_url = response.headers.get('Location')
                                
                                if not next_url:
                                    break
                                
                                # Handle relative URLs
                                if not next_url.startswith(('http://', 'https://')):
                                    from urllib.parse import urljoin
                                    next_url = urljoin(current_url, next_url)
                                
                                visited_urls.append(next_url)
                                
                                # Check for redirect loops
                                if next_url in visited_urls[:-1]:
                                    result["issues"].append("Redirect loop detected")
                                    result["suspicious_redirects"] = True
                                    result["penalty_score"] += 30
                                    break
                                
                                current_url = next_url
                            else:
                                # No more redirects
                                break
                    
                    except asyncio.TimeoutError:
                        result["issues"].append("Redirect chain timeout")
                        break
                    except Exception as e:
                        result["issues"].append(f"Redirect error: {str(e)}")
                        break
                
                result["has_redirects"] = redirect_count > 0
                result["redirect_count"] = redirect_count
                result["redirect_chain"] = visited_urls
                result["final_url"] = current_url
                
                # Analyze redirect chain for suspicious patterns
                if redirect_count > 0:
                    # Multiple redirects are suspicious
                    if redirect_count > 2:
                        result["suspicious_redirects"] = True
                        result["penalty_score"] += redirect_count * 10
                        result["issues"].append(
                            f"Excessive redirects ({redirect_count}) - may hide destination"
                        )
                    
                    # Check if redirects go through different domains
                    domains = set()
                    for url in visited_urls:
                        parsed = urlparse(url)
                        domains.add(parsed.netloc.lower())
                    
                    if len(domains) > 2:
                        result["suspicious_redirects"] = True
                        result["penalty_score"] += 15
                        result["issues"].append(
                            f"Redirects through multiple domains ({len(domains)})"
                        )
                    
                    # Check if final URL is very different from original
                    original_domain = urlparse(link).netloc.lower()
                    final_domain = urlparse(current_url).netloc.lower()
                    
                    if original_domain != final_domain:
                        # Check if it's a known shortener redirecting (acceptable)
                        is_shortener_redirect = any(
                            shortener in original_domain 
                            for shortener in self.problematic_domains["url_shorteners"]
                        )
                        
                        if not is_shortener_redirect:
                            result["suspicious_redirects"] = True
                            result["penalty_score"] += 10
                            result["issues"].append(
                                f"Unexpected domain change: {original_domain} -> {final_domain}"
                            )
                    
                    # Check for protocol downgrade (HTTPS -> HTTP)
                    for i in range(len(visited_urls) - 1):
                        current_parsed = urlparse(visited_urls[i])
                        next_parsed = urlparse(visited_urls[i + 1])
                        
                        if current_parsed.scheme == 'https' and next_parsed.scheme == 'http':
                            result["suspicious_redirects"] = True
                            result["penalty_score"] += 25
                            result["issues"].append("Security downgrade: HTTPS -> HTTP redirect")
                            break
        
        except Exception as e:
            result["issues"].append(f"Redirect analysis error: {str(e)}")
        
        return result
    
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
            
            # Check domain reputation (subtask 6.1)
            reputation_data = await self._check_domain_reputation(link)
            if reputation_data["has_reputation_issues"]:
                analysis["penalty_score"] += reputation_data["penalty_score"]
                analysis["penalty_types"].append("poor_domain_reputation")
                analysis["issues"].extend(reputation_data["issues"])
                analysis["has_penalty_risk"] = True
            
            # Check for URL shorteners (subtask 6.3)
            shortener_result = self._detect_url_shortener(link)
            if shortener_result["is_shortener"]:
                analysis["penalty_score"] += shortener_result["penalty_score"]
                analysis["penalty_types"].append("url_shortener")
                analysis["issues"].append(
                    f"URL shortener detected: {shortener_result['shortener_service']} "
                    f"(confidence: {shortener_result['confidence']:.0%})"
                )
                analysis["has_penalty_risk"] = True
                analysis["shortener_info"] = shortener_result
            
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
            
            # Check for redirect indicators in path
            for pattern in self.penalty_patterns["redirect_indicators"]:
                if re.search(pattern, path, re.IGNORECASE):
                    analysis["penalty_score"] += 15
                    analysis["penalty_types"].append("redirect_indicator")
                    analysis["issues"].append(f"Redirect indicator in path: {pattern}")
            
            # Analyze redirect chain (subtask 6.4)
            redirect_result = await self._analyze_redirect_chain(link)
            if redirect_result["has_redirects"]:
                analysis["penalty_score"] += redirect_result["penalty_score"]
                if redirect_result["suspicious_redirects"]:
                    analysis["penalty_types"].append("suspicious_redirect_chain")
                    analysis["has_penalty_risk"] = True
                analysis["issues"].extend(redirect_result["issues"])
                analysis["redirect_info"] = {
                    "redirect_count": redirect_result["redirect_count"],
                    "final_url": redirect_result["final_url"],
                    "suspicious": redirect_result["suspicious_redirects"]
                }
            
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
        platform_issues = []
        
        platform_config = self.platform_penalties.get(platform, {})
        
        # Use platform-specific rule checker if available
        if platform in self.platform_rule_checkers:
            rule_result = self.platform_rule_checkers[platform](links, content)
            additional_penalty += rule_result.get("penalty_score", 0)
            platform_issues.extend(rule_result.get("issues", []))
        
        # Apply base platform penalties
        if links:
            external_penalty = platform_config.get("external_link_penalty", 0.3)
            additional_penalty += int(len(links) * 15 * external_penalty)
        
        # Check max links rule
        max_links = platform_config.get("max_links", 999)
        if len(links) > max_links:
            additional_penalty += (len(links) - max_links) * 20
            platform_issues.append(
                f"Exceeds recommended link count ({len(links)} > {max_links})"
            )
        
        # Generate platform-specific recommendations
        if platform == "twitter":
            if links:
                recommendations.append("Consider using Twitter Cards to reduce link penalty")
            if len(links) > 1:
                recommendations.append("Limit to one external link per tweet")
        
        elif platform == "facebook":
            recommendations.append("Use Facebook's native sharing features when possible")
            if len(links) > 1:
                recommendations.append("Single link posts perform better on Facebook")
        
        elif platform == "instagram":
            recommendations.append("Use link in bio - Instagram doesn't support clickable post links")
            recommendations.append("Consider Instagram Stories with swipe-up (requires 10k followers)")
        
        elif platform == "linkedin":
            recommendations.append("Share professional and industry-relevant links")
            recommendations.append("Native content without links gets better reach")
        
        elif platform == "tiktok":
            recommendations.append("Focus on native content - avoid external links in posts")
            recommendations.append("Use bio link for external references")
        
        elif platform == "discord":
            recommendations.append("Be cautious with external links - check for phishing")
        
        elif platform == "telegram":
            recommendations.append("Limit promotional links to avoid spam flags")
        
        penalties.update({
            "additional_penalty": additional_penalty,
            "recommendations": recommendations,
            "platform_config": platform_config,
            "platform_issues": platform_issues
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
    
    def _check_twitter_link_rules(self, links: List[str], content: str) -> Dict[str, Any]:
        """Check Twitter-specific link rules."""
        issues = []
        penalty_score = 0
        
        # Check link count
        if len(links) > 1:
            issues.append(f"Multiple links detected ({len(links)}) - Twitter penalizes multiple external links")
            penalty_score += 20
        
        # Check for URL shorteners (Twitter prefers full URLs or t.co)
        for link in links:
            if any(shortener in link for shortener in ["bit.ly", "tinyurl.com", "goo.gl"]):
                issues.append("URL shortener detected - use full URLs or Twitter Cards")
                penalty_score += 15
        
        return {"issues": issues, "penalty_score": penalty_score}
    
    def _check_facebook_link_rules(self, links: List[str], content: str) -> Dict[str, Any]:
        """Check Facebook-specific link rules."""
        issues = []
        penalty_score = 0
        
        # Check for clickbait patterns
        clickbait_patterns = [
            r"you\s+won't\s+believe",
            r"this\s+will\s+shock\s+you",
            r"number\s+\d+\s+will",
            r"what\s+happened\s+next",
            r"doctors\s+hate",
            r"one\s+weird\s+trick"
        ]
        
        for pattern in clickbait_patterns:
            if re.search(pattern, content.lower()):
                issues.append("Clickbait language detected - Facebook heavily penalizes this")
                penalty_score += 30
                break
        
        # Check link count
        if len(links) > 1:
            issues.append("Multiple links may reduce reach - Facebook prefers single link posts")
            penalty_score += 15
        
        return {"issues": issues, "penalty_score": penalty_score}
    
    def _check_instagram_link_rules(self, links: List[str], content: str) -> Dict[str, Any]:
        """Check Instagram-specific link rules."""
        issues = []
        penalty_score = 0
        
        # Instagram doesn't allow clickable links in posts
        if links:
            issues.append("Instagram doesn't support clickable links in posts - use link in bio")
            penalty_score += 25
        
        return {"issues": issues, "penalty_score": penalty_score}
    
    def _check_linkedin_link_rules(self, links: List[str], content: str) -> Dict[str, Any]:
        """Check LinkedIn-specific link rules."""
        issues = []
        penalty_score = 0
        
        # Check for professional domains
        professional_domains = [".edu", ".gov", ".org"]
        has_professional = any(
            any(prof_domain in link for prof_domain in professional_domains)
            for link in links
        )
        
        if not has_professional and links:
            issues.append("Consider using professional domains (.edu, .gov, .org) for better reach")
            penalty_score += 10
        
        # Check for promotional content
        promo_keywords = ["discount", "sale", "buy now", "limited time", "offer"]
        if any(keyword in content.lower() for keyword in promo_keywords):
            issues.append("Promotional content with links may be penalized on LinkedIn")
            penalty_score += 20
        
        return {"issues": issues, "penalty_score": penalty_score}
    
    def _check_tiktok_link_rules(self, links: List[str], content: str) -> Dict[str, Any]:
        """Check TikTok-specific link rules."""
        issues = []
        penalty_score = 0
        
        # TikTok heavily restricts external links
        if links:
            issues.append("TikTok heavily penalizes external links - use bio link only")
            penalty_score += 40
        
        # Check for affiliate links (banned on TikTok)
        affiliate_indicators = ["affiliate", "ref=", "aff=", "commission"]
        for link in links:
            if any(indicator in link.lower() for indicator in affiliate_indicators):
                issues.append("Affiliate links are banned on TikTok")
                penalty_score += 50
                break
        
        return {"issues": issues, "penalty_score": penalty_score}
    
    def _check_discord_link_rules(self, links: List[str], content: str) -> Dict[str, Any]:
        """Check Discord-specific link rules."""
        issues = []
        penalty_score = 0
        
        # Discord is more lenient but checks for phishing
        phishing_indicators = ["discord-nitro", "free-nitro", "discordgift", "steam-gift"]
        for link in links:
            link_lower = link.lower()
            if any(indicator in link_lower for indicator in phishing_indicators):
                if "discord.com" not in link_lower and "discord.gg" not in link_lower:
                    issues.append("Potential phishing link detected")
                    penalty_score += 45
                    break
        
        return {"issues": issues, "penalty_score": penalty_score}
    
    def _check_telegram_link_rules(self, links: List[str], content: str) -> Dict[str, Any]:
        """Check Telegram-specific link rules."""
        issues = []
        penalty_score = 0
        
        # Check for spam patterns
        if len(links) > 3:
            issues.append("Too many links may be flagged as spam")
            penalty_score += 25
        
        # Check for suspicious patterns
        spam_keywords = ["crypto", "investment", "guaranteed", "profit", "earn money"]
        if any(keyword in content.lower() for keyword in spam_keywords) and links:
            issues.append("Promotional content with links may be flagged as spam")
            penalty_score += 20
        
        return {"issues": issues, "penalty_score": penalty_score}
    
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