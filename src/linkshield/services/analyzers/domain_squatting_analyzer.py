#!/usr/bin/env python3
"""
Domain Squatting Analyzer

A comprehensive analyzer for detecting domain squatting attempts, typosquatting,
and related malicious domain registrations targeting legitimate brands and services.
"""

import re
import asyncio
import aiohttp
import difflib
from typing import Dict, Any, List, Optional, Set, Tuple
from urllib.parse import urlparse
from dataclasses import dataclass
from enum import Enum
from datetime import datetime
from bs4 import BeautifulSoup


class SquattingType(Enum):
    """Types of domain squatting detected."""
    TYPOSQUATTING = "typosquatting"
    COMBOSQUATTING = "combosquatting" 
    HOMOGRAPH = "homograph"
    SUBDOMAIN_SQUATTING = "subdomain_squatting"
    TLD_SQUATTING = "tld_squatting"
    HYPHEN_SQUATTING = "hyphen_squatting"
    PLURAL_SQUATTING = "plural_squatting"
    KEYWORD_SQUATTING = "keyword_squatting"


class ThreatLevel(Enum):
    """Threat levels for squatting attempts."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SquattingMatch:
    """Represents a detected domain squatting attempt."""
    squatting_type: SquattingType
    target_domain: str
    confidence: float  # 0.0 to 1.0
    edit_distance: int
    similarity_score: float
    evidence: str
    threat_level: ThreatLevel


@dataclass
class ContentAnalysis:
    """Analysis of squatting domain content."""
    has_content: bool
    content_similarity: float  # Similarity to target domain
    phishing_indicators: List[str]
    social_engineering_detected: bool
    malicious_content_detected: bool
    legitimate_business: bool
    parked_domain: bool
    error_page: bool
    content_summary: str


@dataclass
class DomainSquattingResult:
    """Complete domain squatting analysis result."""
    domain: str
    is_squatting: bool
    squatting_matches: List[SquattingMatch]
    content_analysis: Optional[ContentAnalysis]
    overall_threat_level: ThreatLevel
    confidence_score: float
    risk_factors: List[str]
    analysis_summary: str


class DomainSquattingAnalyzer:
    """
    Comprehensive analyzer for domain squatting detection and threat assessment.
    """
    
    def __init__(self):
        """Initialize the domain squatting analyzer."""
        self.legitimate_domains = self._init_legitimate_domains()
        self.common_tlds = self._init_common_tlds()
        self.homograph_chars = self._init_homograph_chars()
        self.user_agent = "LinkShield-Bot/1.0 Domain-Squatting-Analyzer"
        
    def _init_legitimate_domains(self) -> Set[str]:
        """Initialize comprehensive list of legitimate domains to protect against."""
        return {
            # Tech & Social Media Giants
            'google', 'facebook', 'microsoft', 'apple', 'amazon',
            'twitter', 'instagram', 'linkedin', 'github', 'stackoverflow', 
            'paypal', 'whatsapp', 'stripe', 'youtube', 'tiktok', 'snapchat', 
            'pinterest', 'reddit', 'discord', 'telegram', 'signal', 'slack', 
            'zoom', 'skype', 'twitch', 'spotify',
            
            # E-commerce & Retail
            'ebay', 'etsy', 'shopify', 'walmart', 'target', 'bestbuy', 
            'aliexpress', 'alibaba', 'wish', 'overstock', 'wayfair', 
            'homedepot', 'lowes', 'costco', 'sears', 'macys', 'nordstrom', 
            'zappos', 'asos', 'newegg', 'groupon',
            
            # Financial & Banking
            'chase', 'bankofamerica', 'wellsfargo', 'citibank', 'capitalone',
            'americanexpress', 'visa', 'mastercard', 'discover', 'schwab', 
            'fidelity', 'vanguard', 'morganstanley', 'goldmansachs', 
            'jpmorgan', 'square', 'coinbase', 'binance', 'kraken', 
            'robinhood', 'sofi', 'transferwise', 'westernunion',
            
            # Cloud & Infrastructure
            'aws', 'azure', 'cloudflare', 'digitalocean', 'linode', 
            'heroku', 'oracle', 'ibm', 'salesforce', 'servicenow', 
            'workday', 'sap',
            
            # Email Providers
            'gmail', 'outlook', 'yahoo', 'protonmail', 'aol', 'icloud', 
            'zoho', 'yandex', 'gmx',
            
            # Government & Education
            'irs', 'ssa', 'usps', 'ups', 'fedex', 'dhl', 'state', 
            'whitehouse', 'harvard', 'stanford', 'mit', 'cambridge', 
            'oxford', 'coursera', 'edx', 'udemy', 'khanacademy',
            
            # Media & News
            'cnn', 'foxnews', 'bbc', 'reuters', 'ap', 'bloomberg', 
            'wsj', 'nytimes', 'washingtonpost', 'theguardian', 
            'huffpost', 'buzzfeed', 'netflix', 'hulu', 'disneyplus', 
            'hbo', 'paramount', 'peacock',
            
            # Gaming
            'steam', 'epicgames', 'xbox', 'playstation', 'nintendo', 
            'ea', 'activision', 'ubisoft', 'blizzard', 'riotgames', 
            'minecraft', 'roblox', 'fortnite',
            
            # Travel & Hospitality
            'expedia', 'booking', 'airbnb', 'vrbo', 'tripadvisor', 
            'kayak', 'priceline', 'hotels', 'marriott', 'hilton', 
            'hyatt', 'delta', 'united', 'americanairlines', 'southwest',
            
            # Automotive
            'tesla', 'ford', 'gm', 'toyota', 'honda', 'bmw', 
            'mercedesbenz', 'audi', 'volkswagen', 'nissan', 'hyundai',
            
            # Food & Delivery
            'ubereats', 'doordash', 'grubhub', 'postmates', 'deliveroo',
            'mcdonalds', 'starbucks', 'subway', 'pizzahut', 'dominos',
            'chipotle', 'kfc', 'burgerking', 'wendys',
            
            # Health & Fitness
            'webmd', 'mayoclinic', 'cvs', 'walgreens', 'goodrx', 
            'fitbit', 'myfitnesspal', 'strava', 'peloton', 'calm', 
            'headspace',
            
            # Regional & International
            'baidu', 'taobao', 'qq', 'weibo', 'wechat', 'alipay', 
            'rakuten', 'yandex', 'mailru', 'sberbank', 'deezer', 
            'orange', 'vodafone',
            
            # Additional Major Platforms
            'dropbox', 'box', 'evernote', 'adobe', 'autodesk', 'intel', 
            'amd', 'nvidia', 'qualcomm', 'cisco', 'dell', 'hp', 'lenovo', 
            'logitech', 'godaddy', 'namecheap', 'wordpress', 'wix', 
            'squarespace',
            
            # Crypto & Web3
            'metamask', 'opensea', 'uniswap', 'aave', 'compound', 
            'chainlink', 'solana', 'cardano', 'polkadot', 'avalanche', 
            'polygon'
        }
    
    def _init_common_tlds(self) -> List[str]:
        """Initialize common TLDs for TLD squatting detection."""
        return [
            'com', 'org', 'net', 'edu', 'gov', 'mil', 'int',  # Generic
            'co.uk', 'de', 'fr', 'jp', 'cn', 'ru', 'br',     # Country codes
            'io', 'ai', 'ly', 'me', 'tv', 'cc',              # Popular alternatives
            'biz', 'info', 'name', 'pro', 'mobi',            # Sponsored
            'app', 'dev', 'tech', 'online', 'site', 'store', # New generic
        ]
    
    def _init_homograph_chars(self) -> Dict[str, List[str]]:
        """Initialize homograph character mappings for visual similarity."""
        return {
            'a': ['а', 'α', 'à', 'á', 'â', 'ã', 'ä', 'å', 'æ'],
            'e': ['е', 'ε', 'è', 'é', 'ê', 'ë'],
            'i': ['і', 'ι', 'ì', 'í', 'î', 'ï'],
            'o': ['о', 'ο', 'ò', 'ó', 'ô', 'õ', 'ö', 'ø'],
            'u': ['υ', 'ù', 'ú', 'û', 'ü'],
            'c': ['с', 'ç'],
            'p': ['р', 'π'],
            'x': ['х', 'χ'],
            'y': ['у', 'ý', 'ÿ'],
            'n': ['ñ'],
            's': ['ѕ'],
            'h': ['һ']
        }
    
    async def analyze_domain(self, url: str, fetch_content: bool = True) -> DomainSquattingResult:
        """
        Perform comprehensive domain squatting analysis.
        
        Args:
            url: URL to analyze
            fetch_content: Whether to fetch and analyze page content
            
        Returns:
            DomainSquattingResult with complete analysis
        """
        domain = self._extract_domain(url)
        if not domain:
            return self._create_error_result(url, "Invalid domain format")
        
        # Detect squatting patterns
        squatting_matches = self._detect_squatting_patterns(domain)
        
        # Analyze content if requested and squatting detected
        content_analysis = None
        if fetch_content and squatting_matches:
            content_analysis = await self._analyze_content(url)
        
        # Calculate overall threat assessment
        threat_level, confidence_score, risk_factors = self._calculate_threat_level(
            squatting_matches, content_analysis
        )
        
        # Generate summary
        summary = self._generate_analysis_summary(
            domain, squatting_matches, content_analysis, threat_level
        )
        
        return DomainSquattingResult(
            domain=domain,
            is_squatting=len(squatting_matches) > 0,
            squatting_matches=squatting_matches,
            content_analysis=content_analysis,
            overall_threat_level=threat_level,
            confidence_score=confidence_score,
            risk_factors=risk_factors,
            analysis_summary=summary
        )
    
    def _detect_squatting_patterns(self, domain: str) -> List[SquattingMatch]:
        """Detect various types of domain squatting patterns."""
        matches = []
        domain_parts = domain.split('.')
        domain_name = domain_parts[0].lower()
        
        # Remove common prefixes for better matching
        clean_domain = re.sub(r'^(www\.|m\.|mobile\.)', '', domain_name)
        
        for legit_domain in self.legitimate_domains:
            # Skip exact matches (legitimate domains)
            if clean_domain == legit_domain:
                continue
            
            # Typosquatting detection
            typo_match = self._detect_typosquatting(clean_domain, legit_domain)
            if typo_match:
                matches.append(typo_match)
            
            # Combosquatting detection
            combo_match = self._detect_combosquatting(clean_domain, legit_domain)
            if combo_match:
                matches.append(combo_match)
            
            # Homograph detection
            homograph_match = self._detect_homograph(clean_domain, legit_domain)
            if homograph_match:
                matches.append(homograph_match)
            
            # Subdomain squatting
            subdomain_match = self._detect_subdomain_squatting(domain, legit_domain)
            if subdomain_match:
                matches.append(subdomain_match)
            
            # Hyphen squatting
            hyphen_match = self._detect_hyphen_squatting(clean_domain, legit_domain)
            if hyphen_match:
                matches.append(hyphen_match)
            
            # Plural squatting
            plural_match = self._detect_plural_squatting(clean_domain, legit_domain)
            if plural_match:
                matches.append(plural_match)
        
        # TLD squatting detection
        tld_matches = self._detect_tld_squatting(domain)
        matches.extend(tld_matches)
        
        # Keyword squatting
        keyword_matches = self._detect_keyword_squatting(clean_domain)
        matches.extend(keyword_matches)
        
        return matches
    
    def _detect_typosquatting(self, domain: str, target: str) -> Optional[SquattingMatch]:
        """Detect typosquatting using edit distance and common typos."""
        if len(domain) < 3 or abs(len(domain) - len(target)) > 3:
            return None
        
        edit_distance = self._calculate_edit_distance(domain, target)
        
        # Single character differences (most common typos)
        if edit_distance == 1:
            similarity = self._calculate_similarity(domain, target)
            
            if similarity > 0.7:
                confidence = 0.9
                threat_level = ThreatLevel.HIGH
            else:
                confidence = 0.7
                threat_level = ThreatLevel.MEDIUM
            
            return SquattingMatch(
                squatting_type=SquattingType.TYPOSQUATTING,
                target_domain=target,
                confidence=confidence,
                edit_distance=edit_distance,
                similarity_score=similarity,
                evidence=f"1-character difference from '{target}'",
                threat_level=threat_level
            )
        
        # Two character differences (also suspicious)
        elif edit_distance == 2 and len(domain) > 5:
            similarity = self._calculate_similarity(domain, target)
            
            if similarity > 0.6:
                return SquattingMatch(
                    squatting_type=SquattingType.TYPOSQUATTING,
                    target_domain=target,
                    confidence=0.6,
                    edit_distance=edit_distance,
                    similarity_score=similarity,
                    evidence=f"2-character difference from '{target}'",
                    threat_level=ThreatLevel.MEDIUM
                )
        
        return None
    
    def _detect_combosquatting(self, domain: str, target: str) -> Optional[SquattingMatch]:
        """Detect combosquatting (legitimate domain + additional keywords)."""
        if target not in domain or len(domain) - len(target) < 3:
            return None
        
        # Check if target domain appears in the squatting domain
        target_pos = domain.find(target)
        if target_pos != -1:
            prefix = domain[:target_pos]
            suffix = domain[target_pos + len(target):]
            
            # Common combosquatting keywords
            combo_keywords = [
                'secure', 'safe', 'official', 'login', 'auth', 'verify',
                'support', 'help', 'service', 'account', 'update',
                'new', 'app', 'mobile', 'beta', 'pro', 'plus',
                'mail', 'store', 'shop', 'pay', 'wallet'
            ]
            
            combined_part = prefix + suffix
            for keyword in combo_keywords:
                if keyword in combined_part.lower():
                    return SquattingMatch(
                        squatting_type=SquattingType.COMBOSQUATTING,
                        target_domain=target,
                        confidence=0.8,
                        edit_distance=len(combined_part),
                        similarity_score=len(target) / len(domain),
                        evidence=f"Contains '{target}' + '{keyword}'",
                        threat_level=ThreatLevel.HIGH
                    )
        
        return None
    
    def _detect_homograph(self, domain: str, target: str) -> Optional[SquattingMatch]:
        """Detect homograph attacks using visually similar characters."""
        if len(domain) != len(target):
            return None
        
        homograph_count = 0
        for i, char in enumerate(domain):
            if i < len(target):
                target_char = target[i].lower()
                if char != target_char:
                    # Check if it's a homograph substitution
                    if target_char in self.homograph_chars:
                        if char in self.homograph_chars[target_char]:
                            homograph_count += 1
                        else:
                            # Not a homograph substitution
                            return None
                    else:
                        return None
        
        if homograph_count > 0:
            confidence = min(0.95, 0.7 + (homograph_count * 0.1))
            return SquattingMatch(
                squatting_type=SquattingType.HOMOGRAPH,
                target_domain=target,
                confidence=confidence,
                edit_distance=homograph_count,
                similarity_score=1.0 - (homograph_count / len(domain)),
                evidence=f"{homograph_count} homograph character substitutions",
                threat_level=ThreatLevel.CRITICAL
            )
        
        return None
    
    def _detect_subdomain_squatting(self, full_domain: str, target: str) -> Optional[SquattingMatch]:
        """Detect subdomain squatting patterns."""
        parts = full_domain.split('.')
        if len(parts) < 3:
            return None
        
        # Check if target appears as a subdomain
        for i, part in enumerate(parts[:-2]):  # Exclude main domain and TLD
            if part.lower() == target:
                return SquattingMatch(
                    squatting_type=SquattingType.SUBDOMAIN_SQUATTING,
                    target_domain=target,
                    confidence=0.7,
                    edit_distance=0,
                    similarity_score=1.0,
                    evidence=f"'{target}' used as subdomain",
                    threat_level=ThreatLevel.MEDIUM
                )
        
        return None
    
    def _detect_hyphen_squatting(self, domain: str, target: str) -> Optional[SquattingMatch]:
        """Detect hyphenated variations of legitimate domains."""
        if '-' not in domain:
            return None
        
        # Remove hyphens and compare
        dehyphenated = domain.replace('-', '')
        if dehyphenated == target:
            return SquattingMatch(
                squatting_type=SquattingType.HYPHEN_SQUATTING,
                target_domain=target,
                confidence=0.8,
                edit_distance=domain.count('-'),
                similarity_score=0.9,
                evidence=f"Hyphenated version of '{target}'",
                threat_level=ThreatLevel.MEDIUM
            )
        
        return None
    
    def _detect_plural_squatting(self, domain: str, target: str) -> Optional[SquattingMatch]:
        """Detect plural/singular variations."""
        # Check if domain is plural of target
        if domain == target + 's' or domain == target + 'es':
            return SquattingMatch(
                squatting_type=SquattingType.PLURAL_SQUATTING,
                target_domain=target,
                confidence=0.6,
                edit_distance=len(domain) - len(target),
                similarity_score=0.85,
                evidence=f"Plural form of '{target}'",
                threat_level=ThreatLevel.LOW
            )
        
        # Check if target is plural of domain
        if (target.endswith('s') and domain == target[:-1]) or \
           (target.endswith('es') and domain == target[:-2]):
            return SquattingMatch(
                squatting_type=SquattingType.PLURAL_SQUATTING,
                target_domain=target,
                confidence=0.6,
                edit_distance=len(target) - len(domain),
                similarity_score=0.85,
                evidence=f"Singular form of '{target}'",
                threat_level=ThreatLevel.LOW
            )
        
        return None
    
    def _detect_tld_squatting(self, full_domain: str) -> List[SquattingMatch]:
        """Detect TLD squatting (same domain, different TLD)."""
        matches = []
        parts = full_domain.split('.')
        
        if len(parts) < 2:
            return matches
        
        domain_name = parts[0].lower()
        current_tld = '.'.join(parts[1:]).lower()
        
        # Check if domain name matches any legitimate domain
        if domain_name in self.legitimate_domains:
            # Check if it's using a different TLD
            common_tlds = ['com', 'org', 'net']
            if current_tld not in common_tlds:
                matches.append(SquattingMatch(
                    squatting_type=SquattingType.TLD_SQUATTING,
                    target_domain=domain_name,
                    confidence=0.7,
                    edit_distance=0,
                    similarity_score=1.0,
                    evidence=f"'{domain_name}' with non-standard TLD '.{current_tld}'",
                    threat_level=ThreatLevel.MEDIUM
                ))
        
        return matches
    
    def _detect_keyword_squatting(self, domain: str) -> List[SquattingMatch]:
        """Detect domains using brand keywords in suspicious ways."""
        matches = []
        
        # High-value keywords that are often squatted
        valuable_keywords = [
            'bank', 'pay', 'wallet', 'crypto', 'bitcoin', 'secure',
            'login', 'account', 'verify', 'auth', 'official',
            'support', 'help', 'service', 'update'
        ]
        
        for keyword in valuable_keywords:
            if keyword in domain.lower():
                # Check if it's combined with brand indicators
                brand_indicators = ['app', 'official', 'secure', 'new', 'mobile']
                for indicator in brand_indicators:
                    if indicator in domain.lower() and indicator != keyword:
                        matches.append(SquattingMatch(
                            squatting_type=SquattingType.KEYWORD_SQUATTING,
                            target_domain=keyword,
                            confidence=0.5,
                            edit_distance=0,
                            similarity_score=0.6,
                            evidence=f"Suspicious use of '{keyword}' keyword",
                            threat_level=ThreatLevel.MEDIUM
                        ))
                        break
        
        return matches
    
    async def _analyze_content(self, url: str) -> Optional[ContentAnalysis]:
        """Analyze domain content for malicious intent."""
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=15)
            ) as session:
                headers = {'User-Agent': self.user_agent}
                
                async with session.get(url, headers=headers) as response:
                    if response.status != 200:
                        return ContentAnalysis(
                            has_content=False,
                            content_similarity=0.0,
                            phishing_indicators=[],
                            social_engineering_detected=False,
                            malicious_content_detected=False,
                            legitimate_business=False,
                            parked_domain=False,
                            error_page=True,
                            content_summary=f"HTTP {response.status} error"
                        )
                    
                    content = await response.text()
                    return self._analyze_page_content(content, url)
        
        except Exception as e:
            return ContentAnalysis(
                has_content=False,
                content_similarity=0.0,
                phishing_indicators=[],
                social_engineering_detected=False,
                malicious_content_detected=False,
                legitimate_business=False,
                parked_domain=False,
                error_page=True,
                content_summary=f"Failed to fetch content: {str(e)}"
            )
    
    def _analyze_page_content(self, content: str, url: str) -> ContentAnalysis:
        """Analyze page content for malicious patterns."""
        soup = BeautifulSoup(content, 'html.parser')
        text_content = soup.get_text().lower()
        
        # Check for parked domain indicators
        parked_indicators = [
            'this domain is for sale', 'domain parking', 'parked domain',
            'buy this domain', 'domain available', 'coming soon'
        ]
        is_parked = any(indicator in text_content for indicator in parked_indicators)
        
        # Check for phishing indicators
        phishing_patterns = [
            'verify your account', 'update your payment', 'click here immediately',
            'account suspended', 'login required', 'security alert',
            'unusual activity', 'confirm your identity', 'expires today'
        ]
        phishing_indicators = [p for p in phishing_patterns if p in text_content]
        
        # Social engineering detection
        social_eng_patterns = [
            'urgent action required', 'act now', 'limited time',
            'congratulations', 'you have won', 'claim your prize',
            'customer service', 'support team', 'security department'
        ]
        social_eng_detected = any(pattern in text_content for pattern in social_eng_patterns)
        
        # Check for malicious content patterns
        malicious_patterns = [
            'download', 'install', 'update required', 'plugin missing',
            'codec needed', 'flash player', 'java update'
        ]
        malicious_detected = len([p for p in malicious_patterns if p in text_content]) >= 2
        
        # Check for legitimate business indicators
        business_indicators = [
            'privacy policy', 'terms of service', 'contact us',
            'about us', 'customer support', 'refund policy'
        ]
        legitimate_score = sum(1 for indicator in business_indicators if indicator in text_content)
        is_legitimate = legitimate_score >= 3
        
        # Calculate content similarity (simplified)
        content_similarity = self._calculate_content_similarity(content, url)
        
        # Generate content summary
        if is_parked:
            summary = "Domain appears to be parked or for sale"
        elif phishing_indicators:
            summary = f"Phishing indicators detected: {', '.join(phishing_indicators[:3])}"
        elif social_eng_detected:
            summary = "Social engineering tactics detected"
        elif malicious_detected:
            summary = "Potentially malicious download prompts detected"
        elif is_legitimate:
            summary = "Appears to be legitimate business website"
        else:
            summary = "Content analysis inconclusive"
        
        return ContentAnalysis(
            has_content=len(text_content.strip()) > 100,
            content_similarity=content_similarity,
            phishing_indicators=phishing_indicators,
            social_engineering_detected=social_eng_detected,
            malicious_content_detected=malicious_detected,
            legitimate_business=is_legitimate,
            parked_domain=is_parked,
            error_page=False,
            content_summary=summary
        )
    
    def _calculate_content_similarity(self, content: str, url: str) -> float:
        """Calculate similarity to target domain content (simplified implementation)."""
        # This is a placeholder for more sophisticated content similarity analysis
        # In a production system, you might compare against known legitimate site content
        return 0.0
    
    def _calculate_threat_level(
        self, 
        matches: List[SquattingMatch], 
        content: Optional[ContentAnalysis]
    ) -> Tuple[ThreatLevel, float, List[str]]:
        """Calculate overall threat level and confidence."""
        if not matches:
            return ThreatLevel.LOW, 0.0, []
        
        # Calculate threat score based on matches
        threat_score = 0.0
        risk_factors = []
        
        for match in matches:
            # Weight different squatting types
            type_weights = {
                SquattingType.HOMOGRAPH: 0.9,
                SquattingType.TYPOSQUATTING: 0.8,
                SquattingType.COMBOSQUATTING: 0.7,
                SquattingType.SUBDOMAIN_SQUATTING: 0.5,
                SquattingType.TLD_SQUATTING: 0.6,
                SquattingType.HYPHEN_SQUATTING: 0.4,
                SquattingType.PLURAL_SQUATTING: 0.3,
                SquattingType.KEYWORD_SQUATTING: 0.4
            }
            
            weight = type_weights.get(match.squatting_type, 0.3)
            threat_score += match.confidence * weight * 100
            
            risk_factors.append(f"{match.squatting_type.value}_detected")
        
        # Factor in content analysis
        if content:
            if content.malicious_content_detected:
                threat_score += 30
                risk_factors.append("malicious_content")
            
            if content.phishing_indicators:
                threat_score += 25
                risk_factors.append("phishing_indicators")
            
            if content.social_engineering_detected:
                threat_score += 20
                risk_factors.append("social_engineering")
           

            if content.parked_domain:
                threat_score += 10
                risk_factors.append("parked_domain")
            
            if content.legitimate_business:
                threat_score = max(0, threat_score - 15)
                risk_factors.append("legitimate_indicators")
        
        # Normalize threat score
        threat_score = min(threat_score, 100)
        
        # Determine threat level
        if threat_score >= 80:
            threat_level = ThreatLevel.CRITICAL
        elif threat_score >= 60:
            threat_level = ThreatLevel.HIGH
        elif threat_score >= 30:
            threat_level = ThreatLevel.MEDIUM
        else:
            threat_level = ThreatLevel.LOW
        
        # Calculate overall confidence
        confidence = sum(match.confidence for match in matches) / len(matches) if matches else 0.0
        
        return threat_level, confidence, risk_factors
    
    def _generate_analysis_summary(
        self,
        domain: str,
        matches: List[SquattingMatch],
        content: Optional[ContentAnalysis],
        threat_level: ThreatLevel
    ) -> str:
        """Generate human-readable analysis summary."""
        if not matches:
            return f"No squatting patterns detected for '{domain}'"
        
        # Group matches by type
        type_counts = {}
        for match in matches:
            type_name = match.squatting_type.value.replace('_', ' ').title()
            type_counts[type_name] = type_counts.get(type_name, 0) + 1
        
        # Build summary
        summary_parts = []
        for type_name, count in type_counts.items():
            if count == 1:
                summary_parts.append(f"{type_name}")
            else:
                summary_parts.append(f"{count}x {type_name}")
        
        summary = f"Detected {', '.join(summary_parts)} targeting "
        
        # List targeted domains
        targets = list(set(match.target_domain for match in matches))
        if len(targets) == 1:
            summary += f"'{targets[0]}'"
        else:
            summary += f"multiple brands ({', '.join(targets[:3])}{'...' if len(targets) > 3 else ''})"
        
        # Add content analysis findings
        if content:
            if content.malicious_content_detected:
                summary += ". Malicious content detected"
            elif content.phishing_indicators:
                summary += ". Phishing indicators present"
            elif content.parked_domain:
                summary += ". Domain appears parked"
            elif content.legitimate_business:
                summary += ". Some legitimate business indicators found"
        
        summary += f". Overall threat level: {threat_level.value.upper()}"
        
        return summary
    
    def _extract_domain(self, url: str) -> Optional[str]:
        """Extract domain from URL."""
        try:
            parsed = urlparse(url if url.startswith(('http://', 'https://')) else f'http://{url}')
            return parsed.netloc.lower() if parsed.netloc else None
        except Exception:
            return None
    
    def _calculate_edit_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein edit distance between two strings."""
        if len(s1) < len(s2):
            return self._calculate_edit_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _calculate_similarity(self, s1: str, s2: str) -> float:
        """Calculate similarity score between two strings using difflib."""
        return difflib.SequenceMatcher(None, s1.lower(), s2.lower()).ratio()
    
    def _create_error_result(self, url: str, error: str) -> DomainSquattingResult:
        """Create error result for invalid input."""
        return DomainSquattingResult(
            domain=url,
            is_squatting=False,
            squatting_matches=[],
            content_analysis=None,
            overall_threat_level=ThreatLevel.LOW,
            confidence_score=0.0,
            risk_factors=["invalid_input"],
            analysis_summary=f"Error: {error}"
        )


async def main():
    """Example usage of the DomainSquattingAnalyzer."""
    analyzer = DomainSquattingAnalyzer()
    
    # Test with various suspicious domains
    test_domains = [
        "gooogle.com",          # Typosquatting
        "facebook-login.com",   # Combosquatting
        "gοοgle.com",           # Homograph (using Greek letters)
        "paypal.secure.com",    # Subdomain squatting
        "amazon.net",           # TLD squatting
        "apples.com",           # Plural squatting
        "secure-bank.com",      # Keyword squatting
        "legitimate-domain.com" # Clean domain
    ]
    
    print("Domain Squatting Analysis Results")
    print("=" * 50)
    
    for domain in test_domains:
        print(f"\nAnalyzing: {domain}")
        result = await analyzer.analyze_domain(domain, fetch_content=False)
        
        print(f"Squatting detected: {result.is_squatting}")
        print(f"Threat level: {result.overall_threat_level.value.upper()}")
        print(f"Confidence: {result.confidence_score:.2f}")
        print(f"Summary: {result.analysis_summary}")
        
        if result.squatting_matches:
            print("Detected patterns:")
            for match in result.squatting_matches:
                print(f"  - {match.squatting_type.value}: {match.evidence} "
                      f"(confidence: {match.confidence:.2f})")


if __name__ == "__main__":
    asyncio.run(main())
