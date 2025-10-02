#!/usr/bin/env python3
"""
LinkShield Backend URL Analysis Service

Comprehensive URL analysis service for security scanning, threat detection,
and reputation checking using multiple security providers and AI analysis.
"""

import asyncio
import hashlib
import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Tuple
from urllib.parse import urlparse, urljoin

from typing import Dict, Any, List, Optional, Tuple

from dataclasses import dataclass



import aiohttp
import requests
from bs4 import BeautifulSoup

from src.config.settings import get_settings
from src.models.url_check import ThreatLevel, ScanType, URLReputation
from src.models.analysis_results import (
    AnalysisResults, ProviderScanResult, ProviderMetadata, ReputationUpdate,
    BrokenLinkScanResult, BrokenLinkDetail, BrokenLinkStatus
)
from src.services.ai_service import AIService
from src.services.security_service import SecurityService
from src.services.analyzers.pattern_analyzer import SuspiciousPatternAnalyzer
from src.services.analyzers.shotener_analyzer import URLShortenerAnalyzer
from src.services.analyzers.broken_link_scanner import BrokenLinkScanner


class URLAnalysisError(Exception):
    """
    Base URL analysis error.
    """
    pass


class InvalidURLError(URLAnalysisError):
    """
    Invalid URL error.
    """
    pass


class ScanTimeoutError(URLAnalysisError):
    """
    Scan timeout error.
    """
    pass



class URLAnalysisService:
    """
    URL analysis service for comprehensive security scanning.
    """
    
    def __init__(self, ai_service: AIService, security_service: SecurityService):
        """
        Initialize URLAnalysisService with pure business logic dependencies.
        
        Args:
            ai_service: AI analysis service for content analysis
            security_service: Security service for additional security checks
        """
        self.ai_service = ai_service
        self.security_service = security_service
        self.settings = get_settings()
        
        # Security provider configurations
        self.providers = {
            "virustotal": {
                "enabled": bool(self.settings.VIRUSTOTAL_API_KEY),
                "api_key": self.settings.VIRUSTOTAL_API_KEY,
                "base_url": "https://www.virustotal.com/vtapi/v2",
                "rate_limit": 4  # requests per minute
            },
            "safebrowsing": {
                "enabled": bool(self.settings.GOOGLE_SAFE_BROWSING_API_KEY),
                "api_key": self.settings.GOOGLE_SAFE_BROWSING_API_KEY,
                "base_url": "https://safebrowsing.googleapis.com/v4",
                "rate_limit": 10000  # requests per day
            },
            "urlvoid": {
                "enabled": bool(self.settings.URLVOID_API_KEY),
                "api_key": self.settings.URLVOID_API_KEY,
                "base_url": "https://api.urlvoid.com/v1",
                "rate_limit": 1000  # requests per month
            }
        }
        
        # Analysis configuration
        self.scan_timeout = 30  # seconds
        self.max_redirects = 10
        self.user_agent = "LinkShield-Bot/1.0 (+https://linkshield.site/bot)"
        # === TYPOSQUATTING DETECTION ===
        # Check against common legitimate domains (extensive list)
        self.legitimate_domains = {
            # Tech & Social Media Giants
            'google', 'facebook', 'microsoft', 'apple', 'amazon',
            'twitter', 'instagram', 'linkedin', 'github', 'stackoverflow', 'paypal', 'whatsapp',
            'stripe', 'youtube', 'tiktok', 'snapchat', 'pinterest', 'reddit', 'discord',
            'telegram', 'signal', 'slack', 'zoom', 'skype', 'twitch', 'spotify',
            
            # E-commerce & Retail
            'ebay', 'etsy', 'shopify', 'walmart', 'target', 'bestbuy', 'aliexpress',
            'alibaba', 'wish', 'overstock', 'wayfair', 'homedepot', 'lowes', 'costco',
            'sears', 'macys', 'nordstrom', 'zappos', 'asos', 'newegg', 'groupon',
            
            # Financial & Banking
            'chase', 'bankofamerica', 'wellsfargo', 'citibank', 'capitalone',
            'americanexpress', 'visa', 'mastercard', 'discover', 'schwab', 'fidelity',
            'vanguard', 'morganstanley', 'goldmansachs', 'jpmorgan', 'square', 'coinbase',
            'binance', 'kraken', 'robinhood', 'sofi', 'transferwise', 'westernunion',
            
            # Cloud & Infrastructure
            'aws', 'azure', 'cloudflare', 'digitalocean', 'linode', 'heroku',
            'oracle', 'ibm', 'salesforce', 'servicenow', 'workday', 'sap',
            
            # Email Providers
            'gmail', 'outlook', 'yahoo', 'protonmail', 'aol', 'icloud', 'zoho',
            'mail', 'yandex', 'gmx',
            
            # Government & Education
            'irs', 'ssa', 'usps', 'ups', 'fedex', 'dhl', 'state', 'whitehouse',
            'harvard', 'stanford', 'mit', 'cambridge', 'oxford', 'coursera', 'edx',
            'udemy', 'khanacademy',
            
            # Media & News
            'cnn', 'foxnews', 'bbc', 'reuters', 'ap', 'bloomberg', 'wsj',
            'nytimes', 'washingtonpost', 'theguardian', 'huffpost', 'buzzfeed',
            'netflix', 'hulu', 'disneyplus', 'hbo', 'paramount', 'peacock',
            
            # Gaming
            'steam', 'epicgames', 'xbox', 'playstation', 'nintendo', 'ea',
            'activision', 'ubisoft', 'blizzard', 'riotgames', 'minecraft',
            'roblox', 'fortnite',
            
            # Travel & Hospitality
            'expedia', 'booking', 'airbnb', 'vrbo', 'tripadvisor', 'kayak',
            'priceline', 'hotels', 'marriott', 'hilton', 'hyatt', 'delta',
            'united', 'americanairlines', 'southwest', 'airbnb',
            
            # Automotive
            'tesla', 'ford', 'gm', 'toyota', 'honda', 'bmw', 'mercedesbenz',
            'audi', 'volkswagen', 'nissan', 'hyundai',
            
            # Food & Delivery
            'ubereats', 'doordash', 'grubhub', 'postmates', 'deliveroo',
            'mcdonalds', 'starbucks', 'subway', 'pizzahut', 'dominos',
            'chipotle', 'kfc', 'burgerking', 'wendys',
            
            # Health & Fitness
            'webmd', 'mayoclinic', 'cvs', 'walgreens', 'goodrx', 'fitbit',
            'myfitnesspal', 'strava', 'peloton', 'calm', 'headspace',
            
            # Regional & Country-specific
            'baidu', 'taobao', 'qq', 'weibo', 'wechat', 'alipay', 'rakuten',
            'yandex', 'mailru', 'sberbank', 'deezer', 'orange', 'vodafone',
            
            # Additional Major Platforms
            'dropbox', 'box', 'evernote', 'adobe', 'autodesk', 'intel', 'amd',
            'nvidia', 'qualcomm', 'cisco', 'dell', 'hp', 'lenovo', 'logitech',
            'godaddy', 'namecheap', 'wordpress', 'wix', 'squarespace',
            
            # Crypto & Web3
            'metamask', 'opensea', 'uniswap', 'aave', 'compound', 'chainlink',
            'solana', 'cardano', 'polkadot', 'avalanche', 'polygon'
        }        
 
        
    
    async def quick_security_analysis_by_url(self, url: str):
        """
            This will run a url_analyses with quick settings 
            to be used for social media quick analysis
        """
        # We could interact over this settings until we fing one that is fast enough
        return await self.analyze_url(url=url, scan_types=[ScanType.SECURITY], scan_depth=1, max_links=50)

    async def quick_content_analysis_by_url(self, url: str):
        """
            This will launch a quick content only analysis from the provided url
        """
        return await self.analyze_url(url=url, scan_types=[ScanType.CONTENT], scan_depth=1, max_links=50)



    async def analyze_url(
        self, 
        url: str, 
        scan_types: Optional[List[ScanType]] = None,
        reputation_data: Optional[URLReputation] = None,
        scan_depth: int = 2,
        max_links: int = 100
    ) -> AnalysisResults:
        """
        Perform comprehensive URL analysis and return typed results.
        
        Args:
            url: URL to analyze
            scan_types: Specific scan types to perform
            reputation_data: Historical reputation data for analysis
            scan_depth: Depth for broken link scanning (default: 2)
            max_links: Maximum links to check for broken link scanning (default: 100)
        
        Returns:
            AnalysisResults containing analysis results with threat level and confidence score
        """
        # Validate and normalize URL
        normalized_url: str = self._normalize_url(url)
        if not normalized_url:
            raise InvalidURLError(f"Invalid URL format: {url}")
        
        # Perform comprehensive analysis
        analysis_results = await self._perform_comprehensive_analysis(
            normalized_url, 
            scan_types or ScanType.scan_types(),
            scan_depth=scan_depth,
            max_links=max_links
        )
        
        # Include reputation analysis if data provided
        if reputation_data:
            reputation_analysis = self._analyze_reputation(normalized_url, reputation_data)
            analysis_results.update(reputation_analysis)
        
        # Calculate threat level and confidence score
        threat_level, confidence_score = self._calculate_threat_level(analysis_results)
        
        # Convert legacy analysis results to typed results
        scan_results = []
        scan_types_list = scan_types or ScanType.scan_types()
        
        # Extract broken link scan result if present
        broken_link_scan = None
        if "broken_link_scan" in analysis_results:
            broken_link_scan = analysis_results.pop("broken_link_scan")
        
        # Convert provider results to ProviderScanResult objects
        for provider_name, provider_data in analysis_results.items():
            if isinstance(provider_data, dict) and "provider" in provider_data:
                scan_results.append(ProviderScanResult.from_dict(provider_data))
        
        # Create and return typed AnalysisResults
        return AnalysisResults(
            normalized_url=normalized_url,
            domain=self._extract_domain(normalized_url),
            threat_level=threat_level.value if threat_level else None,
            confidence_score=confidence_score,
            scan_results=scan_results,
            scan_types=[scan_type.value for scan_type in scan_types_list],
            broken_link_scan=broken_link_scan
        )
    
    async def _perform_comprehensive_analysis(self, url: str, scan_types: List[ScanType], scan_depth: int = 2, max_links: int = 100) -> Dict[str, Any]:
        """
        Perform comprehensive analysis using multiple providers.
        
        Args:
            url: URL to analyze
            scan_types: List of scan types to perform
            scan_depth: Depth for broken link scanning
            max_links: Maximum links to check for broken link scanning
        """
        results = {}
        
        # Create analysis tasks
        tasks = []
        
        if ScanType.SECURITY in scan_types:
            tasks.extend([
                self._scan_virustotal(url),
                self._scan_safe_browsing(url),
                self._scan_urlvoid(url)])
        
        if ScanType.REPUTATION in scan_types:
            tasks.append(self._analyze_reputation(url))
        
        if ScanType.CONTENT in scan_types:
            tasks.append(self._analyze_content(url))
        
        if ScanType.TECHNICAL in scan_types:
            tasks.append(self._analyze_technical(url))
        
        if ScanType.BROKEN_LINKS in scan_types:
            tasks.append(self._scan_broken_links_wrapper(url, scan_depth, max_links))
        
        # Execute tasks with timeout
        try:
            task_results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=self.scan_timeout
            )
            
            # Process results
            for i, result in enumerate(task_results):
                if isinstance(result, Exception):
                    continue
                
                if result:
                    results.update(result)
            
        except asyncio.TimeoutError:
            raise ScanTimeoutError("Analysis timed out")
        
        return results
    
    async def _scan_virustotal(self, url: str) -> Dict[str, Any]:
        """
        Scan URL using VirusTotal API.
        Returns dictionary for compatibility with _perform_comprehensive_analysis.
        """
        if not self.providers["virustotal"]["enabled"]:
            return {}
        
        try:
            async with aiohttp.ClientSession() as session:
                # Submit URL for scanning
                submit_url = f"{self.providers['virustotal']['base_url']}/url/scan"
                submit_data = {
                    "apikey": self.providers["virustotal"]["api_key"],
                    "url": url
                }
                
                async with session.post(submit_url, data=submit_data) as response:
                    if response.status != 200:
                        return {}
                    
                    submit_result = await response.json()
                    scan_id = submit_result.get("scan_id")
                
                # Wait a bit for scan to complete
                await asyncio.sleep(2)
                
                # Get scan report
                report_url = f"{self.providers['virustotal']['base_url']}/url/report"
                report_params = {
                    "apikey": self.providers["virustotal"]["api_key"],
                    "resource": scan_id
                }
                
                async with session.get(report_url, params=report_params) as response:
                    if response.status != 200:
                        return {}
                    
                    report = await response.json()
                    
                    # Process VirusTotal results
                    positives = report.get("positives", 0)
                    total = report.get("total", 0)
                    
                    threat_detected = positives > 0
                    confidence_score = (positives / total * 100) if total > 0 else 0
                    
                    threat_types = []
                    if threat_detected:
                        scans = report.get("scans", {})
                        for engine, result in scans.items():
                            if result.get("detected"):
                                threat_type = result.get("result", "malware")
                                if threat_type not in threat_types:
                                    threat_types.append(threat_type)
                    
                    # Create ProviderScanResult
                    metadata = ProviderMetadata(
                        positives=positives,
                        total=total,
                        scan_date=report.get("scan_date")
                    )
                    
                    scan_result = ProviderScanResult(
                        provider="virustotal",
                        threat_detected=threat_detected,
                        threat_types=threat_types,
                        confidence_score=confidence_score,
                        raw_response=report,
                        metadata=metadata
                    )
                    
                    return {
                        "virustotal": scan_result.to_dict()
                    }
        
        except Exception as e:
            scan_result = ProviderScanResult(
                provider="virustotal",
                threat_detected=False,
                error=str(e)
            )
            return {
                "virustotal": scan_result.to_dict()
            }
    
    async def _scan_safe_browsing(self, url: str) -> Dict[str, Any]:
        """
        Scan URL using Google Safe Browsing API.
        Returns dictionary for compatibility with _perform_comprehensive_analysis.
        """
        if not self.providers["safebrowsing"]["enabled"]:
            return {}
        
        try:
            async with aiohttp.ClientSession() as session:
                api_url = f"{self.providers['safebrowsing']['base_url']}/threatMatches:find"
                
                payload = {
                    "client": {
                        "clientId": "linkshield",
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
                
                params = {"key": self.providers["safebrowsing"]["api_key"]}
                
                async with session.post(api_url, json=payload, params=params) as response:
                    if response.status != 200:
                        return {}
                    
                    result = await response.json()
                    
                    threat_matches = result.get("matches", [])
                    threat_detected = len(threat_matches) > 0
                    
                    threat_types = []
                    if threat_detected:
                        for match in threat_matches:
                            threat_type = match.get("threatType", "unknown")
                            if threat_type not in threat_types:
                                threat_types.append(threat_type.lower())
                    
                    confidence_score = 95 if threat_detected else 0
                    
                    # Create ProviderScanResult
                    metadata = ProviderMetadata(matches_count=len(threat_matches))
                    
                    scan_result = ProviderScanResult(
                        provider="safebrowsing",
                        threat_detected=threat_detected,
                        threat_types=threat_types,
                        confidence_score=confidence_score,
                        raw_response=result,
                        metadata=metadata
                    )
                    
                    return {
                        "safebrowsing": scan_result.to_dict()
                    }
        
        except Exception as e:
            scan_result = ProviderScanResult(
                provider="safebrowsing",
                threat_detected=False,
                error=str(e)
            )
            return {
                "safebrowsing": scan_result.to_dict()
            }
    
    async def _scan_urlvoid(self, url: str) -> Dict[str, Any]:
        """
        Scan URL using URLVoid API.
        Returns dictionary for compatibility with _perform_comprehensive_analysis.
        """
        if not self.providers["urlvoid"]["enabled"]:
            return {}
        
        try:
            domain = self._extract_domain(url)
            
            async with aiohttp.ClientSession() as session:
                api_url = f"{self.providers['urlvoid']['base_url']}/pay-as-you-go/"
                
                params = {
                    "key": self.providers["urlvoid"]["api_key"],
                    "host": domain
                }
                
                async with session.get(api_url, params=params) as response:
                    if response.status != 200:
                        return {}
                    
                    result = await response.json()
                    
                    detections = result.get("detections", 0)
                    engines_count = result.get("engines_count", 0)
                    
                    threat_detected = detections > 0
                    confidence_score = (detections / engines_count * 100) if engines_count > 0 else 0
                    
                    threat_types = []
                    if threat_detected:
                        threat_types = ["suspicious", "malware"]
                    
                    # Create ProviderScanResult
                    metadata = ProviderMetadata(
                        detections=detections,
                        engines_count=engines_count
                    )
                    
                    scan_result = ProviderScanResult(
                        provider="urlvoid",
                        threat_detected=threat_detected,
                        threat_types=threat_types,
                        confidence_score=confidence_score,
                        raw_response=result,
                        metadata=metadata
                    )
                    
                    return {
                        "urlvoid": scan_result.to_dict()
                    }
        
        except Exception as e:
            scan_result = ProviderScanResult(
                provider="urlvoid",
                threat_detected=False,
                error=str(e)
            )
            return {
                "urlvoid": scan_result.to_dict()
            }
    
    def _analyze_reputation(self, url: str, reputation_data: Optional[URLReputation] = None) -> Dict[str, Any]:
        """
        Analyze URL reputation based on provided historical data.
        
        Args:
            url: URL to analyze
            reputation_data: Historical reputation data from database
        
        Returns:
            Dictionary containing reputation analysis results
        """
        domain = self._extract_domain(url)
        
        if reputation_data:
            # Calculate reputation score based on historical data
            total_checks = reputation_data.get("total_checks", 0)
            malicious_checks = reputation_data.get("malicious_count", 0)
            
            reputation_score = 100 - (malicious_checks / total_checks * 100) if total_checks > 0 else 50
            
            threat_detected = reputation_score < 70
            confidence_score = min(total_checks * 2, 100)  # More checks = higher confidence

            # Create ProviderScanResult for reputation analysis
            metadata = ProviderMetadata(
                reputation_score=reputation_score,
                total_checks=total_checks,
                malicious_checks=malicious_checks,
                first_seen=reputation_data.get("first_seen"),
                last_seen=reputation_data.get("last_seen")
            )
            
            scan_result = ProviderScanResult(
                provider="internal",
                threat_detected=threat_detected,
                threat_types=["low_reputation"] if threat_detected else [],
                confidence_score=confidence_score,
                metadata=metadata
            )
            
            return {
                "reputation": scan_result.to_dict()
            }
        
        # Create ProviderScanResult for neutral reputation
        metadata = ProviderMetadata(
            reputation_score=50,  # Neutral for new domains
            total_checks=0,
            malicious_checks=0
        )
        
        scan_result = ProviderScanResult(
            provider="internal",
            threat_detected=False,
            threat_types=[],
            confidence_score=0,
            metadata=metadata
        )
        
        return {
            "reputation": scan_result.to_dict()
        }
    
    async def _analyze_content(self, url: str) -> Dict[str, Any]:
        """
        Analyze URL content using AI and pattern matching.
        Returns dictionary for compatibility with _perform_comprehensive_analysis.
        """
        try:
            # Fetch page content
            async with aiohttp.ClientSession() as session:
                headers = {"User-Agent": self.user_agent}
                
                async with session.get(url, headers=headers, timeout=10) as response:
                    if response.status != 200:
                        return {}
                    
                    content = await response.text()
                    
                    # Use AI service for content analysis
                    ai_analysis = await self.ai_service.analyze_content(content, url)
                    
                    # Pattern-based analysis
                    suspicious_patterns = self._detect_suspicious_patterns(content)
                    
                    # Combine results
                    threat_detected = ai_analysis.get("threat_detected", False) or len(suspicious_patterns) > 0
                    
                    threat_types = ai_analysis.get("threat_types", [])
                    if suspicious_patterns:
                        threat_types.extend(["suspicious_content", "phishing_patterns"])
                    
                    confidence_score = max(
                        ai_analysis.get("confidence_score", 0),
                        len(suspicious_patterns) * 20
                    )
                    
                    # Create ProviderScanResult
                    metadata = ProviderMetadata(
                        ai_analysis=ai_analysis,
                        suspicious_patterns=suspicious_patterns,
                        content_length=len(content)
                    )
                    
                    scan_result = ProviderScanResult(
                        provider="internal",
                        threat_detected=threat_detected,
                        threat_types=list(set(threat_types)),
                        confidence_score=min(confidence_score, 100),
                        metadata=metadata
                    )
                    
                    return {
                        "content": scan_result.to_dict()
                    }
        
        except Exception as e:
            scan_result = ProviderScanResult(
                provider="internal",
                threat_detected=False,
                error=str(e)
            )
            return {
                "content": scan_result.to_dict()
            }
    
    async def _analyze_technical(self, url: str) -> Dict[str, Any]:
        """
        Perform exhaustive technical analysis of URL structure and hosting for security assessment.
        Returns dictionary for compatibility with _perform_comprehensive_analysis.
        """
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            path = parsed_url.path
            query = parsed_url.query
            fragment = parsed_url.fragment
            
            suspicious_indicators = []
            security_issues = []
            risk_factors = []
            
            # === PROTOCOL SECURITY ANALYSIS ===
            if parsed_url.scheme == 'http':
                security_issues.append("insecure_protocol")
                risk_factors.append("no_encryption")
            elif parsed_url.scheme != 'https':
                security_issues.append("non_standard_protocol")
            
            # === DOMAIN ANALYSIS ===
            domain_parts = domain.split('.')
            
            # IP address detection (more comprehensive)
            ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
            ipv6_pattern = r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^\[(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\]$'
            
            if re.match(ipv4_pattern, domain) or re.match(ipv6_pattern, domain):
                suspicious_indicators.append("ip_address_host")
                risk_factors.append("direct_ip_access")
            
            # Subdomain analysis
            subdomain_count = len(domain_parts) - 2 if len(domain_parts) > 2 else 0
            if subdomain_count > 3:
                suspicious_indicators.append("excessive_subdomains")
            if subdomain_count > 5:
                security_issues.append("deeply_nested_subdomains")
            
            # Domain length and randomness analysis
            if len(domain) > 50:
                suspicious_indicators.append("unusually_long_domain")
            
            # Check for random character patterns in domain
            for part in domain_parts:
                if len(part) > 15 and re.search(r'^[a-z0-9]{15,}$', part):
                    consonant_ratio = len(re.findall(r'[bcdfghjklmnpqrstvwxz]', part)) / len(part)
                    if consonant_ratio > 0.7:
                        suspicious_indicators.append("random_domain_pattern")
                        break
            
            # Homograph attack detection (basic)
            suspicious_chars = re.findall(r'[а-яё]|[αβγδεζηθικλμνξοπρστυφχψω]|[àáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿ]', domain)
            if suspicious_chars:
                security_issues.append("homograph_attack_chars")
                risk_factors.append("internationalized_domain")
            
            # Punycode detection
            if domain.startswith('xn--') or 'xn--' in domain:
                risk_factors.append("punycode_domain")
            
            # === TLD ANALYSIS ===
            if len(domain_parts) >= 2:
                tld = domain_parts[-1].lower()
                
                # High-risk TLDs
                high_risk_tlds = {
                    'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'cc', 'top', 'click',
                    'download', 'racing', 'loan', 'win', 'bid', 'science',
                    'work', 'party', 'review', 'country', 'kim', 'cricket'
                }
                
                if tld in high_risk_tlds:
                    suspicious_indicators.append("high_risk_tld")
            
            # === ENHANCED URL SHORTENER ANALYSIS ===
            shortener_analysis = await self._analyze_shortener_enhanced(url)
            
            if shortener_analysis['analysis_performed']:
                if shortener_analysis['risk_assessment'] == 'malicious':
                    security_issues.extend(['malicious_shortener', 'dangerous_redirect'])
                elif shortener_analysis['risk_assessment'] == 'suspicious':
                    suspicious_indicators.extend(['suspicious_shortener', 'questionable_redirect'])
                elif not shortener_analysis['legitimate_shortener'] and shortener_analysis['is_shortener']:
                    risk_factors.append('unknown_shortener_service')
                
                # Add specific shortener risk factors
                risk_factors.extend(shortener_analysis.get('risk_factors', []))
                
                # Store shortener analysis in metadata for detailed reporting
                shortener_metadata = {
                    'is_shortener': shortener_analysis['is_shortener'],
                    'legitimate': shortener_analysis.get('legitimate_shortener', False),
                    'final_destination': shortener_analysis.get('final_destination'),
                    'redirect_count': shortener_analysis.get('redirect_count', 0),
                    'analysis_summary': shortener_analysis.get('analysis_summary')
                }

            else:
                # Fallback to basic shortener detection for non-pattern matches
                basic_shorteners = {
                    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link',
                    'tiny.cc', 'is.gd', 'buff.ly', 'rebrand.ly'
                }
                
                if any(shortener in domain for shortener in basic_shorteners):
                    risk_factors.append("url_shortener_detected")
                
                shortener_metadata = {'is_shortener': False, 'analysis_performed': False}
            
            # === PATH ANALYSIS ===
            if path:
                # Path length analysis
                if len(path) > 200:
                    suspicious_indicators.append("extremely_long_path")
                elif len(path) > 100:
                    suspicious_indicators.append("long_path")
                
                # Directory traversal depth
                path_segments = [p for p in path.split('/') if p]
                if len(path_segments) > 15:
                    suspicious_indicators.append("deep_directory_structure")
                elif len(path_segments) > 10:
                    suspicious_indicators.append("deep_path")
                
                # Suspicious path patterns
                if re.search(r'\.\./|\.\.\\', path):
                    security_issues.append("directory_traversal_pattern")
                
                if re.search(r'%[0-9a-fA-F]{2}', path):
                    risk_factors.append("url_encoded_characters")
                    # Check for double encoding
                    if path.count('%25') > 0:
                        security_issues.append("double_url_encoding")
                
                # Executable file extensions in path
                executable_extensions = r'\.(exe|scr|bat|cmd|com|msi|dll|jar|app|dmg|pkg)$'
                if re.search(executable_extensions, path, re.IGNORECASE):
                    security_issues.append("executable_file_download")
                
                # Script file extensions
                script_extensions = r'\.(php|asp|aspx|jsp|cgi|pl|py|rb|js)$'
                if re.search(script_extensions, path, re.IGNORECASE):
                    risk_factors.append("server_side_script")
                
                # Admin/sensitive path detection
                admin_patterns = [
                    r'/admin', r'/wp-admin', r'/administrator', r'/control',
                    r'/panel', r'/dashboard', r'/login', r'/signin', r'/auth',
                    r'/phpmyadmin', r'/.env', r'/config', r'/backup'
                ]
                
                for pattern in admin_patterns:
                    if re.search(pattern, path, re.IGNORECASE):
                        risk_factors.append("admin_path_access")
                        break
            
            # === QUERY STRING ANALYSIS ===
            if query:
                # Query length analysis
                if len(query) > 500:
                    suspicious_indicators.append("extremely_long_query")
                elif len(query) > 200:
                    suspicious_indicators.append("long_query_string")
                
                # Parameter analysis
                params = query.split('&')
                if len(params) > 20:
                    suspicious_indicators.append("excessive_parameters")
                
                # SQL injection patterns
                sql_patterns = [
                    r'union\s+select', r'drop\s+table', r'delete\s+from',
                    r'insert\s+into', r'update\s+set', r'exec\s*\(',
                    r'sp_executesql', r'xp_cmdshell', r'\'.*or.*1=1',
                    r'\'.*or.*\'1\'=\'1', r'\'.*union.*select'
                ]
                
                query_lower = query.lower()
                for pattern in sql_patterns:
                    if re.search(pattern, query_lower):
                        security_issues.append("sql_injection_pattern")
                        break
                
                # XSS patterns
                xss_patterns = [
                    r'<script', r'javascript:', r'on\w+\s*=', r'<iframe',
                    r'<object', r'<embed', r'<form', r'alert\s*\(',
                    r'document\.cookie', r'document\.write'
                ]
                
                for pattern in xss_patterns:
                    if re.search(pattern, query_lower):
                        security_issues.append("xss_pattern")
                        break
                
                # Command injection patterns
                cmd_patterns = [
                    r'[;&|`$]', r'\.\./\.\./\.\./etc/passwd',
                    r'cmd\.exe', r'/bin/sh', r'powershell',
                    r'\$\(.*\)', r'`.*`'
                ]
                
                for pattern in cmd_patterns:
                    if re.search(pattern, query):
                        security_issues.append("command_injection_pattern")
                        break
            
            # === PORT ANALYSIS ===
            if ':' in parsed_url.netloc and parsed_url.port:
                port = parsed_url.port
                
                # Non-standard HTTP ports
                if parsed_url.scheme == 'http' and port != 80:
                    risk_factors.append("non_standard_http_port")
                elif parsed_url.scheme == 'https' and port != 443:
                    risk_factors.append("non_standard_https_port")
                
                # Suspicious ports
                suspicious_ports = [
                    21, 22, 23, 25, 53, 110, 143, 993, 995,  # Common service ports
                    1433, 1521, 3306, 5432,  # Database ports
                    3389, 5900, 5901,        # Remote access ports
                    6667, 6697,              # IRC ports
                    8080, 8443, 9090         # Alternative web ports
                ]
                
                if port in suspicious_ports:
                    suspicious_indicators.append("suspicious_port")
            
            # === ENCODING AND CHARACTER ANALYSIS ===
            full_url = url.lower()
            
            # Multiple encoding detection
            encoding_count = full_url.count('%')
            if encoding_count > 10:
                suspicious_indicators.append("excessive_url_encoding")
            
            # Unicode normalization attacks
            if any(ord(char) > 127 for char in url):
                risk_factors.append("non_ascii_characters")
            
            # === TYPOSQUATTING DETECTION ===
            # Check against common legitimate domains (basic implementation)
            
            for legit_domain in self.legitimate_domains:
                domain_name = domain_parts[0] if len(domain_parts) > 1 else domain
                
                # Simple Levenshtein distance check
                if self._calculate_edit_distance(domain_name, legit_domain) == 1 and len(domain_name) > 3:
                    suspicious_indicators.append("potential_typosquatting")
                    break
            
            # === DYNAMIC URL ANALYSIS ===
            # Check for dynamic content indicators
            dynamic_indicators = ['?', '&', '=', 'php', 'asp', 'jsp', 'cgi']
            dynamic_score = sum(1 for indicator in dynamic_indicators if indicator in url)
            
            if dynamic_score >= 3:
                risk_factors.append("dynamic_content")
            
            # === THREAT SCORING ===
            # Calculate weighted threat score
            threat_weights = {
                'security_issues': 40,      # High impact
                'suspicious_indicators': 20, # Medium impact
                'risk_factors': 10          # Lower impact
            }
            
            threat_score = (
                len(security_issues) * threat_weights['security_issues'] +
                len(suspicious_indicators) * threat_weights['suspicious_indicators'] +
                len(risk_factors) * threat_weights['risk_factors']
            )
            
            threat_detected = threat_score >= 60 or len(security_issues) >= 2
            confidence_score = min(threat_score, 100)
            
            # Determine threat types
            threat_types = []
            if security_issues:
                threat_types.extend(['security_vulnerability', 'malicious_pattern'])
            if suspicious_indicators:
                threat_types.append('suspicious_structure')
            if risk_factors:
                threat_types.append('risky_configuration')
            
            # === METADATA COMPILATION ===
            metadata = ProviderMetadata(
                # Original indicators
                suspicious_indicators=suspicious_indicators,
                domain=domain,
                path_length=len(path),
                subdomain_count=subdomain_count,
                
                # Enhanced analysis results
                security_issues=security_issues,
                risk_factors=risk_factors,
                threat_score=threat_score,
                
                # URL components
                scheme=parsed_url.scheme,
                port=parsed_url.port,
                query_params_count=len(query.split('&')) if query else 0,
                has_fragment=bool(fragment),
                
                # Analysis flags
                is_ip_address=bool(re.match(ipv4_pattern, domain) or re.match(ipv6_pattern, domain)),
                is_shortener=shortener_metadata.get('is_shortener', False),
                legitimate_shortener=shortener_metadata.get('legitimate', False),
                has_suspicious_tld=any(tld in domain for tld in high_risk_tlds),
                has_encoding=encoding_count > 0,
                
                # Shortener analysis results
                shortener_analysis=shortener_metadata,
                
                # Security metrics
                encoding_count=encoding_count,
                directory_depth=len([p for p in path.split('/') if p]) if path else 0,
                dynamic_content_score=dynamic_score
            )
            
            # Create ProviderScanResult
            scan_result = ProviderScanResult(
                provider="internal",
                threat_detected=threat_detected,
                threat_types=list(set(threat_types)),
                confidence_score=confidence_score,
                metadata=metadata
            )
            
            return {
                "technical": scan_result.to_dict()
            }
        
        except Exception as e:
            scan_result = ProviderScanResult(
                provider="internal",
                threat_detected=False,
                error=str(e)
            )
            return {
                "technical": scan_result.to_dict()
            }

    def _calculate_edit_distance(self, s1: str, s2: str) -> int:
        """
        Calculate Levenshtein distance between two strings for typosquatting detection.
        
        Args:
            s1: First string
            s2: Second string
            
        Returns:
            Edit distance between the strings
        """
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
    
    # Integration method for URLAnalysisService
    async def _analyze_shortener_enhanced(self, url: str) -> Dict[str, Any]:
        """
        Enhanced shortener analysis method for integration with URLAnalysisService.
        
        Returns:
            Dictionary containing detailed shortener analysis results
        """
        analyzer = URLShortenerAnalyzer()
        
        # Quick check if URL is a shortener
        basic_info = await analyzer.get_shortener_info(url)
        
        if not basic_info.get('pattern_match', False) and not basic_info.get('is_known_shortener', False):
            return {
                'is_shortener': False,
                'analysis_performed': False
            }
        
        # Perform full analysis
        result = await analyzer.analyze_shortener(url)
        
        # result contains the result of the shorterner analysis we can use the final result to check the url 
        # for suspicious patterns and also domain squatting.
        # --------------------------------------------------------------------------
            # ShortenerAnalysisResult(
            #     original_url=url,
            #     final_destination=url,
            #     is_shortener=False,
            #     redirect_chain=[],
            #     total_redirects=0,
            #     total_response_time=0.0,
            #     risk_assessment="safe",
            #     risk_factors=[],
            #     legitimate_shortener=False,
            #     analysis_summary="Not a URL shortener"
            # )

        # Integrate with existing risk factor system
        risk_factors = []
        
        if result.risk_assessment == "malicious":
            risk_factors.extend(["malicious_shortener", "high_risk_destination"])
        elif result.risk_assessment == "suspicious":
            risk_factors.extend(["suspicious_shortener", "redirect_anomaly"])
        elif not result.legitimate_shortener:
            risk_factors.append("unknown_shortener")
        
        risk_factors.extend(result.risk_factors)
        # TODO -  We need to analyze the destination url of a shoterner for Suspicious Patterns and Domain Squatting

        return {
            'is_shortener': result.is_shortener,
            'legitimate_shortener': result.legitimate_shortener,
            'final_destination': result.final_destination,
            'redirect_count': result.total_redirects,
            'risk_assessment': result.risk_assessment,
            'risk_factors': risk_factors,
            'analysis_summary': result.analysis_summary,
            'analysis_performed': True,
            'shortener_analysis': result  # Full result object for detailed logging
        }

    def _detect_suspicious_patterns(self, content: str) -> List[str]:
        """
        Detect suspicious patterns in page content.
        """
        return SuspiciousPatternAnalyzer().analyze_content(content=content)
    
    def _calculate_threat_level(self, analysis_results: Dict[str, Any]) -> Tuple[ThreatLevel, int]:
        """
        Calculate overall threat level and confidence score.
        """
        threat_scores = []
        confidence_scores = []
        
        for scan_type, result in analysis_results.items():
            if result.get("threat_detected"):
                # Weight different scan types
                weight = {
                    "virustotal": 0.3,
                    "safebrowsing": 0.3,
                    "urlvoid": 0.2,
                    "reputation": 0.1,
                    "content": 0.2,
                    "technical": 0.1
                }.get(scan_type, 0.1)
                
                threat_scores.append(result.get("confidence_score", 0) * weight)
            
            confidence_scores.append(result.get("confidence_score", 0))
        
        # Calculate overall scores
        overall_threat_score = sum(threat_scores)
        overall_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0
        
        # Determine threat level
        if overall_threat_score >= 70:
            threat_level = ThreatLevel.HIGH
        elif overall_threat_score >= 40:
            threat_level = ThreatLevel.MEDIUM
        elif overall_threat_score >= 20:
            threat_level = ThreatLevel.LOW
        else:
            threat_level = ThreatLevel.SAFE
        
        return threat_level, int(overall_confidence)
    
    def _normalize_url(self, url: str) -> Optional[str]:
        """
        Normalize and validate URL.
        """
        try:
            # Add protocol if missing
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            parsed = urlparse(url)
            
            # Validate URL components
            if not parsed.netloc:
                return None
            
            # Normalize URL
            normalized = f"{parsed.scheme}://{parsed.netloc.lower()}{parsed.path}"
            
            if parsed.query:
                normalized += f"?{parsed.query}"
            
            return normalized
        
        except Exception:
            return None
    
    def _extract_domain(self, url: str) -> str:
        """
        Extract domain from URL.
        """
        try:
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except Exception:
            return ""
    
    # Helper methods for controller integration
    
    def get_analysis_result_structure(self) -> Dict[str, Any]:
        """
        Return expected structure for analysis results.
        
        Returns:
            Dictionary describing the expected analysis result structure
        """
        return {
            "normalized_url": "str",
            "domain": "str", 
            "threat_level": "ThreatLevel enum",
            "confidence_score": "int (0-100)",
            "analysis_results": {
                "security_scan_type": {
                    "provider": "str",
                    "threat_detected": "bool",
                    "threat_types": "List[str]",
                    "confidence_score": "int",
                    "raw_response": "dict",
                    "metadata": "dict"
                }
            },
            "scan_types": "List[ScanType]"
        }
    
    def validate_scan_types(self, scan_types: List[ScanType]) -> bool:
        """
        Validate scan type parameters.
        
        Args:
            scan_types: List of scan types to validate
            
        Returns:
            True if all scan types are valid
        """
        return all(ScanType.scan_types() in valid_types for scan_type in scan_types)
    
    def estimate_analysis_time(self, scan_types: List[ScanType]) -> int:
        """
        Estimate time for analysis in seconds.
        
        Args:
            scan_types: List of scan types to perform
            
        Returns:
            Estimated analysis time in seconds
        """
        base_time = 5  # Base analysis time
        
        if ScanType.SECURITY in scan_types:
            base_time += 15  # External security scans take longer
        if ScanType.CONTENT in scan_types:
            base_time += 10  # Content analysis with AI
        if ScanType.REPUTATION in scan_types:
            base_time += 2   # Reputation lookup
        if ScanType.BROKEN_LINKS in scan_types:
            base_time += 20  # Broken link scanning takes longer due to crawling
        if ScanType.TECHNICAL in scan_types:
            base_time += 15    
        return base_time
    
    async def _scan_broken_links_wrapper(self, url: str, scan_depth: int = 2, max_links: int = 100) -> Dict[str, Any]:
        """
        Wrapper for broken link scanning that returns results in the expected format for _perform_comprehensive_analysis.
        
        Args:
            url: URL to scan for broken links
            scan_depth: Depth of crawling
            max_links: Maximum number of links to check
            
        Returns:
            Dictionary containing broken link scan results
        """
        # Do not do verbose scanning as that is not available here or would be 
        # duplicated 
        scanner = BrokenLinkScanner()               
        broken_link_result = await scanner.scan(url=url,config=ScanConfig(verbose=False, slow_threshold=1.5, max_depth=scan_depth, max_links=max_links))
        return {"broken_link_scan": broken_link_result}
    