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
                self._scan_urlvoid(url)
            ])
        
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
        Perform technical analysis of URL structure and hosting.
        Returns dictionary for compatibility with _perform_comprehensive_analysis.
        """
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Analyze URL structure
            suspicious_indicators = []
            
            # Check for suspicious URL patterns
            if len(parsed_url.path) > 100:
                suspicious_indicators.append("long_path")
            
            if parsed_url.path.count('/') > 10:
                suspicious_indicators.append("deep_path")
            
            if re.search(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', domain):
                suspicious_indicators.append("ip_address")
            
            if len(domain.split('.')) > 4:
                suspicious_indicators.append("excessive_subdomains")
            
            if re.search(r'[a-zA-Z0-9]{20,}', domain):
                suspicious_indicators.append("random_domain")
            
            # Check for URL shorteners
            shortener_domains = [
                'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
                'short.link', 'tiny.cc', 'is.gd', 'buff.ly'
            ]
            
            if any(shortener in domain for shortener in shortener_domains):
                suspicious_indicators.append("url_shortener")
            
            threat_detected = len(suspicious_indicators) >= 2
            confidence_score = len(suspicious_indicators) * 25
            
            # Create ProviderScanResult
            metadata = ProviderMetadata(
                suspicious_indicators=suspicious_indicators,
                domain=domain,
                path_length=len(parsed_url.path),
                subdomain_count=len(domain.split('.')) - 2
            )
            
            scan_result = ProviderScanResult(
                provider="internal",
                threat_detected=threat_detected,
                threat_types=["suspicious_structure"] if threat_detected else [],
                confidence_score=min(confidence_score, 100),
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
    
    def _detect_suspicious_patterns(self, content: str) -> List[str]:
        """
        Detect suspicious patterns in page content.
        """
        patterns = []
        
        # Phishing patterns
        phishing_keywords = [
            'verify your account', 'suspended account', 'click here immediately',
            'urgent action required', 'confirm your identity', 'update payment',
            'security alert', 'unusual activity', 'temporary suspension'
        ]
        
        content_lower = content.lower()
        for keyword in phishing_keywords:
            if keyword in content_lower:
                patterns.append(f"phishing_keyword_{keyword.replace(' ', '_')}")
        
        # Suspicious form patterns
        if re.search(r'<input[^>]*type=["\']password["\']', content, re.IGNORECASE):
            patterns.append("password_input")
        
        if re.search(r'<input[^>]*name=["\'].*(?:ssn|social|credit|card)[^"\'>]*["\']', content, re.IGNORECASE):
            patterns.append("sensitive_input")
        
        # Suspicious JavaScript patterns
        if re.search(r'eval\s*\(', content):
            patterns.append("eval_javascript")
        
        if re.search(r'document\.write\s*\(', content):
            patterns.append("document_write")
        
        return patterns
    
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
        broken_link_result = await self._scan_broken_links(url, scan_depth, max_links)
        return {"broken_link_scan": broken_link_result}
    
    async def _scan_broken_links(self, url: str, scan_depth: int = 2, max_links: int = 100) -> BrokenLinkScanResult:
        """
        Scan for broken links on the given URL using structured models.
        
        Args:
            url: URL to scan for broken links
            scan_depth: Depth of crawling (default: 2)
            max_links: Maximum number of links to check (default: 100)
            
        Returns:
            BrokenLinkScanResult: Structured broken link scan results
        """
        try:
            # Fetch the main page content
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
                async with session.get(url) as response:
                    if response.status != 200:
                        return BrokenLinkScanResult(
                            total_links_found=0,
                            total_links_checked=0,
                            broken_links_count=0,
                            scan_depth_used=scan_depth,
                            max_links_used=max_links,
                            broken_links=[],
                            scan_duration=0.0,
                            error_message=f"Failed to fetch main page: HTTP {response.status}"
                        )
                    
                    content = await response.text()
            
            start_time = utc_datetime()
            
            # Extract links from HTML content
            all_links = self._extract_links_from_html(content, url)
            
            # Limit the number of links to check
            links_to_check = all_links[:max_links]
            
            # Check each link status
            broken_link_details = []
            checked_count = 0
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                for link in links_to_check:
                    try:
                        link_status = await self._check_link_status(session, link)
                        checked_count += 1
                        
                        if not link_status["is_working"]:
                            # Determine status based on error type
                            if link_status["status_code"]:
                                if 400 <= link_status["status_code"] < 500:
                                    status = BrokenLinkStatus.CLIENT_ERROR
                                elif 500 <= link_status["status_code"] < 600:
                                    status = BrokenLinkStatus.SERVER_ERROR
                                else:
                                    status = BrokenLinkStatus.BROKEN
                            else:
                                status = BrokenLinkStatus.TIMEOUT
                            
                            broken_link_details.append(BrokenLinkDetail(
                                url=link,
                                status_code=link_status["status_code"],
                                status=status,
                                error_message=link_status["error"],
                                response_time=link_status["response_time"],
                                redirect_url=None,  # Could be enhanced to track redirects
                                depth_level=1  # Currently only scanning depth 1
                            ))
                    except Exception as e:
                        # Count failed checks as broken links
                        broken_link_details.append(BrokenLinkDetail(
                            url=link,
                            status_code=None,
                            status=BrokenLinkStatus.TIMEOUT,
                            error_message=str(e),
                            response_time=None,
                            redirect_url=None,
                            depth_level=1
                        ))
                        checked_count += 1
            
            scan_duration = (datetime.now() - start_time).total_seconds()
            
            return BrokenLinkScanResult(
                total_links_found=len(all_links),
                total_links_checked=checked_count,
                broken_links_count=len(broken_link_details),
                scan_depth_used=scan_depth,
                max_links_used=max_links,
                broken_links=broken_link_details,
                scan_duration=scan_duration,
                error_message=None
            )
            
        except Exception as e:
            return BrokenLinkScanResult(
                total_links_found=0,
                total_links_checked=0,
                broken_links_count=0,
                scan_depth_used=scan_depth,
                max_links_used=max_links,
                broken_links=[],
                scan_duration=0.0,
                error_message=f"Broken link scan failed: {str(e)}"
            )
    
    def _extract_links_from_html(self, html_content: str, base_url: str) -> List[str]:
        """
        Extract all links from HTML content.
        
        Args:
            html_content: HTML content to parse
            base_url: Base URL for resolving relative links
            
        Returns:
            List of absolute URLs found in the HTML
        """
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            links = []
            
            # Find all anchor tags with href attributes
            for link in soup.find_all('a', href=True):
                href = link['href']
                
                # Skip empty hrefs, anchors, and javascript links
                if not href or href.startswith('#') or href.startswith('javascript:') or href.startswith('mailto:'):
                    continue
                
                # Convert relative URLs to absolute URLs
                absolute_url = urljoin(base_url, href)
                
                # Only include HTTP/HTTPS links
                if absolute_url.startswith(('http://', 'https://')):
                    links.append(absolute_url)
            
            # Remove duplicates while preserving order
            seen = set()
            unique_links = []
            for link in links:
                if link not in seen:
                    seen.add(link)
                    unique_links.append(link)
            
            return unique_links
            
        except Exception as e:
            # Return empty list if parsing fails
            return []
    
    async def _check_link_status(self, session: aiohttp.ClientSession, url: str) -> Dict[str, Any]:
        """
        Check if a link is working by making a HEAD request.
        
        Args:
            session: aiohttp session to use for the request
            url: URL to check
            
        Returns:
            Dictionary with link status information
        """
        start_time = datetime.now()
        
        try:
            # Try HEAD request first (faster)
            async with session.head(url, allow_redirects=True) as response:
                response_time = (datetime.now() - start_time).total_seconds()
                
                # Consider 2xx and 3xx status codes as working
                is_working = 200 <= response.status < 400
                
                return {
                    "is_working": is_working,
                    "status_code": response.status,
                    "error": None if is_working else f"HTTP {response.status}",
                    "response_time": response_time
                }
                
        except aiohttp.ClientError as e:
            response_time = (datetime.now() - start_time).total_seconds()
            return {
                "is_working": False,
                "status_code": None,
                "error": f"Connection error: {str(e)}",
                "response_time": response_time
            }
        except Exception as e:
            response_time = (datetime.now() - start_time).total_seconds()
            return {
                "is_working": False,
                "status_code": None,
                "error": f"Unexpected error: {str(e)}",
                "response_time": response_time
            }