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

from src.config.settings import get_settings
from src.models.url_check import ThreatLevel, ScanType, URLReputation
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
        self.user_agent = "LinkShield-Bot/1.0 (+https://linkshield.com/bot)"
    
    async def analyze_url(
        self, 
        url: str, 
        scan_types: Optional[List[ScanType]] = None,
        reputation_data: Optional[URLReputation] = None
    ) -> Dict[str, Any]:
        """
        Perform comprehensive URL analysis and return results as dictionary.
        
        Args:
            url: URL to analyze
            scan_types: Specific scan types to perform
            reputation_data: Historical reputation data for analysis
        
        Returns:
            Dictionary containing analysis results with threat level and confidence score
        """
        # Validate and normalize URL
        normalized_url: str = self._normalize_url(url)
        if not normalized_url:
            raise InvalidURLError(f"Invalid URL format: {url}")
        
        # Perform comprehensive analysis
        analysis_results = await self._perform_comprehensive_analysis(
            normalized_url, 
            scan_types or [ScanType.SECURITY, ScanType.REPUTATION, ScanType.CONTENT]
        )
        
        # Include reputation analysis if data provided
        if reputation_data:
            reputation_analysis = self._analyze_reputation(normalized_url, reputation_data)
            analysis_results.update(reputation_analysis)
        
        # Calculate threat level and confidence score
        threat_level, confidence_score = self._calculate_threat_level(analysis_results)
        
        # Return structured analysis results
        return {
            "normalized_url": normalized_url,
            "domain": self._extract_domain(normalized_url),
            "threat_level": threat_level,
            "confidence_score": confidence_score,
            "analysis_results": analysis_results,
            "scan_types": scan_types or [ScanType.SECURITY, ScanType.REPUTATION, ScanType.CONTENT]
        }
    
    async def _perform_comprehensive_analysis(self, url: str, scan_types: List[ScanType]) -> Dict[str, Any]:
        """
        Perform comprehensive analysis using multiple providers.
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
                    
                    return {
                        "virustotal": {
                            "provider": "virustotal",
                            "threat_detected": threat_detected,
                            "threat_types": threat_types,
                            "confidence_score": confidence_score,
                            "raw_response": report,
                            "metadata": {
                                "positives": positives,
                                "total": total,
                                "scan_date": report.get("scan_date")
                            }
                        }
                    }
        
        except Exception as e:
            return {
                "virustotal": {
                    "provider": "virustotal",
                    "threat_detected": False,
                    "error": str(e)
                }
            }
    
    async def _scan_safe_browsing(self, url: str) -> Dict[str, Any]:
        """
        Scan URL using Google Safe Browsing API.
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
                    
                    return {
                        "safebrowsing": {
                            "provider": "safebrowsing",
                            "threat_detected": threat_detected,
                            "threat_types": threat_types,
                            "confidence_score": confidence_score,
                            "raw_response": result,
                            "metadata": {
                                "matches_count": len(threat_matches)
                            }
                        }
                    }
        
        except Exception as e:
            return {
                "safebrowsing": {
                    "provider": "safebrowsing",
                    "threat_detected": False,
                    "error": str(e)
                }
            }
    
    async def _scan_urlvoid(self, url: str) -> Dict[str, Any]:
        """
        Scan URL using URLVoid API.
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
                    
                    return {
                        "urlvoid": {
                            "provider": "urlvoid",
                            "threat_detected": threat_detected,
                            "threat_types": threat_types,
                            "confidence_score": confidence_score,
                            "raw_response": result,
                            "metadata": {
                                "detections": detections,
                                "engines_count": engines_count
                            }
                        }
                    }
        
        except Exception as e:
            return {
                "urlvoid": {
                    "provider": "urlvoid",
                    "threat_detected": False,
                    "error": str(e)
                }
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

            # TODO Implement ReputationScanResult Class Based on this.
            return {
                "reputation": {
                    "provider": "internal",
                    "threat_detected": threat_detected,
                    "threat_types": ["low_reputation"] if threat_detected else [],
                    "confidence_score": confidence_score,
                    "metadata": {
                        "reputation_score": reputation_score,
                        "total_checks": total_checks,
                        "malicious_checks": malicious_checks,
                        "first_seen": reputation_data.get("first_seen"),
                        "last_seen": reputation_data.get("last_seen")
                    }
                }
            }
        
        return {
            "reputation": {
                "provider": "internal",
                "threat_detected": False,
                "threat_types": [],
                "confidence_score": 0,
                "metadata": {
                    "reputation_score": 50,  # Neutral for new domains
                    "total_checks": 0,
                    "malicious_checks": 0
                }
            }
        }
    
    async def _analyze_content(self, url: str) -> Dict[str, Any]:
        """
        Analyze URL content using AI and pattern matching.
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
                    
                    return {
                        "content": {
                            "provider": "internal",
                            "threat_detected": threat_detected,
                            "threat_types": list(set(threat_types)),
                            "confidence_score": min(confidence_score, 100),
                            "metadata": {
                                "ai_analysis": ai_analysis,
                                "suspicious_patterns": suspicious_patterns,
                                "content_length": len(content)
                            }
                        }
                    }
        
        except Exception as e:
            return {
                "content": {
                    "provider": "internal",
                    "threat_detected": False,
                    "error": str(e)
                }
            }
    
    async def _analyze_technical(self, url: str) -> Dict[str, Any]:
        """
        Perform technical analysis of URL structure and hosting.
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
            
            return {
                "technical": {
                    "provider": "internal",
                    "threat_detected": threat_detected,
                    "threat_types": ["suspicious_structure"] if threat_detected else [],
                    "confidence_score": min(confidence_score, 100),
                    "metadata": {
                        "suspicious_indicators": suspicious_indicators,
                        "domain": domain,
                        "path_length": len(parsed_url.path),
                        "subdomain_count": len(domain.split('.')) - 2
                    }
                }
            }
        
        except Exception as e:
            return {
                "technical": {
                    "provider": "internal",
                    "threat_detected": False,
                    "error": str(e)
                }
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
        valid_types = [ScanType.SECURITY, ScanType.REPUTATION, ScanType.CONTENT]
        return all(scan_type in valid_types for scan_type in scan_types)
    
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
            
        return base_time