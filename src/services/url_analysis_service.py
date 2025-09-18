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
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

from src.config.settings import get_settings
from src.models.url_check import (
    URLCheck, ScanResult, URLReputation, 
    CheckStatus, ThreatLevel, ScanType
)
from src.models.user import User
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
    
    def __init__(self, db_session: Session, ai_service: AIService, security_service: SecurityService):
        self.db = db_session
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
        user_id: Optional[uuid.UUID] = None,
        scan_types: Optional[List[ScanType]] = None,
        priority: bool = False
    ) -> URLCheck:
        """
        Perform comprehensive URL analysis.
        
        Args:
            url: URL to analyze
            user_id: User requesting the analysis
            scan_types: Specific scan types to perform
            priority: Whether to prioritize this scan
        
        Returns:
            URLCheck object with analysis results
        """
        # Validate and normalize URL
        normalized_url = self._normalize_url(url)
        if not normalized_url:
            raise InvalidURLError(f"Invalid URL format: {url}")
        
        # Check for existing recent analysis
        existing_check = self._get_recent_check(normalized_url)
        if existing_check and not priority:
            return existing_check
        
        # Create URL check record
        url_check = URLCheck(
            user_id=user_id,
            original_url=url,
            normalized_url=normalized_url,
            domain=self._extract_domain(normalized_url),
            status=CheckStatus.PENDING
        )
        
        self.db.add(url_check)
        self.db.flush()  # Get ID
        
        try:
            # Update status to scanning
            url_check.status = CheckStatus.SCANNING
            url_check.scan_started_at = datetime.now(timezone.utc)
            self.db.commit()
            
            # Perform analysis
            analysis_results = await self._perform_comprehensive_analysis(
                normalized_url, 
                scan_types or [ScanType.SECURITY, ScanType.REPUTATION, ScanType.CONTENT]
            )
            
            # Process results and determine threat level
            threat_level, confidence_score = self._calculate_threat_level(analysis_results)
            
            # Update URL check with results
            url_check.status = CheckStatus.COMPLETED
            url_check.threat_level = threat_level
            url_check.confidence_score = confidence_score
            url_check.scan_completed_at = datetime.now(timezone.utc)
            url_check.analysis_results = analysis_results
            
            # Create scan results
            for scan_type, result in analysis_results.items():
                scan_result = ScanResult(
                    url_check_id=url_check.id,
                    scan_type=ScanType(scan_type),
                    provider=result.get("provider", "internal"),
                    threat_detected=result.get("threat_detected", False),
                    threat_types=result.get("threat_types", []),
                    confidence_score=result.get("confidence_score", 0),
                    raw_response=result.get("raw_response"),
                    metadata=result.get("metadata", {})
                )
                self.db.add(scan_result)
            
            # Update or create URL reputation
            self._update_url_reputation(normalized_url, threat_level, confidence_score)
            
            self.db.commit()
            
        except Exception as e:
            # Handle scan failure
            url_check.status = CheckStatus.FAILED
            url_check.error_message = str(e)
            url_check.scan_completed_at = datetime.now(timezone.utc)
            self.db.commit()
            raise URLAnalysisError(f"Analysis failed: {str(e)}")
        
        return url_check
    
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
    
    async def _analyze_reputation(self, url: str) -> Dict[str, Any]:
        """
        Analyze URL reputation based on historical data.
        """
        domain = self._extract_domain(url)
        
        # Check existing reputation
        reputation = self.db.query(URLReputation).filter(
            URLReputation.domain == domain
        ).first()
        
        if reputation:
            # Calculate reputation score based on historical data
            total_checks = reputation.total_checks
            malicious_checks = reputation.malicious_count
            
            reputation_score = 100 - (malicious_checks / total_checks * 100) if total_checks > 0 else 50
            
            threat_detected = reputation_score < 70
            confidence_score = min(total_checks * 2, 100)  # More checks = higher confidence
            
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
                        "first_seen": reputation.first_seen.isoformat() if reputation.first_seen else None,
                        "last_seen": reputation.last_seen.isoformat() if reputation.last_seen else None
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
    
    def _get_recent_check(self, url: str, hours: int = 24) -> Optional[URLCheck]:
        """
        Get recent check for URL if available.
        """
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        return self.db.query(URLCheck).filter(
            and_(
                URLCheck.normalized_url == url,
                URLCheck.status == CheckStatus.COMPLETED,
                URLCheck.scan_completed_at > cutoff_time
            )
        ).order_by(URLCheck.scan_completed_at.desc()).first()
    
    def _update_url_reputation(self, url: str, threat_level: ThreatLevel, confidence_score: int) -> None:
        """
        Update URL reputation based on analysis results.
        """
        domain = self._extract_domain(url)
        
        reputation = self.db.query(URLReputation).filter(
            URLReputation.domain == domain
        ).first()
        
        if not reputation:
            reputation = URLReputation(
                domain=domain,
                first_seen=datetime.now(timezone.utc)
            )
            self.db.add(reputation)
        
        # Update reputation statistics
        reputation.total_checks += 1
        reputation.last_seen = datetime.now(timezone.utc)
        
        if threat_level in [ThreatLevel.MEDIUM, ThreatLevel.HIGH]:
            reputation.malicious_count += 1
        
        # Update reputation score
        reputation.reputation_score = (
            (reputation.total_checks - reputation.malicious_count) / 
            reputation.total_checks * 100
        ) if reputation.total_checks > 0 else 50
        
        # Update threat level if this is worse
        if threat_level.value > (reputation.last_threat_level.value if reputation.last_threat_level else 0):
            reputation.last_threat_level = threat_level
    
    def get_url_history(self, url: str, limit: int = 10) -> List[URLCheck]:
        """
        Get analysis history for URL.
        """
        normalized_url = self._normalize_url(url)
        if not normalized_url:
            return []
        
        return self.db.query(URLCheck).filter(
            URLCheck.normalized_url == normalized_url
        ).order_by(URLCheck.created_at.desc()).limit(limit).all()
    
    def get_domain_reputation(self, domain: str) -> Optional[URLReputation]:
        """
        Get reputation information for domain.
        """
        return self.db.query(URLReputation).filter(
            URLReputation.domain == domain.lower()
        ).first()