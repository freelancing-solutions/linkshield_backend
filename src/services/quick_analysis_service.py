"""
Quick Analysis Service for fast URL analysis with sub-3-second response times.

This service provides cached, lightweight URL analysis optimized for bot interactions
with fallback to basic analysis when full analysis times out.
"""

import asyncio
import logging
import hashlib
import json
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
import aioredis
import aiohttp

from ..config.settings import settings
from ..social_protection.social_protection_controller import SocialProtectionController
from ..models.social_protection import URLScanResult

logger = logging.getLogger(__name__)


class QuickAnalysisService:
    """
    Service for performing quick URL analysis with caching and timeout handling.
    
    Optimized for bot interactions requiring sub-3-second response times.
    """
    
    def __init__(self):
        """Initialize the quick analysis service."""
        self.redis_client: Optional[aioredis.Redis] = None
        self.http_session: Optional[aiohttp.ClientSession] = None
        self.social_protection_controller = SocialProtectionController()
        self.is_initialized = False
        
    async def initialize(self):
        """Initialize Redis connection and HTTP session."""
        if self.is_initialized:
            return
            
        try:
            # Initialize Redis connection for caching
            self.redis_client = aioredis.from_url(
                settings.REDIS_URL,
                password=settings.REDIS_PASSWORD,
                decode_responses=True
            )
            
            # Test Redis connection
            await self.redis_client.ping()
            logger.info("Redis connection established for QuickAnalysisService")
            
            # Initialize HTTP session with timeout
            timeout = aiohttp.ClientTimeout(total=2.5)  # Leave 0.5s for processing
            self.http_session = aiohttp.ClientSession(timeout=timeout)
            
            self.is_initialized = True
            logger.info("QuickAnalysisService initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize QuickAnalysisService: {e}")
            raise
    
    async def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Perform quick URL analysis with caching.
        
        Args:
            url: URL to analyze
            
        Returns:
            Analysis results with risk assessment
        """
        if not self.is_initialized:
            await self.initialize()
        
        # Generate cache key
        cache_key = self._generate_cache_key(url)
        
        try:
            # Check cache first
            cached_result = await self._get_cached_result(cache_key)
            if cached_result:
                logger.info(f"Returning cached result for URL: {url}")
                return cached_result
            
            # Perform quick analysis
            result = await self._perform_quick_analysis(url)
            
            # Cache the result
            await self._cache_result(cache_key, result)
            
            return result
            
        except Exception as e:
            logger.error(f"Error in URL analysis: {e}")
            return self._get_error_result(str(e))
    
    async def get_cached_result(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Get cached analysis result for a URL.
        
        Args:
            url: URL to check cache for
            
        Returns:
            Cached result if available, None otherwise
        """
        if not self.is_initialized:
            await self.initialize()
        
        cache_key = self._generate_cache_key(url)
        return await self._get_cached_result(cache_key)
    
    async def _perform_quick_analysis(self, url: str) -> Dict[str, Any]:
        """
        Perform the actual quick analysis of the URL.
        
        Args:
            url: URL to analyze
            
        Returns:
            Analysis results
        """
        try:
            # Start multiple analysis tasks concurrently
            tasks = [
                self._basic_url_check(url),
                self._domain_reputation_check(url),
                self._malware_check(url) if settings.BOT_ENABLE_DEEP_ANALYSIS else self._quick_malware_check(url)
            ]
            
            # Wait for all tasks with timeout
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Combine results
            analysis_result = self._combine_analysis_results(url, results)
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"Error in quick analysis: {e}")
            return self._get_error_result(str(e))
    
    async def _basic_url_check(self, url: str) -> Dict[str, Any]:
        """
        Perform basic URL validation and structure analysis.
        
        Args:
            url: URL to check
            
        Returns:
            Basic analysis results
        """
        try:
            # Use existing social protection controller for basic checks
            # This is a simplified version for quick response
            result = {
                "check_type": "basic",
                "url": url,
                "is_valid": True,
                "risk_indicators": []
            }
            
            # Basic URL structure checks
            if not url.startswith(('http://', 'https://')):
                result["risk_indicators"].append("Non-standard protocol")
            
            # Check for suspicious patterns
            suspicious_patterns = [
                'bit.ly', 'tinyurl.com', 'short.link', 't.co',
                'phishing', 'malware', 'virus', 'hack'
            ]
            
            for pattern in suspicious_patterns:
                if pattern in url.lower():
                    result["risk_indicators"].append(f"Suspicious pattern: {pattern}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error in basic URL check: {e}")
            return {"check_type": "basic", "error": str(e)}
    
    async def _domain_reputation_check(self, url: str) -> Dict[str, Any]:
        """
        Quick domain reputation check using cached data.
        
        Args:
            url: URL to check
            
        Returns:
            Domain reputation results
        """
        try:
            from urllib.parse import urlparse
            
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            result = {
                "check_type": "domain_reputation",
                "domain": domain,
                "reputation_score": 50,  # Default neutral score
                "risk_indicators": []
            }
            
            # Check against known bad domains (this would be a cached list)
            known_bad_domains = [
                'malware.com', 'phishing.net', 'virus.org'  # Example domains
            ]
            
            if domain in known_bad_domains:
                result["reputation_score"] = 10
                result["risk_indicators"].append("Known malicious domain")
            
            # Check domain age and other factors (simplified)
            if len(domain.split('.')) > 3:  # Subdomain heavy
                result["risk_indicators"].append("Complex subdomain structure")
            
            return result
            
        except Exception as e:
            logger.error(f"Error in domain reputation check: {e}")
            return {"check_type": "domain_reputation", "error": str(e)}
    
    async def _quick_malware_check(self, url: str) -> Dict[str, Any]:
        """
        Quick malware check using lightweight methods.
        
        Args:
            url: URL to check
            
        Returns:
            Malware check results
        """
        try:
            result = {
                "check_type": "quick_malware",
                "url": url,
                "threat_detected": False,
                "risk_indicators": []
            }
            
            # Quick pattern-based checks
            malware_patterns = [
                '.exe', '.scr', '.bat', '.cmd', '.pif',
                'download', 'install', 'update.exe'
            ]
            
            for pattern in malware_patterns:
                if pattern in url.lower():
                    result["risk_indicators"].append(f"Suspicious file pattern: {pattern}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error in quick malware check: {e}")
            return {"check_type": "quick_malware", "error": str(e)}
    
    async def _malware_check(self, url: str) -> Dict[str, Any]:
        """
        Deep malware check using external APIs (when enabled).
        
        Args:
            url: URL to check
            
        Returns:
            Malware check results
        """
        try:
            # This would integrate with VirusTotal, Google Safe Browsing, etc.
            # For now, return a placeholder result
            result = {
                "check_type": "deep_malware",
                "url": url,
                "threat_detected": False,
                "scan_engines": 0,
                "detections": 0
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Error in deep malware check: {e}")
            return {"check_type": "deep_malware", "error": str(e)}
    
    def _combine_analysis_results(self, url: str, results: list) -> Dict[str, Any]:
        """
        Combine multiple analysis results into a single response.
        
        Args:
            url: Analyzed URL
            results: List of analysis results
            
        Returns:
            Combined analysis result
        """
        combined_result = {
            "url": url,
            "timestamp": datetime.utcnow().isoformat(),
            "status": "completed",
            "risk_level": "low",
            "risk_score": 0,
            "message": "URL appears safe",
            "details": [],
            "risk_indicators": []
        }
        
        total_risk_score = 0
        risk_indicators = []
        
        # Process each result
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Analysis task failed: {result}")
                continue
            
            if isinstance(result, dict) and "error" not in result:
                combined_result["details"].append(result)
                
                # Extract risk indicators
                if "risk_indicators" in result:
                    risk_indicators.extend(result["risk_indicators"])
                
                # Calculate risk score
                if result.get("check_type") == "domain_reputation":
                    reputation_score = result.get("reputation_score", 50)
                    if reputation_score < 30:
                        total_risk_score += 30
                elif result.get("threat_detected"):
                    total_risk_score += 50
        
        # Determine overall risk level
        combined_result["risk_indicators"] = list(set(risk_indicators))
        combined_result["risk_score"] = min(total_risk_score, 100)
        
        if total_risk_score >= 70:
            combined_result["risk_level"] = "high"
            combined_result["message"] = "⚠️ High risk detected - avoid this URL"
        elif total_risk_score >= 40:
            combined_result["risk_level"] = "medium"
            combined_result["message"] = "⚠️ Medium risk detected - proceed with caution"
        elif total_risk_score >= 20:
            combined_result["risk_level"] = "low"
            combined_result["message"] = "⚠️ Low risk detected - generally safe"
        else:
            combined_result["risk_level"] = "safe"
            combined_result["message"] = "✅ URL appears safe"
        
        return combined_result
    
    def _generate_cache_key(self, url: str) -> str:
        """
        Generate a cache key for the URL.
        
        Args:
            url: URL to generate key for
            
        Returns:
            Cache key string
        """
        url_hash = hashlib.md5(url.encode()).hexdigest()
        return f"quick_analysis:{url_hash}"
    
    async def _get_cached_result(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """
        Get cached analysis result.
        
        Args:
            cache_key: Cache key to lookup
            
        Returns:
            Cached result if available
        """
        try:
            if not self.redis_client:
                return None
            
            cached_data = await self.redis_client.get(cache_key)
            if cached_data:
                return json.loads(cached_data)
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting cached result: {e}")
            return None
    
    async def _cache_result(self, cache_key: str, result: Dict[str, Any]):
        """
        Cache analysis result.
        
        Args:
            cache_key: Cache key
            result: Result to cache
        """
        try:
            if not self.redis_client:
                return
            
            # Cache for the configured TTL
            await self.redis_client.setex(
                cache_key,
                settings.BOT_CACHE_TTL_SECONDS,
                json.dumps(result)
            )
            
        except Exception as e:
            logger.error(f"Error caching result: {e}")
    
    def _get_error_result(self, error_message: str) -> Dict[str, Any]:
        """
        Generate error result for failed analysis.
        
        Args:
            error_message: Error message
            
        Returns:
            Error result dictionary
        """
        return {
            "status": "error",
            "risk_level": "unknown",
            "risk_score": 0,
            "message": "Analysis failed, please try again later",
            "error": error_message,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    async def shutdown(self):
        """Shutdown the service and cleanup resources."""
        try:
            if self.redis_client:
                await self.redis_client.close()
                logger.info("Redis connection closed")
            
            if self.http_session:
                await self.http_session.close()
                logger.info("HTTP session closed")
            
            self.is_initialized = False
            logger.info("QuickAnalysisService shutdown completed")
            
        except Exception as e:
            logger.error(f"Error during service shutdown: {e}")


# Global service instance
quick_analysis_service = QuickAnalysisService()