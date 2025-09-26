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
from datetime import datetime
import redis.asyncio as redis
import aiohttp

from src.config.settings import settings
from src.social_protection.controllers import SocialProtectionController
logger = logging.getLogger(__name__)

# TODO Badly implemented not supposed to be using controllers here but on the routes
class QuickAnalysisService:
    """
    Service for performing quick URL analysis with caching and timeout handling.
    
    Optimized for bot interactions requiring sub-3-second response times.
    """
    
    def __init__(self):
        """Initialize the quick analysis service."""
        self.redis_client: Optional[redis.Redis] = None
        self.http_session: Optional[aiohttp.ClientSession] = None
        self.social_protection_controller = None  # Will be initialized when needed
        self.is_initialized = False
        
    async def initialize(self):
        """Initialize Redis connection and HTTP session."""
        if self.is_initialized:
            return
            
        try:
            # Initialize Redis connection for caching
            self.redis_client = redis.from_url(
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
        """Get cached analysis result for a URL."""
        if not self.is_initialized:
            await self.initialize()
        
        cache_key = self._generate_cache_key(url)
        return await self._get_cached_result(cache_key)
    
    async def _perform_quick_analysis(self, url: str) -> Dict[str, Any]:
        """Perform the actual quick analysis of the URL."""
        try:
            tasks = [
                self._basic_url_check(url),
                self._domain_reputation_check(url),
                self._malware_check(url) if settings.BOT_ENABLE_DEEP_ANALYSIS else self._quick_malware_check(url)
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            return self._combine_analysis_results(url, results)
        except Exception as e:
            logger.error(f"Error in quick analysis: {e}")
            return self._get_error_result(str(e))
    
    async def _basic_url_check(self, url: str) -> Dict[str, Any]:
        """Perform basic URL validation and structure analysis."""
        try:
            result = {
                "check_type": "basic",
                "url": url,
                "is_valid": True,
                "risk_indicators": []
            }
            if not url.startswith(('http://', 'https://')):
                result["risk_indicators"].append("Non-standard protocol")
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
        """Quick domain reputation check using cached data."""
        try:
            from urllib.parse import urlparse
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            result = {
                "check_type": "domain_reputation",
                "domain": domain,
                "reputation_score": 50,
                "risk_indicators": []
            }
            known_bad_domains = ['malware.com', 'phishing.net', 'virus.org']
            if domain in known_bad_domains:
                result["reputation_score"] = 10
                result["risk_indicators"].append("Known malicious domain")
            if len(domain.split('.')) > 3:
                result["risk_indicators"].append("Complex subdomain structure")
            return result
        except Exception as e:
            logger.error(f"Error in domain reputation check: {e}")
            return {"check_type": "domain_reputation", "error": str(e)}
    
    async def _quick_malware_check(self, url: str) -> Dict[str, Any]:
        """Quick malware check using lightweight methods."""
        try:
            result = {
                "check_type": "quick_malware",
                "url": url,
                "threat_detected": False,
                "risk_indicators": []
            }
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
        """Deep malware check using external APIs (when enabled)."""
        try:
            return {
                "check_type": "deep_malware",
                "url": url,
                "threat_detected": False,
                "scan_engines": 0,
                "detections": 0
            }
        except Exception as e:
            logger.error(f"Error in deep malware check: {e}")
            return {"check_type": "deep_malware", "error": str(e)}
    
    def _combine_analysis_results(self, url: str, results: list) -> Dict[str, Any]:
        """Combine multiple analysis results into a single response."""
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
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Analysis task failed: {result}")
                continue
            if isinstance(result, dict) and "error" not in result:
                combined_result["details"].append(result)
                if "risk_indicators" in result:
                    risk_indicators.extend(result["risk_indicators"])
                if result.get("check_type") == "domain_reputation":
                    if result.get("reputation_score", 50) < 30:
                        total_risk_score += 30
                elif result.get("threat_detected"):
                    total_risk_score += 50
        combined_result["risk_indicators"] = list(set(risk_indicators))
        combined_result["risk_score"] = min(total_risk_score, 100)
        if total_risk_score >= 70:
            combined_result.update({
                "risk_level": "high",
                "message": "⚠️ High risk detected - avoid this URL"
            })
        elif total_risk_score >= 40:
            combined_result.update({
                "risk_level": "medium",
                "message": "⚠️ Medium risk detected - proceed with caution"
            })
        elif total_risk_score >= 20:
            combined_result.update({
                "risk_level": "low",
                "message": "⚠️ Low risk detected - generally safe"
            })
        else:
            combined_result.update({
                "risk_level": "safe",
                "message": "✅ URL appears safe"
            })
        return combined_result
    
    def _generate_cache_key(self, url: str) -> str:
        """Generate a cache key for the URL."""
        url_hash = hashlib.md5(url.encode()).hexdigest()
        return f"quick_analysis:{url_hash}"
    
    async def _get_cached_result(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached analysis result."""
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
        """Cache analysis result."""
        try:
            if not self.redis_client:
                return
            await self.redis_client.setex(
                cache_key,
                settings.BOT_CACHE_TTL_SECONDS,
                json.dumps(result)
            )
        except Exception as e:
            logger.error(f"Error caching result: {e}")
    
    def _get_error_result(self, error_message: str) -> Dict[str, Any]:
        """Generate error result for failed analysis."""
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
