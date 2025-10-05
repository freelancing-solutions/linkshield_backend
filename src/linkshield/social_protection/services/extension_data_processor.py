#!/usr/bin/env python3
"""
LinkShield Backend Extension Data Processor

Service for processing and validating data received from browser extensions.
Handles real-time social media content analysis and risk assessment.
"""

import asyncio
import json
import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse
import re

from linkshield.social_protection.data_models import (
    ExtensionScanPayload,
    ExtensionResponse,
    RealTimeAssessment,
    FeedMonitoringData,
    LinkSafetyCheck,
    ExtensionSettings,
    ExtensionAnalytics,
    ExtensionHealthCheck,
    BatchExtensionRequest,
    BatchExtensionResponse
)
from linkshield.social_protection.types import (
    PlatformType,
    RiskLevel
)
from linkshield.models.social_protection import (
    ContentType,
    AssessmentType
)
from linkshield.social_protection.exceptions import (
    ExtensionProcessingError,
    DataValidationError,
    ServiceError,
    TimeoutError as SPTimeoutError
)
from linkshield.social_protection.logging_utils import get_logger
from linkshield.social_protection import metrics

logger = get_logger("ExtensionDataProcessor")


# Legacy exception classes for backward compatibility
class ExtensionDataProcessorError(ExtensionProcessingError):
    """Base exception for extension data processor errors."""
    pass


class ValidationError(DataValidationError):
    """Data validation error."""
    pass


class ProcessingError(ExtensionProcessingError):
    """Data processing error."""
    pass


class ExtensionDataProcessor:
    """
    Service for processing browser extension data and performing real-time analysis.
    
    This service handles:
    - Extension request validation
    - Real-time content analysis
    - Risk assessment processing
    - Batch processing for multiple requests
    - Extension health monitoring
    """
    
    def __init__(self, ai_service=None):
        """
        Initialize the extension data processor.
        
        Args:
            ai_service: Optional AIService instance for advanced content analysis
        """
        self.logger = logger
        self.ai_service = ai_service
        
        # In-memory cache with TTL for response caching
        self._cache = {}
        self._cache_timestamps = {}
        self._cache_ttl = 180  # 3 minutes TTL in seconds
        self._max_cache_size = 1000  # Maximum cache entries
        
        # Metrics tracking
        self._cache_hits = 0
        self._cache_misses = 0
        self._total_cache_operations = 0
        
        # Content analysis patterns for quick risk detection
        self.risk_patterns = {
            "phishing": [
                r"verify\s+your\s+account\s+immediately",
                r"suspended\s+account",
                r"click\s+here\s+to\s+confirm",
                r"urgent\s+action\s+required",
                r"limited\s+time\s+offer",
                r"congratulations.*winner",
                r"claim\s+your\s+prize"
            ],
            "scam": [
                r"make\s+money\s+fast",
                r"work\s+from\s+home",
                r"guaranteed\s+income",
                r"no\s+experience\s+required",
                r"investment\s+opportunity",
                r"double\s+your\s+money"
            ],
            "malware": [
                r"download\s+now",
                r"free\s+software",
                r"codec\s+required",
                r"update\s+flash\s+player",
                r"install\s+plugin"
            ]
        }
        
        # Platform-specific risk indicators
        self.platform_indicators = {
            PlatformType.META_FACEBOOK: {
                "suspicious_domains": ["fb-security", "facebook-help", "meta-support"],
                "risk_keywords": ["account verification", "security alert", "policy violation"]
            },
            PlatformType.TWITTER: {
                "suspicious_domains": ["twitter-support", "x-help", "twitter-security"],
                "risk_keywords": ["account suspended", "verify account", "policy update"]
            },
            PlatformType.META_INSTAGRAM: {
                "suspicious_domains": ["instagram-help", "ig-support", "meta-instagram"],
                "risk_keywords": ["copyright violation", "account review", "community guidelines"]
            },
            PlatformType.LINKEDIN: {
                "suspicious_domains": ["linkedin-support", "professional-network"],
                "risk_keywords": ["profile verification", "premium upgrade", "connection request"]
            },
            PlatformType.TIKTOK: {
                "suspicious_domains": ["tiktok-support", "bytedance-help"],
                "risk_keywords": ["content violation", "age verification", "creator fund"]
            }
        }
    
    async def process_extension_request(self, request_data: Dict[str, Any]) -> ExtensionResponse:
        """
        Process a single extension request and return assessment results.
        
        Args:
            request_data: Raw request data from browser extension
            
        Returns:
            ExtensionResponse: Processed response with risk assessment
            
        Raises:
            ValidationError: If request data is invalid
            ProcessingError: If processing fails
        """
        request_id = request_data.get("request_id", "unknown")
        start_time = time.time()
        
        # Track concurrent requests
        metrics.increment_concurrent_requests()
        
        try:
            self.logger.debug(f"Processing extension request {request_id}")
            
            # Validate and parse request
            extension_request = self._validate_extension_request(request_data)
            
            # Perform real-time assessment with timeout
            try:
                assessment = await asyncio.wait_for(
                    self._perform_real_time_assessment(extension_request),
                    timeout=5.0  # 5 second timeout for real-time processing
                )
            except asyncio.TimeoutError:
                self.logger.error(f"Assessment timeout for request {request_id}")
                metrics.record_timeout("process_extension_request")
                raise SPTimeoutError(
                    "Real-time assessment timed out",
                    details={"request_id": request_id, "timeout_seconds": 5}
                )
            
            # Generate response
            response = ExtensionResponse(
                request_id=extension_request.request_id,
                timestamp=datetime.now(timezone.utc),
                assessment=assessment,
                processing_time_ms=assessment.processing_time_ms,
                success=True,
                error_message=None
            )
            
            # Record metrics
            duration_seconds = time.time() - start_time
            metrics.record_request_processed(
                platform=extension_request.platform.value,
                content_type=extension_request.content_type.value,
                status="success",
                duration_seconds=duration_seconds
            )
            
            self.logger.info(
                f"Successfully processed extension request {extension_request.request_id}",
                extra={
                    "request_id": extension_request.request_id,
                    "platform": extension_request.platform.value,
                    "risk_level": assessment.risk_level.value,
                    "processing_time_ms": assessment.processing_time_ms
                }
            )
            return response
            
        except (ValidationError, DataValidationError) as e:
            metrics.record_error("validation_error", "process_extension_request")
            self.logger.error(
                f"Validation error for request {request_id}: {str(e)}",
                extra={"request_id": request_id, "error_type": type(e).__name__}
            )
            raise
        except SPTimeoutError as e:
            metrics.record_error("timeout_error", "process_extension_request")
            self.logger.error(
                f"Timeout error for request {request_id}: {str(e)}",
                extra={"request_id": request_id}
            )
            raise ProcessingError(f"Request processing timed out: {str(e)}")
        except Exception as e:
            metrics.record_error("unexpected_error", "process_extension_request")
            self.logger.error(
                f"Unexpected processing error for request {request_id}: {str(e)}",
                exc_info=True,
                extra={"request_id": request_id, "error_type": type(e).__name__}
            )
            raise ProcessingError(f"Failed to process extension request: {str(e)}")
        finally:
            # Always decrement concurrent requests counter
            metrics.decrement_concurrent_requests()
    
    async def process_batch_request(self, batch_data: Dict[str, Any]) -> BatchExtensionResponse:
        """
        Process multiple extension requests in batch with optimized concurrency.
        
        Uses semaphore-based concurrency control to prevent resource exhaustion
        and implements chunked processing for large batches.
        
        Args:
            batch_data: Batch request data containing multiple requests
            
        Returns:
            BatchExtensionResponse: Batch response with all assessments
        """
        batch_id = batch_data.get("batch_id", "unknown")
        start_time = time.time()
        
        try:
            self.logger.info(
                f"Processing batch request {batch_id}",
                extra={"batch_id": batch_id}
            )
            
            # Validate batch request
            batch_request = self._validate_batch_request(batch_data)
            batch_size = len(batch_request.requests)
            
            # Process requests with optimized concurrency
            successful_responses = []
            failed_requests = []
            
            # Use semaphore to limit concurrent processing
            max_concurrent = 10  # Process up to 10 requests concurrently
            semaphore = asyncio.Semaphore(max_concurrent)
            
            async def process_with_semaphore(request: ExtensionScanPayload) -> ExtensionResponse:
                """Process a single request with semaphore control."""
                async with semaphore:
                    return await self._process_single_request_async(request)
            
            # Create tasks with semaphore control
            tasks = [
                process_with_semaphore(request)
                for request in batch_request.requests
            ]
            
            # Wait for all tasks to complete with overall timeout
            try:
                responses = await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=30.0  # 30 second timeout for batch processing
                )
            except asyncio.TimeoutError:
                self.logger.error(
                    f"Batch processing timeout for batch {batch_id}",
                    extra={"batch_id": batch_id, "timeout_seconds": 30}
                )
                raise SPTimeoutError(
                    "Batch processing timed out",
                    details={"batch_id": batch_id, "timeout_seconds": 30}
                )
            
            # Separate successful responses from errors
            for i, response in enumerate(responses):
                if isinstance(response, Exception):
                    metrics.record_batch_item("failed")
                    self.logger.warning(
                        f"Request {batch_request.requests[i].request_id} in batch {batch_id} failed: {str(response)}",
                        extra={
                            "batch_id": batch_id,
                            "request_id": batch_request.requests[i].request_id,
                            "error_type": type(response).__name__
                        }
                    )
                    failed_requests.append({
                        "request_id": batch_request.requests[i].request_id,
                        "error": str(response),
                        "error_type": type(response).__name__
                    })
                else:
                    metrics.record_batch_item("success")
                    successful_responses.append(response)
            
            # Create batch response
            batch_response = BatchExtensionResponse(
                batch_id=batch_request.batch_id,
                timestamp=datetime.now(timezone.utc),
                responses=successful_responses,
                failed_requests=failed_requests,
                total_requests=len(batch_request.requests),
                successful_requests=len(successful_responses),
                failed_count=len(failed_requests)
            )
            
            # Record batch metrics
            duration_seconds = time.time() - start_time
            metrics.record_batch_processed(
                batch_size=batch_size,
                status="success",
                duration_seconds=duration_seconds
            )
            
            self.logger.info(
                f"Processed batch {batch_request.batch_id}: {len(successful_responses)}/{len(batch_request.requests)} successful",
                extra={
                    "batch_id": batch_request.batch_id,
                    "total_requests": len(batch_request.requests),
                    "successful": len(successful_responses),
                    "failed": len(failed_requests)
                }
            )
            return batch_response
            
        except (ValidationError, DataValidationError) as e:
            metrics.record_error("validation_error", "process_batch_request")
            self.logger.error(
                f"Batch validation error for batch {batch_id}: {str(e)}",
                extra={"batch_id": batch_id, "error_type": type(e).__name__}
            )
            raise
        except SPTimeoutError as e:
            metrics.record_timeout("process_batch_request")
            metrics.record_error("timeout_error", "process_batch_request")
            self.logger.error(
                f"Batch timeout error for batch {batch_id}: {str(e)}",
                extra={"batch_id": batch_id}
            )
            raise ProcessingError(f"Batch processing timed out: {str(e)}")
        except Exception as e:
            metrics.record_error("unexpected_error", "process_batch_request")
            self.logger.error(
                f"Unexpected batch processing error for batch {batch_id}: {str(e)}",
                exc_info=True,
                extra={"batch_id": batch_id, "error_type": type(e).__name__}
            )
            raise ProcessingError(f"Failed to process batch request: {str(e)}")
    
    async def check_link_safety(self, url: str, platform: PlatformType) -> LinkSafetyCheck:
        """
        Perform quick safety check on a URL.
        
        Args:
            url: URL to check
            platform: Social media platform context
            
        Returns:
            LinkSafetyCheck: Safety assessment results
        """
        start_time = datetime.now(timezone.utc)
        
        try:
            self.logger.debug(f"Checking link safety for {url} on platform {platform.value}")
            
            # Parse URL
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            # Initialize safety check
            is_safe = True
            risk_level = RiskLevel.LOW
            risk_factors = []
            
            # Check domain against platform-specific indicators
            if platform in self.platform_indicators:
                indicators = self.platform_indicators[platform]
                
                for suspicious_domain in indicators["suspicious_domains"]:
                    if suspicious_domain in domain:
                        is_safe = False
                        risk_level = RiskLevel.HIGH
                        risk_factors.append(f"Suspicious domain pattern: {suspicious_domain}")
            
            # Check for common malicious patterns
            if re.search(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', domain):
                is_safe = False
                risk_level = RiskLevel.MEDIUM
                risk_factors.append("IP address instead of domain name")
            
            # Check for suspicious URL patterns
            if len(parsed_url.path) > 200:
                risk_level = max(risk_level, RiskLevel.MEDIUM)
                risk_factors.append("Unusually long URL path")
            
            if parsed_url.query and len(parsed_url.query) > 500:
                risk_level = max(risk_level, RiskLevel.MEDIUM)
                risk_factors.append("Unusually long query parameters")
            
            # Calculate processing time
            processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            duration_seconds = processing_time / 1000.0
            
            # Record metrics
            metrics.record_link_check(
                platform=platform.value,
                is_safe=is_safe,
                duration_seconds=duration_seconds
            )
            
            return LinkSafetyCheck(
                url=url,
                is_safe=is_safe,
                risk_level=risk_level,
                risk_factors=risk_factors,
                platform=platform,
                checked_at=datetime.now(timezone.utc),
                processing_time_ms=int(processing_time)
            )
            
        except Exception as e:
            metrics.record_error("link_check_error", "check_link_safety")
            self.logger.error(f"Link safety check error for {url}: {str(e)}")
            return LinkSafetyCheck(
                url=url,
                is_safe=False,
                risk_level=RiskLevel.HIGH,
                risk_factors=[f"Error during safety check: {str(e)}"],
                platform=platform,
                checked_at=datetime.now(timezone.utc),
                processing_time_ms=0
            )
    
    def _validate_extension_request(self, request_data: Dict[str, Any]) -> ExtensionScanPayload:
        """
        Validate and parse extension request data.
        
        Args:
            request_data: Raw request data from extension
            
        Returns:
            ExtensionScanPayload: Validated request object
            
        Raises:
            ValidationError: If request data is invalid
        """
        try:
            # Check required fields
            required_fields = ["request_id", "platform", "content_type", "content"]
            for field in required_fields:
                if field not in request_data:
                    raise ValidationError(f"Missing required field: {field}")
            
            # Validate platform
            try:
                platform = PlatformType(request_data["platform"])
            except ValueError:
                raise ValidationError(f"Invalid platform: {request_data['platform']}")
            
            # Validate content type
            try:
                content_type = ContentType(request_data["content_type"])
            except ValueError:
                raise ValidationError(f"Invalid content type: {request_data['content_type']}")
            
            # Create ExtensionScanPayload object
            extension_request = ExtensionScanPayload(
                request_id=request_data["request_id"],
                user_id=request_data.get("user_id"),
                platform=platform,
                content_type=content_type,
                content=request_data["content"],
                url=request_data.get("url"),
                metadata=request_data.get("metadata", {}),
                timestamp=datetime.now(timezone.utc)
            )
            
            return extension_request
            
        except ValidationError:
            raise
        except Exception as e:
            raise ValidationError(f"Request validation failed: {str(e)}")
    
    def _validate_batch_request(self, batch_data: Dict[str, Any]) -> BatchExtensionRequest:
        """
        Validate batch request data.
        
        Args:
            batch_data: Raw batch request data
            
        Returns:
            BatchExtensionRequest: Validated batch request
            
        Raises:
            ValidationError: If validation fails
        """
        try:
            if "batch_id" not in batch_data:
                raise ValidationError("Missing batch_id")
            
            if "requests" not in batch_data or not isinstance(batch_data["requests"], list):
                raise ValidationError("Missing or invalid requests array")
            
            if len(batch_data["requests"]) == 0:
                raise ValidationError("Empty requests array")
            
            if len(batch_data["requests"]) > 100:  # Limit batch size
                raise ValidationError("Batch size exceeds maximum limit of 100")
            
            # Validate each request in the batch
            validated_requests = []
            for i, request_data in enumerate(batch_data["requests"]):
                try:
                    validated_request = self._validate_extension_request(request_data)
                    validated_requests.append(validated_request)
                except ValidationError as e:
                    raise ValidationError(f"Request {i} validation failed: {str(e)}")
            
            return BatchExtensionRequest(
                batch_id=batch_data["batch_id"],
                requests=validated_requests,
                timestamp=datetime.now(timezone.utc)
            )
            
        except ValidationError:
            raise
        except Exception as e:
            raise ValidationError(f"Batch validation failed: {str(e)}")
    
    async def _perform_real_time_assessment(self, request: ExtensionScanPayload) -> RealTimeAssessment:
        """
        Perform real-time risk assessment on extension request with AI integration.
        
        Args:
            request: Validated extension request
            
        Returns:
            RealTimeAssessment: Assessment results
        """
        start_time = datetime.now(timezone.utc)
        
        try:
            # Check cache first
            cache_key = self._generate_cache_key(request.content, request.platform, request.url)
            cached_assessment = self._get_cached_assessment(cache_key)
            
            if cached_assessment:
                # Record cache hit
                metrics.record_cache_operation("get", "hit")
                
                # Return cached result with updated request_id and timestamp
                cached_assessment.request_id = request.request_id
                cached_assessment.timestamp = datetime.now(timezone.utc)
                cached_assessment.assessment_id = f"rt_{request.request_id}_{int(datetime.now(timezone.utc).timestamp())}"
                
                # Add cache hit indicator to metadata
                if "metadata" not in request.metadata:
                    request.metadata["metadata"] = {}
                request.metadata["metadata"]["cache_hit"] = True
                
                return cached_assessment
            
            # Record cache miss
            metrics.record_cache_operation("get", "miss")
            
            # Initialize assessment
            risk_level = RiskLevel.LOW
            risk_factors = []
            confidence_score = 0.5
            
            # Analyze content for risk patterns
            content_lower = request.content.lower()
            
            for risk_type, patterns in self.risk_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, content_lower, re.IGNORECASE):
                        risk_factors.append(f"{risk_type}_pattern_detected")
                        risk_level = max(risk_level, RiskLevel.MEDIUM)
                        confidence_score += 0.2
                        # Record pattern match
                        metrics.record_content_pattern_match(
                            platform=request.platform.value,
                            pattern_type=risk_type
                        )
            
            # Platform-specific analysis
            if request.platform in self.platform_indicators:
                indicators = self.platform_indicators[request.platform]
                
                for keyword in indicators["risk_keywords"]:
                    if keyword.lower() in content_lower:
                        risk_factors.append(f"platform_specific_risk_{keyword.replace(' ', '_')}")
                        risk_level = max(risk_level, RiskLevel.MEDIUM)
                        confidence_score += 0.15
                        # Record platform indicator match
                        metrics.record_platform_indicator_match(
                            platform=request.platform.value,
                            indicator_type="risk_keyword"
                        )
            
            # URL analysis if provided
            if request.url:
                link_check = await self.check_link_safety(request.url, request.platform)
                if not link_check.is_safe:
                    risk_level = max(risk_level, link_check.risk_level)
                    risk_factors.extend(link_check.risk_factors)
                    confidence_score += 0.3
            
            # AI-powered comprehensive analysis if available
            if self.ai_service:
                try:
                    ai_analysis = await self._perform_ai_analysis(request)
                    
                    # Integrate AI results
                    if ai_analysis.get("threat_detected"):
                        ai_risk_level = self._map_ai_threat_to_risk_level(
                            ai_analysis.get("confidence_score", 0)
                        )
                        risk_level = max(risk_level, ai_risk_level)
                        
                        # Add AI-detected threat types to risk factors
                        for threat_type in ai_analysis.get("threat_types", []):
                            risk_factors.append(f"ai_detected_{threat_type}")
                        
                        # Boost confidence with AI analysis
                        ai_confidence = ai_analysis.get("confidence_score", 0) / 100.0
                        confidence_score = min(1.0, confidence_score * 0.4 + ai_confidence * 0.6)
                    
                    # Add AI analysis details to metadata
                    request.metadata["ai_analysis"] = {
                        "threat_detected": ai_analysis.get("threat_detected"),
                        "threat_types": ai_analysis.get("threat_types", []),
                        "confidence": ai_analysis.get("confidence_score", 0)
                    }
                    
                except Exception as e:
                    self.logger.warning(
                        f"AI analysis failed for request {request.request_id}: {str(e)}",
                        extra={"request_id": request.request_id}
                    )
                    # Continue with pattern-based analysis
            
            # Adjust confidence score
            confidence_score = min(confidence_score, 1.0)
            
            # Determine final risk level based on factors
            if len(risk_factors) >= 3:
                risk_level = RiskLevel.HIGH
            elif len(risk_factors) >= 1:
                risk_level = RiskLevel.MEDIUM
            
            # Calculate processing time
            processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            
            assessment = RealTimeAssessment(
                assessment_id=f"rt_{request.request_id}_{int(datetime.now(timezone.utc).timestamp())}",
                request_id=request.request_id,
                platform=request.platform,
                content_type=request.content_type,
                risk_level=risk_level,
                confidence_score=confidence_score,
                risk_factors=risk_factors,
                assessment_type=AssessmentType.REAL_TIME,
                timestamp=datetime.now(timezone.utc),
                processing_time_ms=int(processing_time)
            )
            
            # Record risk assessment metrics
            metrics.record_risk_assessment(
                platform=request.platform.value,
                risk_level=risk_level.value,
                confidence_score=confidence_score
            )
            
            # Record individual risk factors
            for risk_factor in risk_factors:
                # Extract risk type from factor string
                risk_type = risk_factor.split('_')[0] if '_' in risk_factor else risk_factor
                metrics.record_risk_factor(
                    platform=request.platform.value,
                    risk_type=risk_type
                )
            
            # Cache the assessment for future requests
            self._cache_assessment(cache_key, assessment)
            
            return assessment
            
        except Exception as e:
            self.logger.error(f"Real-time assessment error: {str(e)}")
            processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            
            return RealTimeAssessment(
                assessment_id=f"rt_error_{request.request_id}",
                request_id=request.request_id,
                platform=request.platform,
                content_type=request.content_type,
                risk_level=RiskLevel.HIGH,
                confidence_score=0.0,
                risk_factors=[f"Assessment error: {str(e)}"],
                assessment_type=AssessmentType.REAL_TIME,
                timestamp=datetime.now(timezone.utc),
                processing_time_ms=int(processing_time)
            )
    
    async def _perform_ai_analysis(self, request: ExtensionScanPayload) -> Dict[str, Any]:
        """
        Perform AI-powered content analysis.
        
        Args:
            request: Extension request with content to analyze
            
        Returns:
            Dict containing AI analysis results
        """
        ai_start_time = time.time()
        
        try:
            # Use AI service for comprehensive content analysis
            url = request.url or "https://example.com"
            analysis_result = await self.ai_service.analyze_content(
                content=request.content,
                url=url
            )
            
            # Record AI analysis metrics
            ai_duration = time.time() - ai_start_time
            metrics.record_ai_analysis(
                platform=request.platform.value,
                status="success",
                duration_seconds=ai_duration,
                threat_types=analysis_result.get("threat_types", [])
            )
            
            return analysis_result
            
        except Exception as e:
            # Record AI analysis failure
            ai_duration = time.time() - ai_start_time
            metrics.record_ai_analysis(
                platform=request.platform.value,
                status="error",
                duration_seconds=ai_duration
            )
            
            self.logger.error(
                f"AI analysis error: {str(e)}",
                extra={"request_id": request.request_id}
            )
            return {
                "threat_detected": False,
                "threat_types": [],
                "confidence_score": 0,
                "error": str(e)
            }
    
    def _map_ai_threat_to_risk_level(self, confidence_score: int) -> RiskLevel:
        """
        Map AI threat confidence score to risk level.
        
        Args:
            confidence_score: AI confidence score (0-100)
            
        Returns:
            RiskLevel enum value
        """
        if confidence_score >= 80:
            return RiskLevel.HIGH
        elif confidence_score >= 50:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    async def _process_single_request_async(self, request: ExtensionScanPayload) -> ExtensionResponse:
        """
        Process a single request asynchronously for batch processing.
        
        Args:
            request: Extension request to process
            
        Returns:
            ExtensionResponse: Processing result
        """
        try:
            assessment = await self._perform_real_time_assessment(request)
            
            return ExtensionResponse(
                request_id=request.request_id,
                timestamp=datetime.now(timezone.utc),
                assessment=assessment,
                processing_time_ms=assessment.processing_time_ms,
                success=True,
                error_message=None
            )
            
        except Exception as e:
            return ExtensionResponse(
                request_id=request.request_id,
                timestamp=datetime.now(timezone.utc),
                assessment=None,
                processing_time_ms=0,
                success=False,
                error_message=str(e)
            )
    
    def _generate_cache_key(self, content: str, platform: PlatformType, url: Optional[str] = None) -> str:
        """
        Generate a cache key for content analysis.
        
        Args:
            content: Content to analyze
            platform: Platform type
            url: Optional URL
            
        Returns:
            Cache key string
        """
        import hashlib
        
        # Create a hash of the content and context
        content_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()[:16]
        url_part = hashlib.sha256(url.encode('utf-8')).hexdigest()[:8] if url else "nourl"
        
        return f"ext:{platform.value}:{content_hash}:{url_part}"
    
    def _get_cached_assessment(self, cache_key: str) -> Optional[RealTimeAssessment]:
        """
        Retrieve cached assessment if available and not expired.
        
        Args:
            cache_key: Cache key to lookup
            
        Returns:
            Cached assessment or None if not found/expired
        """
        # Clean up expired entries periodically
        self._cleanup_expired_cache()
        
        self._total_cache_operations += 1
        
        if cache_key in self._cache:
            timestamp = self._cache_timestamps.get(cache_key)
            if timestamp:
                age = (datetime.now(timezone.utc) - timestamp).total_seconds()
                if age < self._cache_ttl:
                    self._cache_hits += 1
                    self._update_cache_metrics()
                    
                    self.logger.debug(
                        f"Cache hit for key {cache_key}",
                        extra={"cache_key": cache_key, "age_seconds": age}
                    )
                    return self._cache[cache_key]
                else:
                    # Expired, remove from cache
                    del self._cache[cache_key]
                    del self._cache_timestamps[cache_key]
        
        self._cache_misses += 1
        self._update_cache_metrics()
        return None
    
    def _cache_assessment(self, cache_key: str, assessment: RealTimeAssessment) -> None:
        """
        Cache an assessment result.
        
        Args:
            cache_key: Cache key
            assessment: Assessment to cache
        """
        # Record cache set operation
        metrics.record_cache_operation("set", "success")
        
        # Enforce max cache size with LRU eviction
        if len(self._cache) >= self._max_cache_size:
            # Remove oldest entry
            oldest_key = min(self._cache_timestamps.keys(), 
                           key=lambda k: self._cache_timestamps[k])
            del self._cache[oldest_key]
            del self._cache_timestamps[oldest_key]
        
        self._cache[cache_key] = assessment
        self._cache_timestamps[cache_key] = datetime.now(timezone.utc)
        
        # Update cache size metric
        self._update_cache_metrics()
        
        self.logger.debug(
            f"Cached assessment for key {cache_key}",
            extra={"cache_key": cache_key, "cache_size": len(self._cache)}
        )
    
    def _cleanup_expired_cache(self) -> None:
        """Clean up expired cache entries."""
        now = datetime.now(timezone.utc)
        expired_keys = []
        
        for key, timestamp in self._cache_timestamps.items():
            age = (now - timestamp).total_seconds()
            if age >= self._cache_ttl:
                expired_keys.append(key)
        
        for key in expired_keys:
            del self._cache[key]
            del self._cache_timestamps[key]
        
        if expired_keys:
            # Record cache evictions
            for _ in expired_keys:
                metrics.record_cache_operation("evict", "expired")
            
            self.logger.debug(
                f"Cleaned up {len(expired_keys)} expired cache entries",
                extra={"expired_count": len(expired_keys)}
            )
    
    def _update_cache_metrics(self) -> None:
        """Update cache metrics."""
        cache_size = len(self._cache)
        hit_rate = (
            self._cache_hits / self._total_cache_operations
            if self._total_cache_operations > 0
            else 0.0
        )
        
        metrics.update_cache_metrics(cache_size=cache_size, hit_rate=hit_rate)     
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dictionary with cache statistics
        """
        return {
            "cache_size": len(self._cache),
            "max_cache_size": self._max_cache_size,
            "cache_ttl_seconds": self._cache_ttl,
            "utilization": len(self._cache) / self._max_cache_size if self._max_cache_size > 0 else 0
        }