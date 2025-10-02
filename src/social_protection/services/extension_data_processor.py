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

from src.social_protection.data_models import (
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
from src.social_protection.types import (
    PlatformType,
    RiskLevel
)
from src.models.social_protection import (
    ContentType,
    AssessmentType
)
from src.social_protection.exceptions import (
    ExtensionProcessingError,
    DataValidationError,
    ServiceError,
    TimeoutError as SPTimeoutError
)
from src.social_protection.logging_utils import get_logger

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
    
    def __init__(self):
        """Initialize the extension data processor."""
        self.logger = logging.getLogger(__name__)
        
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
            PlatformType.FACEBOOK: {
                "suspicious_domains": ["fb-security", "facebook-help", "meta-support"],
                "risk_keywords": ["account verification", "security alert", "policy violation"]
            },
            PlatformType.TWITTER: {
                "suspicious_domains": ["twitter-support", "x-help", "twitter-security"],
                "risk_keywords": ["account suspended", "verify account", "policy update"]
            },
            PlatformType.INSTAGRAM: {
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
            self.logger.error(
                f"Validation error for request {request_id}: {str(e)}",
                extra={"request_id": request_id, "error_type": type(e).__name__}
            )
            raise
        except SPTimeoutError as e:
            self.logger.error(
                f"Timeout error for request {request_id}: {str(e)}",
                extra={"request_id": request_id}
            )
            raise ProcessingError(f"Request processing timed out: {str(e)}")
        except Exception as e:
            self.logger.error(
                f"Unexpected processing error for request {request_id}: {str(e)}",
                exc_info=True,
                extra={"request_id": request_id, "error_type": type(e).__name__}
            )
            raise ProcessingError(f"Failed to process extension request: {str(e)}")
    
    async def process_batch_request(self, batch_data: Dict[str, Any]) -> BatchExtensionResponse:
        """
        Process multiple extension requests in batch.
        
        Args:
            batch_data: Batch request data containing multiple requests
            
        Returns:
            BatchExtensionResponse: Batch response with all assessments
        """
        batch_id = batch_data.get("batch_id", "unknown")
        
        try:
            self.logger.info(f"Processing batch request {batch_id}")
            
            # Validate batch request
            batch_request = self._validate_batch_request(batch_data)
            
            # Process requests concurrently with timeout
            tasks = []
            for request in batch_request.requests:
                task = self._process_single_request_async(request)
                tasks.append(task)
            
            # Wait for all tasks to complete with overall timeout
            try:
                responses = await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=30.0  # 30 second timeout for batch processing
                )
            except asyncio.TimeoutError:
                self.logger.error(f"Batch processing timeout for batch {batch_id}")
                raise SPTimeoutError(
                    "Batch processing timed out",
                    details={"batch_id": batch_id, "timeout_seconds": 30}
                )
            
            # Separate successful responses from errors
            successful_responses = []
            failed_requests = []
            
            for i, response in enumerate(responses):
                if isinstance(response, Exception):
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
            self.logger.error(
                f"Batch validation error for batch {batch_id}: {str(e)}",
                extra={"batch_id": batch_id, "error_type": type(e).__name__}
            )
            raise
        except SPTimeoutError as e:
            self.logger.error(
                f"Batch timeout error for batch {batch_id}: {str(e)}",
                extra={"batch_id": batch_id}
            )
            raise ProcessingError(f"Batch processing timed out: {str(e)}")
        except Exception as e:
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
        Perform real-time risk assessment on extension request.
        
        Args:
            request: Validated extension request
            
        Returns:
            RealTimeAssessment: Assessment results
        """
        start_time = datetime.now(timezone.utc)
        
        try:
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
            
            # Platform-specific analysis
            if request.platform in self.platform_indicators:
                indicators = self.platform_indicators[request.platform]
                
                for keyword in indicators["risk_keywords"]:
                    if keyword.lower() in content_lower:
                        risk_factors.append(f"platform_specific_risk_{keyword.replace(' ', '_')}")
                        risk_level = max(risk_level, RiskLevel.MEDIUM)
                        confidence_score += 0.15
            
            # URL analysis if provided
            if request.url:
                link_check = await self.check_link_safety(request.url, request.platform)
                if not link_check.is_safe:
                    risk_level = max(risk_level, link_check.risk_level)
                    risk_factors.extend(link_check.risk_factors)
                    confidence_score += 0.3
            
            # Adjust confidence score
            confidence_score = min(confidence_score, 1.0)
            
            # Determine final risk level based on factors
            if len(risk_factors) >= 3:
                risk_level = RiskLevel.HIGH
            elif len(risk_factors) >= 1:
                risk_level = RiskLevel.MEDIUM
            
            # Calculate processing time
            processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            
            return RealTimeAssessment(
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