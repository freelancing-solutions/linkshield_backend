"""
Comprehensive unit tests for ExtensionDataProcessor.

Tests cover:
- Extension request validation
- Real-time assessment
- Batch processing
- Link safety checks
- Caching functionality
- AI integration
- Error handling
- Metrics tracking
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime, timezone
from uuid import uuid4

from src.social_protection.services.extension_data_processor import (
    ExtensionDataProcessor,
    ValidationError,
    ProcessingError
)
from src.social_protection.data_models import (
    ExtensionScanPayload,
    ExtensionResponse,
    RealTimeAssessment,
    LinkSafetyCheck,
    BatchExtensionRequest,
    BatchExtensionResponse
)
from src.social_protection.types import PlatformType, RiskLevel
from src.models.social_protection import ContentType, AssessmentType


@pytest.fixture
def mock_ai_service():
    """Create a mock AI service."""
    ai_service = Mock()
    ai_service.analyze_content = AsyncMock()
    return ai_service


@pytest.fixture
def processor(mock_ai_service):
    """Create ExtensionDataProcessor with mocked AI service."""
    return ExtensionDataProcessor(ai_service=mock_ai_service)


@pytest.fixture
def processor_no_ai():
    """Create ExtensionDataProcessor without AI service."""
    return ExtensionDataProcessor(ai_service=None)


@pytest.fixture
def sample_request_data():
    """Create sample extension request data."""
    return {
        "request_id": str(uuid4()),
        "user_id": str(uuid4()),
        "platform": "twitter",
        "content_type": "post",
        "content": "This is a test post",
        "url": "https://example.com",
        "metadata": {"author": "test_user"}
    }


class TestRequestValidation:
    """Test extension request validation."""
    
    def test_validate_valid_request(self, processor, sample_request_data):
        """Test validation of valid request."""
        result = processor._validate_extension_request(sample_request_data)
        
        assert isinstance(result, ExtensionScanPayload)
        assert result.request_id == sample_request_data["request_id"]
        assert result.platform == PlatformType.TWITTER
        assert result.content_type == ContentType.POST
        assert result.content == sample_request_data["content"]
    
    def test_validate_missing_required_field(self, processor):
        """Test validation fails with missing required field."""
        invalid_data = {
            "request_id": str(uuid4()),
            "platform": "twitter"
            # Missing content_type and content
        }
        
        with pytest.raises(ValidationError) as exc_info:
            processor._validate_extension_request(invalid_data)
        
        assert "Missing required field" in str(exc_info.value)
    
    def test_validate_invalid_platform(self, processor, sample_request_data):
        """Test validation fails with invalid platform."""
        sample_request_data["platform"] = "invalid_platform"
        
        with pytest.raises(ValidationError) as exc_info:
            processor._validate_extension_request(sample_request_data)
        
        assert "Invalid platform" in str(exc_info.value)
    
    def test_validate_invalid_content_type(self, processor, sample_request_data):
        """Test validation fails with invalid content type."""
        sample_request_data["content_type"] = "invalid_type"
        
        with pytest.raises(ValidationError) as exc_info:
            processor._validate_extension_request(sample_request_data)
        
        assert "Invalid content type" in str(exc_info.value)
    
    def test_validate_optional_fields(self, processor):
        """Test validation with optional fields missing."""
        minimal_data = {
            "request_id": str(uuid4()),
            "platform": "twitter",
            "content_type": "post",
            "content": "Test content"
        }
        
        result = processor._validate_extension_request(minimal_data)
        
        assert isinstance(result, ExtensionScanPayload)
        assert result.user_id is None
        assert result.url is None
        assert result.metadata == {}


class TestBatchValidation:
    """Test batch request validation."""
    
    def test_validate_valid_batch(self, processor, sample_request_data):
        """Test validation of valid batch request."""
        batch_data = {
            "batch_id": str(uuid4()),
            "requests": [sample_request_data, sample_request_data.copy()]
        }
        
        result = processor._validate_batch_request(batch_data)
        
        assert isinstance(result, BatchExtensionRequest)
        assert result.batch_id == batch_data["batch_id"]
        assert len(result.requests) == 2
    
    def test_validate_batch_missing_batch_id(self, processor, sample_request_data):
        """Test batch validation fails without batch_id."""
        batch_data = {
            "requests": [sample_request_data]
        }
        
        with pytest.raises(ValidationError) as exc_info:
            processor._validate_batch_request(batch_data)
        
        assert "Missing batch_id" in str(exc_info.value)
    
    def test_validate_batch_empty_requests(self, processor):
        """Test batch validation fails with empty requests."""
        batch_data = {
            "batch_id": str(uuid4()),
            "requests": []
        }
        
        with pytest.raises(ValidationError) as exc_info:
            processor._validate_batch_request(batch_data)
        
        assert "Empty requests array" in str(exc_info.value)
    
    def test_validate_batch_exceeds_limit(self, processor, sample_request_data):
        """Test batch validation fails when exceeding size limit."""
        batch_data = {
            "batch_id": str(uuid4()),
            "requests": [sample_request_data.copy() for _ in range(101)]
        }
        
        with pytest.raises(ValidationError) as exc_info:
            processor._validate_batch_request(batch_data)
        
        assert "exceeds maximum limit" in str(exc_info.value)
    
    def test_validate_batch_invalid_request(self, processor, sample_request_data):
        """Test batch validation fails with invalid request in batch."""
        invalid_request = sample_request_data.copy()
        del invalid_request["content"]
        
        batch_data = {
            "batch_id": str(uuid4()),
            "requests": [sample_request_data, invalid_request]
        }
        
        with pytest.raises(ValidationError) as exc_info:
            processor._validate_batch_request(batch_data)
        
        assert "Request 1 validation failed" in str(exc_info.value)


class TestRealTimeAssessment:
    """Test real-time content assessment."""
    
    @pytest.mark.asyncio
    async def test_assessment_clean_content(self, processor_no_ai):
        """Test assessment of clean content without AI."""
        request = ExtensionScanPayload(
            request_id=str(uuid4()),
            platform=PlatformType.TWITTER,
            content_type=ContentType.POST,
            content="This is a normal professional post about technology.",
            timestamp=datetime.now(timezone.utc)
        )
        
        result = await processor_no_ai._perform_real_time_assessment(request)
        
        assert isinstance(result, RealTimeAssessment)
        assert result.risk_level == RiskLevel.LOW
        assert len(result.risk_factors) == 0
        assert result.confidence_score >= 0.5
    
    @pytest.mark.asyncio
    async def test_assessment_phishing_patterns(self, processor_no_ai):
        """Test assessment detects phishing patterns."""
        request = ExtensionScanPayload(
            request_id=str(uuid4()),
            platform=PlatformType.TWITTER,
            content_type=ContentType.POST,
            content="Verify your account immediately! Urgent action required!",
            timestamp=datetime.now(timezone.utc)
        )
        
        result = await processor_no_ai._perform_real_time_assessment(request)
        
        assert result.risk_level in [RiskLevel.MEDIUM, RiskLevel.HIGH]
        assert len(result.risk_factors) > 0
        assert any("phishing" in factor for factor in result.risk_factors)
    
    @pytest.mark.asyncio
    async def test_assessment_scam_patterns(self, processor_no_ai):
        """Test assessment detects scam patterns."""
        request = ExtensionScanPayload(
            request_id=str(uuid4()),
            platform=PlatformType.TWITTER,
            content_type=ContentType.POST,
            content="Make money fast! Guaranteed income! Work from home!",
            timestamp=datetime.now(timezone.utc)
        )
        
        result = await processor_no_ai._perform_real_time_assessment(request)
        
        assert result.risk_level in [RiskLevel.MEDIUM, RiskLevel.HIGH]
        assert len(result.risk_factors) > 0
        assert any("scam" in factor for factor in result.risk_factors)
    
    @pytest.mark.asyncio
    async def test_assessment_malware_patterns(self, processor_no_ai):
        """Test assessment detects malware patterns."""
        request = ExtensionScanPayload(
            request_id=str(uuid4()),
            platform=PlatformType.TWITTER,
            content_type=ContentType.POST,
            content="Download now! Free software! Install plugin required!",
            timestamp=datetime.now(timezone.utc)
        )
        
        result = await processor_no_ai._perform_real_time_assessment(request)
        
        assert result.risk_level in [RiskLevel.MEDIUM, RiskLevel.HIGH]
        assert len(result.risk_factors) > 0
        assert any("malware" in factor for factor in result.risk_factors)
    
    @pytest.mark.asyncio
    async def test_assessment_platform_specific_risks(self, processor_no_ai):
        """Test assessment detects platform-specific risks."""
        request = ExtensionScanPayload(
            request_id=str(uuid4()),
            platform=PlatformType.TWITTER,
            content_type=ContentType.POST,
            content="Account suspended! Verify account now!",
            timestamp=datetime.now(timezone.utc)
        )
        
        result = await processor_no_ai._perform_real_time_assessment(request)
        
        assert result.risk_level in [RiskLevel.MEDIUM, RiskLevel.HIGH]
        assert len(result.risk_factors) > 0
        assert any("platform_specific" in factor for factor in result.risk_factors)
    
    @pytest.mark.asyncio
    async def test_assessment_with_unsafe_url(self, processor_no_ai):
        """Test assessment with unsafe URL."""
        request = ExtensionScanPayload(
            request_id=str(uuid4()),
            platform=PlatformType.TWITTER,
            content_type=ContentType.POST,
            content="Check this out",
            url="http://192.168.1.1/malicious",
            timestamp=datetime.now(timezone.utc)
        )
        
        result = await processor_no_ai._perform_real_time_assessment(request)
        
        assert result.risk_level in [RiskLevel.MEDIUM, RiskLevel.HIGH]
        assert len(result.risk_factors) > 0
    
    @pytest.mark.asyncio
    async def test_assessment_multiple_risk_factors(self, processor_no_ai):
        """Test assessment with multiple risk factors triggers HIGH risk."""
        request = ExtensionScanPayload(
            request_id=str(uuid4()),
            platform=PlatformType.TWITTER,
            content_type=ContentType.POST,
            content="Verify account! Make money fast! Download now!",
            timestamp=datetime.now(timezone.utc)
        )
        
        result = await processor_no_ai._perform_real_time_assessment(request)
        
        assert result.risk_level == RiskLevel.HIGH
        assert len(result.risk_factors) >= 3
    
    @pytest.mark.asyncio
    async def test_assessment_with_ai_threat_detected(self, processor, mock_ai_service):
        """Test assessment with AI detecting threat."""
        mock_ai_service.analyze_content.return_value = {
            "threat_detected": True,
            "threat_types": ["phishing", "scam"],
            "confidence_score": 85
        }
        
        request = ExtensionScanPayload(
            request_id=str(uuid4()),
            platform=PlatformType.TWITTER,
            content_type=ContentType.POST,
            content="Test content",
            url="https://example.com",
            timestamp=datetime.now(timezone.utc)
        )
        
        result = await processor._perform_real_time_assessment(request)
        
        assert result.risk_level in [RiskLevel.MEDIUM, RiskLevel.HIGH]
        assert any("ai_detected" in factor for factor in result.risk_factors)
    
    @pytest.mark.asyncio
    async def test_assessment_with_ai_no_threat(self, processor, mock_ai_service):
        """Test assessment with AI detecting no threat."""
        mock_ai_service.analyze_content.return_value = {
            "threat_detected": False,
            "threat_types": [],
            "confidence_score": 10
        }
        
        request = ExtensionScanPayload(
            request_id=str(uuid4()),
            platform=PlatformType.TWITTER,
            content_type=ContentType.POST,
            content="Normal content",
            url="https://example.com",
            timestamp=datetime.now(timezone.utc)
        )
        
        result = await processor._perform_real_time_assessment(request)
        
        assert result.risk_level == RiskLevel.LOW
        assert "ai_analysis" in request.metadata
    
    @pytest.mark.asyncio
    async def test_assessment_ai_error_continues(self, processor, mock_ai_service):
        """Test assessment continues when AI fails."""
        mock_ai_service.analyze_content.side_effect = Exception("AI service error")
        
        request = ExtensionScanPayload(
            request_id=str(uuid4()),
            platform=PlatformType.TWITTER,
            content_type=ContentType.POST,
            content="Test content",
            url="https://example.com",
            timestamp=datetime.now(timezone.utc)
        )
        
        result = await processor._perform_real_time_assessment(request)
        
        # Should still return assessment based on pattern analysis
        assert isinstance(result, RealTimeAssessment)
        assert result.risk_level == RiskLevel.LOW


class TestLinkSafetyCheck:
    """Test link safety checking."""
    
    @pytest.mark.asyncio
    async def test_safe_link(self, processor_no_ai):
        """Test checking a safe link."""
        result = await processor_no_ai.check_link_safety(
            "https://example.com",
            PlatformType.TWITTER
        )
        
        assert isinstance(result, LinkSafetyCheck)
        assert result.is_safe is True
        assert result.risk_level == RiskLevel.LOW
        assert len(result.risk_factors) == 0
    
    @pytest.mark.asyncio
    async def test_suspicious_domain_pattern(self, processor_no_ai):
        """Test detection of suspicious domain patterns."""
        result = await processor_no_ai.check_link_safety(
            "https://twitter-support.malicious.com",
            PlatformType.TWITTER
        )
        
        assert result.is_safe is False
        assert result.risk_level == RiskLevel.HIGH
        assert len(result.risk_factors) > 0
        assert any("Suspicious domain" in factor for factor in result.risk_factors)
    
    @pytest.mark.asyncio
    async def test_ip_address_url(self, processor_no_ai):
        """Test detection of IP address URLs."""
        result = await processor_no_ai.check_link_safety(
            "http://192.168.1.1/path",
            PlatformType.TWITTER
        )
        
        assert result.is_safe is False
        assert result.risk_level == RiskLevel.MEDIUM
        assert any("IP address" in factor for factor in result.risk_factors)
    
    @pytest.mark.asyncio
    async def test_long_url_path(self, processor_no_ai):
        """Test detection of unusually long URL paths."""
        long_path = "a" * 250
        result = await processor_no_ai.check_link_safety(
            f"https://example.com/{long_path}",
            PlatformType.TWITTER
        )
        
        assert result.risk_level in [RiskLevel.MEDIUM, RiskLevel.HIGH]
        assert any("long URL path" in factor for factor in result.risk_factors)
    
    @pytest.mark.asyncio
    async def test_long_query_parameters(self, processor_no_ai):
        """Test detection of unusually long query parameters."""
        long_query = "param=" + "x" * 550
        result = await processor_no_ai.check_link_safety(
            f"https://example.com?{long_query}",
            PlatformType.TWITTER
        )
        
        assert result.risk_level in [RiskLevel.MEDIUM, RiskLevel.HIGH]
        assert any("long query" in factor for factor in result.risk_factors)
    
    @pytest.mark.asyncio
    async def test_link_check_error_handling(self, processor_no_ai):
        """Test link safety check error handling."""
        # Pass invalid URL to trigger error
        result = await processor_no_ai.check_link_safety(
            "not-a-valid-url",
            PlatformType.TWITTER
        )
        
        # Should return unsafe result on error
        assert result.is_safe is False
        assert result.risk_level == RiskLevel.HIGH


class TestCaching:
    """Test caching functionality."""
    
    @pytest.mark.asyncio
    async def test_cache_hit(self, processor_no_ai):
        """Test cache hit for identical content."""
        request = ExtensionScanPayload(
            request_id=str(uuid4()),
            platform=PlatformType.TWITTER,
            content_type=ContentType.POST,
            content="Test content for caching",
            timestamp=datetime.now(timezone.utc)
        )
        
        # First assessment - cache miss
        result1 = await processor_no_ai._perform_real_time_assessment(request)
        
        # Second assessment - should hit cache
        request.request_id = str(uuid4())  # Different request ID
        result2 = await processor_no_ai._perform_real_time_assessment(request)
        
        assert result1.risk_level == result2.risk_level
        assert result1.confidence_score == result2.confidence_score
    
    def test_cache_key_generation(self, processor_no_ai):
        """Test cache key generation."""
        key1 = processor_no_ai._generate_cache_key(
            "content",
            PlatformType.TWITTER,
            "https://example.com"
        )
        key2 = processor_no_ai._generate_cache_key(
            "content",
            PlatformType.TWITTER,
            "https://example.com"
        )
        key3 = processor_no_ai._generate_cache_key(
            "different",
            PlatformType.TWITTER,
            "https://example.com"
        )
        
        assert key1 == key2  # Same content should generate same key
        assert key1 != key3  # Different content should generate different key
    
    def test_cache_expiration(self, processor_no_ai):
        """Test cache entry expiration."""
        # Set short TTL for testing
        processor_no_ai._cache_ttl = 1
        
        cache_key = "test_key"
        assessment = Mock(spec=RealTimeAssessment)
        
        # Cache the assessment
        processor_no_ai._cache_assessment(cache_key, assessment)
        
        # Should be in cache immediately
        result = processor_no_ai._get_cached_assessment(cache_key)
        assert result is not None
        
        # Wait for expiration
        import time
        time.sleep(1.1)
        
        # Should be expired now
        result = processor_no_ai._get_cached_assessment(cache_key)
        assert result is None
    
    def test_cache_lru_eviction(self, processor_no_ai):
        """Test LRU eviction when cache is full."""
        # Set small cache size
        processor_no_ai._max_cache_size = 3
        
        # Fill cache
        for i in range(4):
            cache_key = f"key_{i}"
            assessment = Mock(spec=RealTimeAssessment)
            processor_no_ai._cache_assessment(cache_key, assessment)
        
        # Cache should not exceed max size
        assert len(processor_no_ai._cache) <= 3
        
        # Oldest entry should be evicted
        assert "key_0" not in processor_no_ai._cache
    
    def test_cache_stats(self, processor_no_ai):
        """Test cache statistics retrieval."""
        stats = processor_no_ai.get_cache_stats()
        
        assert "cache_size" in stats
        assert "max_cache_size" in stats
        assert "cache_ttl_seconds" in stats
        assert "utilization" in stats
        assert stats["max_cache_size"] == 1000
        assert stats["cache_ttl_seconds"] == 180


class TestProcessExtensionRequest:
    """Test main process_extension_request method."""
    
    @pytest.mark.asyncio
    async def test_process_valid_request(self, processor_no_ai, sample_request_data):
        """Test processing a valid extension request."""
        result = await processor_no_ai.process_extension_request(sample_request_data)
        
        assert isinstance(result, ExtensionResponse)
        assert result.success is True
        assert result.error_message is None
        assert result.assessment is not None
        assert result.processing_time_ms > 0
    
    @pytest.mark.asyncio
    async def test_process_invalid_request(self, processor_no_ai):
        """Test processing an invalid request."""
        invalid_data = {
            "request_id": str(uuid4())
            # Missing required fields
        }
        
        with pytest.raises(ValidationError):
            await processor_no_ai.process_extension_request(invalid_data)
    
    @pytest.mark.asyncio
    async def test_process_request_with_ai(self, processor, mock_ai_service, sample_request_data):
        """Test processing request with AI service."""
        mock_ai_service.analyze_content.return_value = {
            "threat_detected": False,
            "threat_types": [],
            "confidence_score": 10
        }
        
        result = await processor.process_extension_request(sample_request_data)
        
        assert result.success is True
        assert result.assessment is not None
        mock_ai_service.analyze_content.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_process_request_timeout(self, processor_no_ai, sample_request_data):
        """Test request processing timeout handling."""
        # Mock the assessment to take too long
        async def slow_assessment(*args, **kwargs):
            await asyncio.sleep(10)
            return Mock()
        
        with patch.object(processor_no_ai, '_perform_real_time_assessment', slow_assessment):
            with pytest.raises(ProcessingError) as exc_info:
                await processor_no_ai.process_extension_request(sample_request_data)
            
            assert "timed out" in str(exc_info.value).lower()


class TestBatchProcessing:
    """Test batch request processing."""
    
    @pytest.mark.asyncio
    async def test_process_batch_success(self, processor_no_ai, sample_request_data):
        """Test successful batch processing."""
        batch_data = {
            "batch_id": str(uuid4()),
            "requests": [
                sample_request_data,
                {**sample_request_data, "request_id": str(uuid4())},
                {**sample_request_data, "request_id": str(uuid4())}
            ]
        }
        
        result = await processor_no_ai.process_batch_request(batch_data)
        
        assert isinstance(result, BatchExtensionResponse)
        assert result.total_requests == 3
        assert result.successful_requests == 3
        assert result.failed_count == 0
        assert len(result.responses) == 3
    
    @pytest.mark.asyncio
    async def test_process_batch_partial_failure(self, processor_no_ai, sample_request_data):
        """Test batch processing with some failures."""
        invalid_request = sample_request_data.copy()
        invalid_request["content"] = None  # Will cause processing error
        
        batch_data = {
            "batch_id": str(uuid4()),
            "requests": [
                sample_request_data,
                invalid_request
            ]
        }
        
        # This should not raise, but handle the error gracefully
        result = await processor_no_ai.process_batch_request(batch_data)
        
        assert result.total_requests == 2
        # At least one should succeed
        assert result.successful_requests >= 1
    
    @pytest.mark.asyncio
    async def test_process_batch_concurrency_limit(self, processor_no_ai, sample_request_data):
        """Test batch processing respects concurrency limits."""
        # Create a large batch
        batch_data = {
            "batch_id": str(uuid4()),
            "requests": [
                {**sample_request_data, "request_id": str(uuid4())}
                for _ in range(20)
            ]
        }
        
        result = await processor_no_ai.process_batch_request(batch_data)
        
        assert result.total_requests == 20
        # Should process all successfully with concurrency control
        assert result.successful_requests == 20
    
    @pytest.mark.asyncio
    async def test_process_batch_timeout(self, processor_no_ai, sample_request_data):
        """Test batch processing timeout."""
        # Mock slow processing
        async def slow_process(*args, **kwargs):
            await asyncio.sleep(35)
            return Mock()
        
        batch_data = {
            "batch_id": str(uuid4()),
            "requests": [sample_request_data]
        }
        
        with patch.object(processor_no_ai, '_process_single_request_async', slow_process):
            with pytest.raises(ProcessingError) as exc_info:
                await processor_no_ai.process_batch_request(batch_data)
            
            assert "timed out" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_process_batch_invalid_batch(self, processor_no_ai):
        """Test batch processing with invalid batch data."""
        invalid_batch = {
            "batch_id": str(uuid4()),
            "requests": []  # Empty
        }
        
        with pytest.raises(ValidationError):
            await processor_no_ai.process_batch_request(invalid_batch)


class TestAIIntegration:
    """Test AI service integration."""
    
    @pytest.mark.asyncio
    async def test_ai_analysis_success(self, processor, mock_ai_service):
        """Test successful AI analysis."""
        mock_ai_service.analyze_content.return_value = {
            "threat_detected": True,
            "threat_types": ["phishing"],
            "confidence_score": 75
        }
        
        request = ExtensionScanPayload(
            request_id=str(uuid4()),
            platform=PlatformType.TWITTER,
            content_type=ContentType.POST,
            content="Test content",
            url="https://example.com",
            timestamp=datetime.now(timezone.utc)
        )
        
        result = await processor._perform_ai_analysis(request)
        
        assert result["threat_detected"] is True
        assert "phishing" in result["threat_types"]
        assert result["confidence_score"] == 75
    
    @pytest.mark.asyncio
    async def test_ai_analysis_error(self, processor, mock_ai_service):
        """Test AI analysis error handling."""
        mock_ai_service.analyze_content.side_effect = Exception("AI error")
        
        request = ExtensionScanPayload(
            request_id=str(uuid4()),
            platform=PlatformType.TWITTER,
            content_type=ContentType.POST,
            content="Test content",
            url="https://example.com",
            timestamp=datetime.now(timezone.utc)
        )
        
        result = await processor._perform_ai_analysis(request)
        
        assert result["threat_detected"] is False
        assert "error" in result
    
    def test_map_ai_threat_to_risk_level_high(self, processor_no_ai):
        """Test mapping high AI confidence to risk level."""
        risk_level = processor_no_ai._map_ai_threat_to_risk_level(85)
        assert risk_level == RiskLevel.HIGH
    
    def test_map_ai_threat_to_risk_level_medium(self, processor_no_ai):
        """Test mapping medium AI confidence to risk level."""
        risk_level = processor_no_ai._map_ai_threat_to_risk_level(60)
        assert risk_level == RiskLevel.MEDIUM
    
    def test_map_ai_threat_to_risk_level_low(self, processor_no_ai):
        """Test mapping low AI confidence to risk level."""
        risk_level = processor_no_ai._map_ai_threat_to_risk_level(30)
        assert risk_level == RiskLevel.LOW


class TestPlatformSpecificAnalysis:
    """Test platform-specific risk analysis."""
    
    @pytest.mark.asyncio
    async def test_twitter_specific_risks(self, processor_no_ai):
        """Test Twitter-specific risk detection."""
        request = ExtensionScanPayload(
            request_id=str(uuid4()),
            platform=PlatformType.TWITTER,
            content_type=ContentType.POST,
            content="Account suspended! Verify your account!",
            timestamp=datetime.now(timezone.utc)
        )
        
        result = await processor_no_ai._perform_real_time_assessment(request)
        
        assert len(result.risk_factors) > 0
        assert any("platform_specific" in factor for factor in result.risk_factors)
    
    @pytest.mark.asyncio
    async def test_facebook_specific_risks(self, processor_no_ai):
        """Test Facebook-specific risk detection."""
        request = ExtensionScanPayload(
            request_id=str(uuid4()),
            platform=PlatformType.META_FACEBOOK,
            content_type=ContentType.POST,
            content="Security alert! Account verification required!",
            timestamp=datetime.now(timezone.utc)
        )
        
        result = await processor_no_ai._perform_real_time_assessment(request)
        
        assert len(result.risk_factors) > 0
    
    @pytest.mark.asyncio
    async def test_instagram_specific_risks(self, processor_no_ai):
        """Test Instagram-specific risk detection."""
        request = ExtensionScanPayload(
            request_id=str(uuid4()),
            platform=PlatformType.META_INSTAGRAM,
            content_type=ContentType.POST,
            content="Copyright violation! Community guidelines!",
            timestamp=datetime.now(timezone.utc)
        )
        
        result = await processor_no_ai._perform_real_time_assessment(request)
        
        assert len(result.risk_factors) > 0
    
    @pytest.mark.asyncio
    async def test_linkedin_specific_risks(self, processor_no_ai):
        """Test LinkedIn-specific risk detection."""
        request = ExtensionScanPayload(
            request_id=str(uuid4()),
            platform=PlatformType.LINKEDIN,
            content_type=ContentType.POST,
            content="Profile verification required! Premium upgrade!",
            timestamp=datetime.now(timezone.utc)
        )
        
        result = await processor_no_ai._perform_real_time_assessment(request)
        
        assert len(result.risk_factors) > 0
    
    @pytest.mark.asyncio
    async def test_tiktok_specific_risks(self, processor_no_ai):
        """Test TikTok-specific risk detection."""
        request = ExtensionScanPayload(
            request_id=str(uuid4()),
            platform=PlatformType.TIKTOK,
            content_type=ContentType.POST,
            content="Content violation! Age verification required!",
            timestamp=datetime.now(timezone.utc)
        )
        
        result = await processor_no_ai._perform_real_time_assessment(request)
        
        assert len(result.risk_factors) > 0


class TestErrorHandling:
    """Test error handling and edge cases."""
    
    @pytest.mark.asyncio
    async def test_assessment_error_returns_safe_default(self, processor_no_ai):
        """Test that assessment errors return safe default."""
        # Create request that will cause an error in processing
        request = ExtensionScanPayload(
            request_id=str(uuid4()),
            platform=PlatformType.TWITTER,
            content_type=ContentType.POST,
            content=None,  # Invalid content
            timestamp=datetime.now(timezone.utc)
        )
        
        # Mock the pattern analysis to raise an error
        with patch.object(processor_no_ai, 'risk_patterns', side_effect=Exception("Test error")):
            result = await processor_no_ai._perform_real_time_assessment(request)
            
            # Should return high risk assessment on error
            assert result.risk_level == RiskLevel.HIGH
            assert result.confidence_score == 0.0
            assert len(result.risk_factors) > 0
    
    @pytest.mark.asyncio
    async def test_process_single_request_async_error(self, processor_no_ai):
        """Test error handling in async single request processing."""
        request = ExtensionScanPayload(
            request_id=str(uuid4()),
            platform=PlatformType.TWITTER,
            content_type=ContentType.POST,
            content="Test",
            timestamp=datetime.now(timezone.utc)
        )
        
        # Mock assessment to raise error
        with patch.object(processor_no_ai, '_perform_real_time_assessment', side_effect=Exception("Test error")):
            result = await processor_no_ai._process_single_request_async(request)
            
            assert result.success is False
            assert result.error_message is not None
            assert "Test error" in result.error_message
    
    def test_cleanup_expired_cache(self, processor_no_ai):
        """Test cleanup of expired cache entries."""
        # Set short TTL
        processor_no_ai._cache_ttl = 1
        
        # Add some entries
        for i in range(3):
            cache_key = f"key_{i}"
            assessment = Mock(spec=RealTimeAssessment)
            processor_no_ai._cache_assessment(cache_key, assessment)
        
        # Wait for expiration
        import time
        time.sleep(1.1)
        
        # Trigger cleanup
        processor_no_ai._cleanup_expired_cache()
        
        # All entries should be removed
        assert len(processor_no_ai._cache) == 0


class TestMetricsTracking:
    """Test metrics tracking functionality."""
    
    @pytest.mark.asyncio
    async def test_cache_metrics_updated(self, processor_no_ai):
        """Test that cache metrics are updated."""
        initial_hits = processor_no_ai._cache_hits
        initial_misses = processor_no_ai._cache_misses
        
        request = ExtensionScanPayload(
            request_id=str(uuid4()),
            platform=PlatformType.TWITTER,
            content_type=ContentType.POST,
            content="Test content",
            timestamp=datetime.now(timezone.utc)
        )
        
        # First call - cache miss
        await processor_no_ai._perform_real_time_assessment(request)
        assert processor_no_ai._cache_misses > initial_misses
        
        # Second call - cache hit
        request.request_id = str(uuid4())
        await processor_no_ai._perform_real_time_assessment(request)
        assert processor_no_ai._cache_hits > initial_hits


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
