#!/usr/bin/env python3
"""
Tests for Extension Data Processor Telemetry

Verifies that metrics are properly collected during extension data processing.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime, timezone

from linkshield.social_protection.services.extension_data_processor import ExtensionDataProcessor
from linkshield.social_protection.types import PlatformType, RiskLevel
from linkshield.models.social_protection import ContentType
from linkshield.social_protection import metrics


@pytest.fixture
def processor():
    """Create an ExtensionDataProcessor instance for testing."""
    return ExtensionDataProcessor(ai_service=None)


@pytest.fixture
def sample_request():
    """Create a sample extension request."""
    return {
        "request_id": "test-123",
        "platform": "twitter",
        "content_type": "post",
        "content": "Check out this amazing offer! Click here to claim your prize!",
        "url": "https://suspicious-site.com/offer",
        "metadata": {}
    }


@pytest.mark.asyncio
async def test_metrics_recorded_on_successful_request(processor, sample_request):
    """Test that metrics are recorded when processing a successful request."""
    
    with patch.object(metrics, 'record_request_processed') as mock_record:
        with patch.object(metrics, 'increment_concurrent_requests'):
            with patch.object(metrics, 'decrement_concurrent_requests'):
                response = await processor.process_extension_request(sample_request)
                
                assert response.success is True
                # Verify metrics were recorded
                mock_record.assert_called_once()
                call_args = mock_record.call_args
                assert call_args[1]['platform'] == 'twitter'
                assert call_args[1]['content_type'] == 'post'
                assert call_args[1]['status'] == 'success'
                assert call_args[1]['duration_seconds'] > 0


@pytest.mark.asyncio
async def test_metrics_recorded_on_cache_hit(processor, sample_request):
    """Test that cache metrics are recorded on cache hits."""
    
    with patch.object(metrics, 'record_cache_operation') as mock_cache_op:
        with patch.object(metrics, 'increment_concurrent_requests'):
            with patch.object(metrics, 'decrement_concurrent_requests'):
                with patch.object(metrics, 'record_request_processed'):
                    # First request - cache miss
                    await processor.process_extension_request(sample_request)
                    
                    # Second request - should be cache hit
                    await processor.process_extension_request(sample_request)
                    
                    # Verify cache operations were recorded
                    assert mock_cache_op.call_count >= 2
                    # Check for cache hit
                    cache_calls = [call for call in mock_cache_op.call_args_list 
                                 if call[0] == ('get', 'hit')]
                    assert len(cache_calls) > 0


@pytest.mark.asyncio
async def test_metrics_recorded_on_risk_assessment(processor, sample_request):
    """Test that risk assessment metrics are recorded."""
    
    with patch.object(metrics, 'record_risk_assessment') as mock_risk:
        with patch.object(metrics, 'increment_concurrent_requests'):
            with patch.object(metrics, 'decrement_concurrent_requests'):
                with patch.object(metrics, 'record_request_processed'):
                    response = await processor.process_extension_request(sample_request)
                    
                    # Verify risk assessment metrics were recorded
                    mock_risk.assert_called_once()
                    call_args = mock_risk.call_args
                    assert call_args[1]['platform'] == 'twitter'
                    assert 'risk_level' in call_args[1]
                    assert 'confidence_score' in call_args[1]


@pytest.mark.asyncio
async def test_metrics_recorded_on_pattern_match(processor, sample_request):
    """Test that pattern match metrics are recorded."""
    
    with patch.object(metrics, 'record_content_pattern_match') as mock_pattern:
        with patch.object(metrics, 'increment_concurrent_requests'):
            with patch.object(metrics, 'decrement_concurrent_requests'):
                with patch.object(metrics, 'record_request_processed'):
                    with patch.object(metrics, 'record_risk_assessment'):
                        response = await processor.process_extension_request(sample_request)
                        
                        # Verify pattern matches were recorded
                        # The sample request contains phishing patterns
                        assert mock_pattern.call_count > 0


@pytest.mark.asyncio
async def test_metrics_recorded_on_link_check(processor):
    """Test that link check metrics are recorded."""
    
    with patch.object(metrics, 'record_link_check') as mock_link:
        await processor.check_link_safety(
            "https://suspicious-site.com",
            PlatformType.TWITTER
        )
        
        # Verify link check metrics were recorded
        mock_link.assert_called_once()
        call_args = mock_link.call_args
        assert call_args[1]['platform'] == 'twitter'
        assert 'is_safe' in call_args[1]
        assert 'duration_seconds' in call_args[1]


@pytest.mark.asyncio
async def test_metrics_recorded_on_batch_processing(processor):
    """Test that batch processing metrics are recorded."""
    
    batch_request = {
        "batch_id": "batch-123",
        "requests": [
            {
                "request_id": f"req-{i}",
                "platform": "twitter",
                "content_type": "post",
                "content": f"Test content {i}",
                "metadata": {}
            }
            for i in range(5)
        ]
    }
    
    with patch.object(metrics, 'record_batch_processed') as mock_batch:
        with patch.object(metrics, 'record_batch_item'):
            response = await processor.process_batch_request(batch_request)
            
            # Verify batch metrics were recorded
            mock_batch.assert_called_once()
            call_args = mock_batch.call_args
            assert call_args[1]['batch_size'] == 5
            assert call_args[1]['status'] == 'success'
            assert call_args[1]['duration_seconds'] > 0


@pytest.mark.asyncio
async def test_metrics_recorded_on_error(processor):
    """Test that error metrics are recorded on failures."""
    
    invalid_request = {
        "request_id": "test-error",
        # Missing required fields
    }
    
    with patch.object(metrics, 'record_error') as mock_error:
        with pytest.raises(Exception):
            await processor.process_extension_request(invalid_request)
        
        # Verify error metrics were recorded
        assert mock_error.call_count > 0


@pytest.mark.asyncio
async def test_concurrent_requests_tracked(processor, sample_request):
    """Test that concurrent requests are tracked."""
    
    with patch.object(metrics, 'increment_concurrent_requests') as mock_inc:
        with patch.object(metrics, 'decrement_concurrent_requests') as mock_dec:
            with patch.object(metrics, 'record_request_processed'):
                await processor.process_extension_request(sample_request)
                
                # Verify concurrent request tracking
                mock_inc.assert_called_once()
                mock_dec.assert_called_once()


@pytest.mark.asyncio
async def test_cache_metrics_updated(processor, sample_request):
    """Test that cache metrics are updated."""
    
    with patch.object(metrics, 'update_cache_metrics') as mock_update:
        with patch.object(metrics, 'increment_concurrent_requests'):
            with patch.object(metrics, 'decrement_concurrent_requests'):
                with patch.object(metrics, 'record_request_processed'):
                    await processor.process_extension_request(sample_request)
                    
                    # Verify cache metrics were updated
                    assert mock_update.call_count > 0
                    call_args = mock_update.call_args
                    assert 'cache_size' in call_args[1]
                    assert 'hit_rate' in call_args[1]


def test_cache_stats_available(processor):
    """Test that cache statistics are available."""
    
    stats = processor.get_cache_stats()
    
    assert 'cache_size' in stats
    assert 'max_cache_size' in stats
    assert 'cache_ttl_seconds' in stats
    assert 'utilization' in stats
    assert stats['max_cache_size'] == 1000
    assert stats['cache_ttl_seconds'] == 180
