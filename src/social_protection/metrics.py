#!/usr/bin/env python3
"""
Social Protection Metrics Collection

Prometheus metrics for monitoring social protection services.
"""

from prometheus_client import Counter, Histogram, Gauge, Info
from typing import Optional


# Extension Data Processor Metrics

# Request counters
extension_requests_total = Counter(
    'social_protection_extension_requests_total',
    'Total extension requests processed',
    ['platform', 'content_type', 'status']
)

extension_batch_requests_total = Counter(
    'social_protection_extension_batch_requests_total',
    'Total batch requests processed',
    ['status']
)

# Processing time histograms
extension_processing_duration_seconds = Histogram(
    'social_protection_extension_processing_duration_seconds',
    'Extension request processing duration in seconds',
    ['platform', 'content_type'],
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
)

extension_batch_processing_duration_seconds = Histogram(
    'social_protection_extension_batch_processing_duration_seconds',
    'Batch request processing duration in seconds',
    ['batch_size_range'],
    buckets=(0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0)
)

# Risk assessment metrics
extension_risk_assessments_total = Counter(
    'social_protection_extension_risk_assessments_total',
    'Total risk assessments performed',
    ['platform', 'risk_level']
)

extension_risk_factors_detected_total = Counter(
    'social_protection_extension_risk_factors_detected_total',
    'Total risk factors detected',
    ['platform', 'risk_type']
)

# AI analysis metrics
extension_ai_analysis_total = Counter(
    'social_protection_extension_ai_analysis_total',
    'Total AI analyses performed',
    ['platform', 'status']
)

extension_ai_analysis_duration_seconds = Histogram(
    'social_protection_extension_ai_analysis_duration_seconds',
    'AI analysis duration in seconds',
    ['platform'],
    buckets=(0.1, 0.5, 1.0, 2.0, 5.0, 10.0)
)

extension_ai_threats_detected_total = Counter(
    'social_protection_extension_ai_threats_detected_total',
    'Total threats detected by AI',
    ['platform', 'threat_type']
)

# Cache metrics
extension_cache_operations_total = Counter(
    'social_protection_extension_cache_operations_total',
    'Total cache operations',
    ['operation', 'result']
)

extension_cache_size = Gauge(
    'social_protection_extension_cache_size',
    'Current number of entries in cache'
)

extension_cache_hit_rate = Gauge(
    'social_protection_extension_cache_hit_rate',
    'Cache hit rate (0-1)'
)

# Link safety check metrics
extension_link_checks_total = Counter(
    'social_protection_extension_link_checks_total',
    'Total link safety checks performed',
    ['platform', 'is_safe']
)

extension_link_check_duration_seconds = Histogram(
    'social_protection_extension_link_check_duration_seconds',
    'Link safety check duration in seconds',
    ['platform'],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5)
)

# Error metrics
extension_errors_total = Counter(
    'social_protection_extension_errors_total',
    'Total errors encountered',
    ['error_type', 'operation']
)

extension_timeouts_total = Counter(
    'social_protection_extension_timeouts_total',
    'Total timeout errors',
    ['operation']
)

# Batch processing metrics
extension_batch_items_processed_total = Counter(
    'social_protection_extension_batch_items_processed_total',
    'Total items processed in batches',
    ['status']
)

extension_batch_size = Histogram(
    'social_protection_extension_batch_size',
    'Batch request sizes',
    buckets=(1, 5, 10, 25, 50, 100)
)

# Concurrent processing metrics
extension_concurrent_requests = Gauge(
    'social_protection_extension_concurrent_requests',
    'Current number of concurrent requests being processed'
)

# Content analysis metrics
extension_content_patterns_matched_total = Counter(
    'social_protection_extension_content_patterns_matched_total',
    'Total content patterns matched',
    ['platform', 'pattern_type']
)

extension_platform_indicators_matched_total = Counter(
    'social_protection_extension_platform_indicators_matched_total',
    'Total platform-specific indicators matched',
    ['platform', 'indicator_type']
)

# Confidence score distribution
extension_confidence_score = Histogram(
    'social_protection_extension_confidence_score',
    'Distribution of confidence scores',
    ['platform'],
    buckets=(0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0)
)


# Helper functions for metric recording

def record_request_processed(platform: str, content_type: str, status: str, duration_seconds: float):
    """Record a processed extension request."""
    extension_requests_total.labels(
        platform=platform,
        content_type=content_type,
        status=status
    ).inc()
    
    extension_processing_duration_seconds.labels(
        platform=platform,
        content_type=content_type
    ).observe(duration_seconds)


def record_batch_processed(batch_size: int, status: str, duration_seconds: float):
    """Record a processed batch request."""
    extension_batch_requests_total.labels(status=status).inc()
    
    # Determine batch size range
    if batch_size <= 10:
        size_range = "1-10"
    elif batch_size <= 25:
        size_range = "11-25"
    elif batch_size <= 50:
        size_range = "26-50"
    else:
        size_range = "51-100"
    
    extension_batch_processing_duration_seconds.labels(
        batch_size_range=size_range
    ).observe(duration_seconds)
    
    extension_batch_size.observe(batch_size)


def record_risk_assessment(platform: str, risk_level: str, confidence_score: float):
    """Record a risk assessment."""
    extension_risk_assessments_total.labels(
        platform=platform,
        risk_level=risk_level
    ).inc()
    
    extension_confidence_score.labels(platform=platform).observe(confidence_score)


def record_risk_factor(platform: str, risk_type: str):
    """Record a detected risk factor."""
    extension_risk_factors_detected_total.labels(
        platform=platform,
        risk_type=risk_type
    ).inc()


def record_ai_analysis(platform: str, status: str, duration_seconds: float, threat_types: Optional[list] = None):
    """Record an AI analysis."""
    extension_ai_analysis_total.labels(
        platform=platform,
        status=status
    ).inc()
    
    extension_ai_analysis_duration_seconds.labels(
        platform=platform
    ).observe(duration_seconds)
    
    if threat_types:
        for threat_type in threat_types:
            extension_ai_threats_detected_total.labels(
                platform=platform,
                threat_type=threat_type
            ).inc()


def record_cache_operation(operation: str, result: str):
    """Record a cache operation."""
    extension_cache_operations_total.labels(
        operation=operation,
        result=result
    ).inc()


def update_cache_metrics(cache_size: int, hit_rate: float):
    """Update cache metrics."""
    extension_cache_size.set(cache_size)
    extension_cache_hit_rate.set(hit_rate)


def record_link_check(platform: str, is_safe: bool, duration_seconds: float):
    """Record a link safety check."""
    extension_link_checks_total.labels(
        platform=platform,
        is_safe=str(is_safe).lower()
    ).inc()
    
    extension_link_check_duration_seconds.labels(
        platform=platform
    ).observe(duration_seconds)


def record_error(error_type: str, operation: str):
    """Record an error."""
    extension_errors_total.labels(
        error_type=error_type,
        operation=operation
    ).inc()


def record_timeout(operation: str):
    """Record a timeout."""
    extension_timeouts_total.labels(operation=operation).inc()


def record_batch_item(status: str):
    """Record a batch item processed."""
    extension_batch_items_processed_total.labels(status=status).inc()


def record_content_pattern_match(platform: str, pattern_type: str):
    """Record a content pattern match."""
    extension_content_patterns_matched_total.labels(
        platform=platform,
        pattern_type=pattern_type
    ).inc()


def record_platform_indicator_match(platform: str, indicator_type: str):
    """Record a platform indicator match."""
    extension_platform_indicators_matched_total.labels(
        platform=platform,
        indicator_type=indicator_type
    ).inc()


def increment_concurrent_requests():
    """Increment concurrent request counter."""
    extension_concurrent_requests.inc()


def decrement_concurrent_requests():
    """Decrement concurrent request counter."""
    extension_concurrent_requests.dec()
