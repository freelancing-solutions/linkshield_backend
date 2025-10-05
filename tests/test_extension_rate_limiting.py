#!/usr/bin/env python3
import pytest
from starlette.testclient import TestClient

from linkshield.main import create_app
from linkshield.routes.extension import router as extension_router
from linkshield.services.advanced_rate_limiter import get_rate_limiter
from linkshield.services.depends import get_url_analysis_service, get_extension_data_processor


class DummyAnalysis:
    def __init__(self, url: str):
        self.normalized_url = url
        self.domain = "example.com"
        self.threat_level = "safe"
        self.confidence_score = 0.95
        self.scan_types = ["dns", "http"]

    def has_threat_detected(self):
        return False

    def get_threat_types(self):
        return []


class DummyURLService:
    async def quick_security_analysis_by_url(self, url: str) -> DummyAnalysis:
        return DummyAnalysis(url)


class DummyProcessorResponse:
    def __init__(self):
        class Assessment:
            risk_level = "low"
            confidence = 0.9
            risk_factors = []
            processing_time_ms = 15

        self.assessment = Assessment()
        self.status = "success"
        self.error_message = None
        self.processing_time_ms = 15


class DummyProcessor:
    async def process_extension_request(self, payload):
        return DummyProcessorResponse()


class DummyUser:
    def __init__(self, user_id: str = "test-user", subscription_plan: str = "free"):
        self.id = user_id
        self.subscription_plan = subscription_plan


@pytest.fixture(autouse=True)
def setup_dependencies():
    # Override dependencies with dummy implementations
    app.dependency_overrides[get_url_analysis_service] = lambda: DummyURLService()
    app.dependency_overrides[get_extension_data_processor] = lambda: DummyProcessor()
    yield
    app.dependency_overrides.clear()


def reset_rate_limit_keys():
    limiter = get_rate_limiter()
    # Reset client key used by TestClient for anonymous quick checks
    client_key = "rate_limit:extension_url_check:client:testclient"
    # Reset user keys
    bulk_user_key = "rate_limit:extension_bulk_url_check:user:test-user"
    content_user_key = "rate_limit:extension_content_analyze:user:test-user"

    # Use event loop to run async resets
    import asyncio

    async def _reset():
        await limiter.storage.reset_counter(client_key)
        await limiter.storage.reset_counter(bulk_user_key)
        await limiter.storage.reset_counter(content_user_key)

    asyncio.get_event_loop().run_until_complete(_reset())


def test_quick_url_check_rate_limit_headers_and_exceed():
    reset_rate_limit_keys()
    client = TestClient(create_app())

    payload = {"url": "https://example.com"}

    # First request should be allowed and include rate limit headers
    r = client.post("/api/v1/extension/url/check", json=payload)
    assert r.status_code == 200
    assert "X-RateLimit-Limit" in r.headers
    assert "X-RateLimit-Remaining" in r.headers

    # Exceed limit (default 12/minute for quick check)
    for _ in range(12):
        client.post("/api/v1/extension/url/check", json=payload)

    r2 = client.post("/api/v1/extension/url/check", json=payload)
    assert r2.status_code == 429


def test_bulk_requires_auth_and_is_rate_limited():
    reset_rate_limit_keys()
    client = TestClient(create_app())

    # Without auth should be 401
    r = client.post(
        "/api/v1/extension/url/bulk-check",
        json={"items": [{"url": "https://example.com"}]}
    )
    assert r.status_code == 401

    # Override get_current_user to return a dummy user
    from linkshield.authentication.dependencies import get_current_user
    app.dependency_overrides[get_current_user] = lambda: DummyUser()

    # With auth should succeed
    r2 = client.post(
        "/api/v1/extension/url/bulk-check",
        json={"items": [{"url": "https://example.com"}]}
    )
    assert r2.status_code == 200

    # Hit rate limit for bulk (limit 6/minute). Do 7 total including previous
    for _ in range(6):
        client.post(
            "/api/v1/extension/url/bulk-check",
            json={"items": [{"url": "https://example.com"}]}
        )

    r3 = client.post(
        "/api/v1/extension/url/bulk-check",
        json={"items": [{"url": "https://example.com"}]}
    )
    assert r3.status_code == 429


def test_content_requires_auth_and_is_rate_limited():
    reset_rate_limit_keys()
    client = TestClient(create_app())

    # Without auth should be 401
    r = client.post(
        "/api/v1/extension/content/analyze",
        json={"content": "hello", "context": {}}
    )
    assert r.status_code == 401

    # Override get_current_user to return a dummy user
    from linkshield.authentication.dependencies import get_current_user
    app.dependency_overrides[get_current_user] = lambda: DummyUser()

    # With auth should succeed
    r2 = client.post(
        "/api/v1/extension/content/analyze",
        json={"content": "hello", "context": {}}
    )
    assert r2.status_code == 200

    # Hit rate limit for content analyze (limit 12/minute)
    for _ in range(12):
        client.post(
            "/api/v1/extension/content/analyze",
            json={"content": "hello", "context": {}}
        )

    r3 = client.post(
        "/api/v1/extension/content/analyze",
        json={"content": "hello", "context": {}}
    )
    assert r3.status_code == 429