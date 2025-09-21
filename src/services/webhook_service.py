#!/usr/bin/env python3
"""
LinkShield Backend Webhook Service

Comprehensive webhook service for delivering HTTP notifications with authentication,
retry logic, and error handling. Supports various event types and standardized payloads.
"""

import asyncio
import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Any, Optional, List, Union
from urllib.parse import urlparse

import aiohttp
from pydantic import BaseModel, HttpUrl, Field

from src.config.settings import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class WebhookEventType(str, Enum):
    """Supported webhook event types."""
    TASK_COMPLETED = "task.completed"
    TASK_FAILED = "task.failed"
    ANALYSIS_FINISHED = "analysis.finished"
    REPORT_CREATED = "report.created"
    REPORT_ASSIGNED = "report.assigned"
    REPORT_RESOLVED = "report.resolved"
    URL_CHECK_COMPLETED = "url_check.completed"
    ADMIN_ALERT = "admin.alert"
    SYSTEM_NOTIFICATION = "system.notification"


class WebhookPayload(BaseModel):
    """Standardized webhook payload structure."""
    event_type: WebhookEventType
    event_id: str = Field(..., description="Unique event identifier")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    data: Dict[str, Any] = Field(..., description="Event-specific data")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Additional metadata")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class WebhookDeliveryResult(BaseModel):
    """Result of webhook delivery attempt."""
    success: bool
    status_code: Optional[int] = None
    response_body: Optional[str] = None
    error_message: Optional[str] = None
    delivery_time_ms: Optional[int] = None
    attempt_number: int
    final_attempt: bool


class WebhookService:
    """
    Comprehensive webhook service for HTTP notification delivery.
    
    Features:
    - HMAC-SHA256 signature authentication
    - Exponential backoff retry logic
    - Timeout handling and error tracking
    - Support for multiple event types
    - Webhook URL validation
    - Delivery logging and monitoring
    """
    
    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None
        self.default_timeout = getattr(settings, 'WEBHOOK_TIMEOUT', 30)
        self.max_retries = getattr(settings, 'WEBHOOK_MAX_RETRIES', 3)
        self.retry_delays = [1, 3, 9]  # Exponential backoff: 1s, 3s, 9s
        self.max_payload_size = getattr(settings, 'WEBHOOK_MAX_PAYLOAD_SIZE', 1024 * 1024)  # 1MB
        self.signature_algorithm = 'sha256'
        
    async def __aenter__(self):
        """Async context manager entry."""
        await self._ensure_session()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
        
    async def _ensure_session(self):
        """Ensure aiohttp session is initialized."""
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=self.default_timeout)
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers={
                    'User-Agent': 'LinkShield-Webhook/1.0',
                    'Content-Type': 'application/json'
                }
            )
    
    async def close(self):
        """Close the aiohttp session."""
        if self.session and not self.session.closed:
            await self.session.close()
            self.session = None
    
    def validate_webhook_url(self, url: str) -> bool:
        """
        Validate webhook URL for security and format.
        
        Args:
            url: Webhook URL to validate
            
        Returns:
            bool: True if URL is valid and allowed
        """
        try:
            parsed = urlparse(url)
            
            # Must be HTTP or HTTPS
            if parsed.scheme not in ('http', 'https'):
                logger.warning(f"Invalid webhook URL scheme: {parsed.scheme}")
                return False
                
            # Must have a host
            if not parsed.hostname:
                logger.warning(f"Webhook URL missing hostname: {url}")
                return False
                
            # Block localhost and private IPs in production
            if hasattr(settings, 'WEBHOOK_ALLOW_LOCALHOST') and not settings.WEBHOOK_ALLOW_LOCALHOST:
                if parsed.hostname in ('localhost', '127.0.0.1', '::1'):
                    logger.warning(f"Localhost webhook URLs not allowed: {url}")
                    return False
                    
            # Check against allowed domains if configured
            if hasattr(settings, 'WEBHOOK_ALLOWED_DOMAINS') and settings.WEBHOOK_ALLOWED_DOMAINS:
                allowed_domains = settings.WEBHOOK_ALLOWED_DOMAINS
                if not any(parsed.hostname.endswith(domain) for domain in allowed_domains):
                    logger.warning(f"Webhook URL domain not allowed: {parsed.hostname}")
                    return False
                    
            return True
            
        except Exception as e:
            logger.error(f"Error validating webhook URL {url}: {e}")
            return False
    
    def _generate_signature(self, payload: str, secret: str) -> str:
        """
        Generate HMAC-SHA256 signature for webhook payload.
        
        Args:
            payload: JSON payload string
            secret: Webhook secret key
            
        Returns:
            str: HMAC signature in format 'sha256=<hex_digest>'
        """
        signature = hmac.new(
            secret.encode('utf-8'),
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        return f"sha256={signature}"
    
    def _create_headers(self, payload: str, secret: Optional[str] = None) -> Dict[str, str]:
        """
        Create HTTP headers for webhook request.
        
        Args:
            payload: JSON payload string
            secret: Optional webhook secret for signature
            
        Returns:
            Dict[str, str]: HTTP headers
        """
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'LinkShield-Webhook/1.0',
            'X-LinkShield-Event': 'webhook',
            'X-LinkShield-Delivery': datetime.now(timezone.utc).isoformat()
        }
        
        if secret:
            headers['X-LinkShield-Signature'] = self._generate_signature(payload, secret)
            
        return headers
    
    async def send_webhook(
        self,
        url: str,
        payload: WebhookPayload,
        secret: Optional[str] = None,
        timeout: Optional[int] = None,
        max_retries: Optional[int] = None
    ) -> WebhookDeliveryResult:
        """
        Send webhook notification with retry logic.
        
        Args:
            url: Webhook URL
            payload: Webhook payload
            secret: Optional secret for HMAC signature
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts
            
        Returns:
            WebhookDeliveryResult: Delivery result with status and metrics
        """
        if not self.validate_webhook_url(url):
            return WebhookDeliveryResult(
                success=False,
                error_message="Invalid webhook URL",
                attempt_number=0,
                final_attempt=True
            )
        
        # Serialize payload
        try:
            payload_json = payload.json()
            if len(payload_json.encode('utf-8')) > self.max_payload_size:
                return WebhookDeliveryResult(
                    success=False,
                    error_message=f"Payload too large: {len(payload_json)} bytes",
                    attempt_number=0,
                    final_attempt=True
                )
        except Exception as e:
            return WebhookDeliveryResult(
                success=False,
                error_message=f"Failed to serialize payload: {e}",
                attempt_number=0,
                final_attempt=True
            )
        
        await self._ensure_session()
        
        timeout = timeout or self.default_timeout
        max_retries = max_retries or self.max_retries
        headers = self._create_headers(payload_json, secret)
        
        # Attempt delivery with retries
        for attempt in range(max_retries + 1):
            is_final_attempt = attempt == max_retries
            start_time = datetime.now()
            
            try:
                logger.info(f"Sending webhook to {url} (attempt {attempt + 1}/{max_retries + 1})")
                
                async with self.session.post(
                    url,
                    data=payload_json,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=timeout)
                ) as response:
                    delivery_time = int((datetime.now() - start_time).total_seconds() * 1000)
                    response_body = await response.text()
                    
                    if response.status < 400:
                        logger.info(f"Webhook delivered successfully to {url} in {delivery_time}ms")
                        return WebhookDeliveryResult(
                            success=True,
                            status_code=response.status,
                            response_body=response_body[:1000],  # Limit response body size
                            delivery_time_ms=delivery_time,
                            attempt_number=attempt + 1,
                            final_attempt=is_final_attempt
                        )
                    else:
                        error_msg = f"HTTP {response.status}: {response_body[:500]}"
                        logger.warning(f"Webhook delivery failed to {url}: {error_msg}")
                        
                        if is_final_attempt:
                            return WebhookDeliveryResult(
                                success=False,
                                status_code=response.status,
                                response_body=response_body[:1000],
                                error_message=error_msg,
                                delivery_time_ms=delivery_time,
                                attempt_number=attempt + 1,
                                final_attempt=True
                            )
                            
            except asyncio.TimeoutError:
                error_msg = f"Webhook timeout after {timeout}s"
                logger.warning(f"Webhook delivery timeout to {url}")
                
                if is_final_attempt:
                    return WebhookDeliveryResult(
                        success=False,
                        error_message=error_msg,
                        attempt_number=attempt + 1,
                        final_attempt=True
                    )
                    
            except Exception as e:
                error_msg = f"Webhook delivery error: {str(e)}"
                logger.error(f"Webhook delivery error to {url}: {e}")
                
                if is_final_attempt:
                    return WebhookDeliveryResult(
                        success=False,
                        error_message=error_msg,
                        attempt_number=attempt + 1,
                        final_attempt=True
                    )
            
            # Wait before retry (exponential backoff)
            if not is_final_attempt:
                delay = self.retry_delays[min(attempt, len(self.retry_delays) - 1)]
                logger.info(f"Retrying webhook delivery to {url} in {delay}s")
                await asyncio.sleep(delay)
        
        # This should never be reached, but just in case
        return WebhookDeliveryResult(
            success=False,
            error_message="Maximum retries exceeded",
            attempt_number=max_retries + 1,
            final_attempt=True
        )
    
    async def send_bulk_webhook(
        self,
        webhooks: List[Dict[str, Any]],
        concurrency_limit: int = 10
    ) -> List[WebhookDeliveryResult]:
        """
        Send multiple webhooks concurrently with rate limiting.
        
        Args:
            webhooks: List of webhook configurations with 'url', 'payload', and optional 'secret'
            concurrency_limit: Maximum concurrent webhook deliveries
            
        Returns:
            List[WebhookDeliveryResult]: Results for each webhook delivery
        """
        semaphore = asyncio.Semaphore(concurrency_limit)
        
        async def send_single_webhook(webhook_config: Dict[str, Any]) -> WebhookDeliveryResult:
            async with semaphore:
                return await self.send_webhook(
                    url=webhook_config['url'],
                    payload=webhook_config['payload'],
                    secret=webhook_config.get('secret'),
                    timeout=webhook_config.get('timeout'),
                    max_retries=webhook_config.get('max_retries')
                )
        
        tasks = [send_single_webhook(webhook) for webhook in webhooks]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Convert exceptions to failed results
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed_results.append(WebhookDeliveryResult(
                    success=False,
                    error_message=f"Bulk webhook error: {str(result)}",
                    attempt_number=1,
                    final_attempt=True
                ))
            else:
                processed_results.append(result)
        
        return processed_results
    
    def create_task_completed_payload(
        self,
        task_id: str,
        task_type: str,
        result: Dict[str, Any],
        user_id: Optional[str] = None
    ) -> WebhookPayload:
        """
        Create standardized payload for task completion events.
        
        Args:
            task_id: Task identifier
            task_type: Type of task completed
            result: Task result data
            user_id: Optional user identifier
            
        Returns:
            WebhookPayload: Standardized webhook payload
        """
        return WebhookPayload(
            event_type=WebhookEventType.TASK_COMPLETED,
            event_id=f"task_completed_{task_id}",
            data={
                "task_id": task_id,
                "task_type": task_type,
                "result": result,
                "user_id": user_id
            },
            metadata={
                "source": "linkshield_backend",
                "version": "1.0"
            }
        )
    
    def create_analysis_finished_payload(
        self,
        analysis_id: str,
        analysis_type: str,
        results: Dict[str, Any],
        user_id: Optional[str] = None
    ) -> WebhookPayload:
        """
        Create standardized payload for analysis completion events.
        
        Args:
            analysis_id: Analysis identifier
            analysis_type: Type of analysis completed
            results: Analysis results
            user_id: Optional user identifier
            
        Returns:
            WebhookPayload: Standardized webhook payload
        """
        return WebhookPayload(
            event_type=WebhookEventType.ANALYSIS_FINISHED,
            event_id=f"analysis_finished_{analysis_id}",
            data={
                "analysis_id": analysis_id,
                "analysis_type": analysis_type,
                "results": results,
                "user_id": user_id
            },
            metadata={
                "source": "linkshield_backend",
                "version": "1.0"
            }
        )


# Global webhook service instance
_webhook_service: Optional[WebhookService] = None


async def get_webhook_service() -> WebhookService:
    """
    Get or create the global webhook service instance.
    
    Returns:
        WebhookService: Global webhook service instance
    """
    global _webhook_service
    if _webhook_service is None:
        _webhook_service = WebhookService()
    await _webhook_service._ensure_session()
    return _webhook_service


async def cleanup_webhook_service():
    """Clean up the global webhook service instance."""
    global _webhook_service
    if _webhook_service:
        await _webhook_service.close()
        _webhook_service = None