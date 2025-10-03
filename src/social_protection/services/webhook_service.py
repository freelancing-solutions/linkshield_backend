#!/usr/bin/env python3
"""
Webhook Notification Service

Provides webhook notifications for scan completion, crisis alerts, and other events.
"""

import asyncio
import json
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from uuid import UUID
import httpx

from src.social_protection.logging_utils import get_logger
from src.social_protection.exceptions import ExternalServiceError

logger = get_logger("WebhookService")


class WebhookService:
    """
    Service for sending webhook notifications.
    
    Supports:
    - Scan completion notifications
    - Crisis alert notifications
    - Custom event notifications
    - Retry logic for failed deliveries
    """
    
    def __init__(self, timeout: float = 10.0, max_retries: int = 3):
        """
        Initialize webhook service.
        
        Args:
            timeout: HTTP request timeout in seconds
            max_retries: Maximum number of retry attempts
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self._client: Optional[httpx.AsyncClient] = None
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client"""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True
            )
        return self._client
    
    async def close(self) -> None:
        """Close HTTP client"""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    async def send_webhook(
        self,
        url: str,
        payload: Dict[str, Any],
        headers: Optional[Dict[str, str]] = None,
        secret: Optional[str] = None
    ) -> bool:
        """
        Send webhook notification with retry logic.
        
        Args:
            url: Webhook URL
            payload: Notification payload
            headers: Optional custom headers
            secret: Optional webhook secret for signature
            
        Returns:
            True if webhook was delivered successfully
        """
        if not url:
            logger.warning("Webhook URL not provided, skipping notification")
            return False
        
        # Prepare headers
        request_headers = {
            "Content-Type": "application/json",
            "User-Agent": "LinkShield-SocialProtection/1.0"
        }
        
        if headers:
            request_headers.update(headers)
        
        # Add signature if secret provided
        if secret:
            import hmac
            import hashlib
            
            payload_bytes = json.dumps(payload).encode()
            signature = hmac.new(
                secret.encode(),
                payload_bytes,
                hashlib.sha256
            ).hexdigest()
            request_headers["X-Webhook-Signature"] = f"sha256={signature}"
        
        # Add timestamp
        payload["timestamp"] = datetime.now(timezone.utc).isoformat()
        
        # Retry logic
        attempt = 0
        last_error = None
        
        while attempt < self.max_retries:
            try:
                client = await self._get_client()
                
                logger.info(
                    "Sending webhook notification",
                    url=url,
                    attempt=attempt + 1,
                    max_retries=self.max_retries
                )
                
                response = await client.post(
                    url,
                    json=payload,
                    headers=request_headers
                )
                
                if response.status_code in [200, 201, 202, 204]:
                    logger.info(
                        "Webhook delivered successfully",
                        url=url,
                        status_code=response.status_code,
                        attempt=attempt + 1
                    )
                    return True
                else:
                    logger.warning(
                        "Webhook delivery failed with non-success status",
                        url=url,
                        status_code=response.status_code,
                        response_text=response.text[:200],
                        attempt=attempt + 1
                    )
                    last_error = f"HTTP {response.status_code}: {response.text[:100]}"
                
            except httpx.TimeoutException as e:
                logger.warning(
                    "Webhook delivery timeout",
                    url=url,
                    attempt=attempt + 1,
                    error=str(e)
                )
                last_error = f"Timeout: {str(e)}"
                
            except httpx.RequestError as e:
                logger.warning(
                    "Webhook delivery request error",
                    url=url,
                    attempt=attempt + 1,
                    error=str(e)
                )
                last_error = f"Request error: {str(e)}"
                
            except Exception as e:
                logger.error(
                    "Unexpected error sending webhook",
                    url=url,
                    attempt=attempt + 1,
                    error=str(e)
                )
                last_error = f"Unexpected error: {str(e)}"
            
            attempt += 1
            
            # Wait before retry (exponential backoff)
            if attempt < self.max_retries:
                delay = 2 ** attempt  # 2, 4, 8 seconds
                await asyncio.sleep(delay)
        
        logger.error(
            "Webhook delivery failed after all retries",
            url=url,
            max_retries=self.max_retries,
            last_error=last_error
        )
        return False
    
    async def notify_scan_complete(
        self,
        webhook_url: str,
        scan_id: UUID,
        user_id: UUID,
        platform: str,
        status: str,
        result_summary: Optional[Dict[str, Any]] = None,
        secret: Optional[str] = None
    ) -> bool:
        """
        Send scan completion notification.
        
        Args:
            webhook_url: Webhook URL
            scan_id: Scan identifier
            user_id: User identifier
            platform: Platform name
            status: Scan status (completed/failed)
            result_summary: Optional scan result summary
            secret: Optional webhook secret
            
        Returns:
            True if notification was delivered
        """
        payload = {
            "event": "scan.completed",
            "scan_id": str(scan_id),
            "user_id": str(user_id),
            "platform": platform,
            "status": status,
            "result_summary": result_summary or {}
        }
        
        return await self.send_webhook(webhook_url, payload, secret=secret)
    
    async def notify_crisis_alert(
        self,
        webhook_url: str,
        alert_id: UUID,
        brand: str,
        severity: str,
        score: float,
        reason: str,
        secret: Optional[str] = None
    ) -> bool:
        """
        Send crisis alert notification.
        
        Args:
            webhook_url: Webhook URL
            alert_id: Alert identifier
            brand: Brand name
            severity: Alert severity
            score: Crisis score
            reason: Alert reason
            secret: Optional webhook secret
            
        Returns:
            True if notification was delivered
        """
        payload = {
            "event": "crisis.alert",
            "alert_id": str(alert_id),
            "brand": brand,
            "severity": severity,
            "score": score,
            "reason": reason
        }
        
        return await self.send_webhook(webhook_url, payload, secret=secret)
    
    async def notify_custom_event(
        self,
        webhook_url: str,
        event_type: str,
        event_data: Dict[str, Any],
        secret: Optional[str] = None
    ) -> bool:
        """
        Send custom event notification.
        
        Args:
            webhook_url: Webhook URL
            event_type: Event type identifier
            event_data: Event data
            secret: Optional webhook secret
            
        Returns:
            True if notification was delivered
        """
        payload = {
            "event": event_type,
            **event_data
        }
        
        return await self.send_webhook(webhook_url, payload, secret=secret)
    
    async def send_batch_webhooks(
        self,
        webhooks: List[Dict[str, Any]]
    ) -> Dict[str, bool]:
        """
        Send multiple webhooks concurrently.
        
        Args:
            webhooks: List of webhook configurations with 'url', 'payload', 'secret'
            
        Returns:
            Dictionary mapping webhook URLs to delivery status
        """
        tasks = []
        urls = []
        
        for webhook in webhooks:
            url = webhook.get("url")
            payload = webhook.get("payload", {})
            secret = webhook.get("secret")
            
            if url:
                tasks.append(self.send_webhook(url, payload, secret=secret))
                urls.append(url)
        
        if not tasks:
            return {}
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return {
            url: result if not isinstance(result, Exception) else False
            for url, result in zip(urls, results)
        }


# Global webhook service instance
_webhook_service: Optional[WebhookService] = None


def get_webhook_service() -> WebhookService:
    """
    Get or create global webhook service instance.
    
    Returns:
        WebhookService instance
    """
    global _webhook_service
    
    if _webhook_service is None:
        _webhook_service = WebhookService()
    
    return _webhook_service
