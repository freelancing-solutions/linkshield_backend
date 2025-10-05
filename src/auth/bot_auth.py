"""
Bot Authentication and Webhook Signature Verification.

This module provides authentication and security functions for bot operations,
including webhook signature verification for different platforms.
"""

import hmac
import hashlib
import base64
import json
import logging
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timedelta
import secrets

from fastapi import HTTPException, Request
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from ..config.settings import settings
from .service_token_storage import ServiceTokenStorage, TokenNotFoundError, TokenExpiredError, ServiceTokenStorageError, RedisConnectionError

logger = logging.getLogger(__name__)


class BotAuthenticationError(Exception):
    """Custom exception for bot authentication errors."""
    pass


class WebhookSignatureVerifier:
    """
    Handles webhook signature verification for different platforms.
    
    Each platform has its own signature verification method to ensure
    that webhook requests are authentic and haven't been tampered with.
    """
    
    @staticmethod
    def verify_twitter_signature(payload: bytes, signature: str, 
                                webhook_secret: Optional[str] = None) -> bool:
        """
        Verify Twitter webhook signature using HMAC-SHA256.
        
        Args:
            payload: Raw request payload
            signature: X-Twitter-Webhooks-Signature header value
            webhook_secret: Twitter webhook secret (defaults to settings)
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            if not webhook_secret:
                webhook_secret = settings.BOT_WEBHOOK_SECRET
            
            if not webhook_secret:
                logger.error("Twitter webhook secret not configured")
                return False
            
            # Twitter uses sha256= prefix
            if not signature.startswith('sha256='):
                logger.warning("Twitter signature missing sha256= prefix")
                return False
            
            # Extract the signature hash
            signature_hash = signature[7:]  # Remove 'sha256=' prefix
            
            # Calculate expected signature
            expected_signature = hmac.new(
                webhook_secret.encode('utf-8'),
                payload,
                hashlib.sha256
            ).hexdigest()
            
            # Compare signatures using constant-time comparison
            is_valid = hmac.compare_digest(signature_hash, expected_signature)
            
            if not is_valid:
                logger.warning("Twitter webhook signature verification failed")
            
            return is_valid
            
        except Exception as e:
            logger.error(f"Error verifying Twitter signature: {e}")
            return False
    
    @staticmethod
    def verify_telegram_signature(payload: bytes, signature: str,
                                 bot_token: Optional[str] = None) -> bool:
        """
        Verify Telegram webhook signature using HMAC-SHA256.
        
        Args:
            payload: Raw request payload
            signature: X-Telegram-Bot-Api-Secret-Token header value
            bot_token: Telegram bot token (defaults to settings)
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            if not bot_token:
                bot_token = settings.TELEGRAM_BOT_TOKEN
            
            if not bot_token:
                logger.error("Telegram bot token not configured")
                return False
            
            # For Telegram, we use the secret token approach
            webhook_secret = settings.BOT_WEBHOOK_SECRET
            if not webhook_secret:
                logger.error("Telegram webhook secret not configured")
                return False
            
            # Telegram sends the secret token directly
            is_valid = hmac.compare_digest(signature, webhook_secret)
            
            if not is_valid:
                logger.warning("Telegram webhook signature verification failed")
            
            return is_valid
            
        except Exception as e:
            logger.error(f"Error verifying Telegram signature: {e}")
            return False
    
    @staticmethod
    def verify_discord_signature(payload: bytes, signature: str, timestamp: str,
                                public_key: Optional[str] = None) -> bool:
        """
        Verify Discord interaction signature using Ed25519.
        
        Args:
            payload: Raw request payload
            signature: X-Signature-Ed25519 header value (hex-encoded)
            timestamp: X-Signature-Timestamp header value
            public_key: Discord application public key (hex-encoded)
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Get Discord public key from settings or parameter
            if not public_key:
                public_key = settings.DISCORD_PUBLIC_KEY
            
            if not public_key:
                logger.error("Discord public key not configured")
                return False
            
            # Validate signature and timestamp format
            if not signature or not timestamp:
                logger.warning("Discord signature or timestamp missing")
                return False
            
            # Validate timestamp to prevent replay attacks (Discord recommends 5 minute window)
            try:
                timestamp_int = int(timestamp)
                current_time = int(datetime.utcnow().timestamp())
                time_diff = abs(current_time - timestamp_int)
                
                # Reject requests older than 5 minutes (300 seconds)
                if time_diff > 300:
                    logger.warning(f"Discord webhook timestamp too old: {time_diff} seconds")
                    return False
                    
            except ValueError:
                logger.error("Invalid Discord timestamp format")
                return False
            
            # Create message to verify (timestamp + payload)
            message = timestamp.encode() + payload
            
            try:
                # Convert hex-encoded public key to Ed25519PublicKey object
                public_key_bytes = bytes.fromhex(public_key)
                ed25519_public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
                
                # Convert hex-encoded signature to bytes
                signature_bytes = bytes.fromhex(signature)
                
                # Verify Ed25519 signature
                ed25519_public_key.verify(signature_bytes, message)
                
                logger.debug("Discord Ed25519 signature verification successful")
                return True
                
            except ValueError as e:
                logger.error(f"Invalid Discord public key or signature format: {e}")
                return False
            except InvalidSignature:
                logger.warning("Discord Ed25519 signature verification failed")
                return False
            
        except Exception as e:
            logger.error(f"Error verifying Discord signature: {e}")
            return False


class BotAuthenticator:
    """
    Handles bot authentication and authorization.
    
    Manages bot service accounts, API key validation, and access control
    for bot operations.
    """
    
    def __init__(self):
        """Initialize the bot authenticator."""
        self.signature_verifier = WebhookSignatureVerifier()
        self.service_token_storage = ServiceTokenStorage()  # Redis-based storage
    
    async def authenticate_webhook_request(self, request: Request, platform: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Authenticate a webhook request from a specific platform.
        
        Args:
            request: FastAPI request object
            platform: Platform name (twitter, telegram, discord)
            
        Returns:
            Tuple of (is_authenticated, context_data)
        """
        try:
            # Get request payload
            payload = await request.body()
            
            # Platform-specific authentication
            if platform == "twitter":
                return await self._authenticate_twitter_webhook(request, payload)
            elif platform == "telegram":
                return await self._authenticate_telegram_webhook(request, payload)
            elif platform == "discord":
                return await self._authenticate_discord_webhook(request, payload)
            else:
                logger.error(f"Unknown platform for webhook authentication: {platform}")
                return False, {"error": "unknown_platform"}
                
        except Exception as e:
            logger.error(f"Error authenticating webhook request: {e}")
            return False, {"error": "authentication_failed", "details": str(e)}
    
    async def _authenticate_twitter_webhook(self, request: Request, payload: bytes) -> Tuple[bool, Dict[str, Any]]:
        """Authenticate Twitter webhook request."""
        try:
            # Get signature from headers
            signature = request.headers.get('X-Twitter-Webhooks-Signature')
            if not signature:
                logger.warning("Twitter webhook missing signature header")
                return False, {"error": "missing_signature"}
            
            # Verify signature
            is_valid = self.signature_verifier.verify_twitter_signature(payload, signature)
            
            if is_valid:
                # Parse payload for additional context
                try:
                    payload_data = json.loads(payload.decode('utf-8'))
                    context = {
                        "platform": "twitter",
                        "authenticated": True,
                        "payload_size": len(payload),
                        "has_user_event": "user_event" in payload_data,
                        "event_type": payload_data.get("event_type", "unknown")
                    }
                except:
                    context = {
                        "platform": "twitter",
                        "authenticated": True,
                        "payload_size": len(payload)
                    }
                
                return True, context
            else:
                return False, {"error": "invalid_signature", "platform": "twitter"}
                
        except Exception as e:
            logger.error(f"Error in Twitter webhook authentication: {e}")
            return False, {"error": "authentication_error", "details": str(e)}
    
    async def _authenticate_telegram_webhook(self, request: Request, payload: bytes) -> Tuple[bool, Dict[str, Any]]:
        """Authenticate Telegram webhook request."""
        try:
            # Get secret token from headers
            secret_token = request.headers.get('X-Telegram-Bot-Api-Secret-Token')
            if not secret_token:
                logger.warning("Telegram webhook missing secret token header")
                return False, {"error": "missing_secret_token"}
            
            # Verify signature
            is_valid = self.signature_verifier.verify_telegram_signature(payload, secret_token)
            
            if is_valid:
                # Parse payload for additional context
                try:
                    payload_data = json.loads(payload.decode('utf-8'))
                    context = {
                        "platform": "telegram",
                        "authenticated": True,
                        "payload_size": len(payload),
                        "update_id": payload_data.get("update_id"),
                        "has_message": "message" in payload_data,
                        "has_callback_query": "callback_query" in payload_data
                    }
                except:
                    context = {
                        "platform": "telegram",
                        "authenticated": True,
                        "payload_size": len(payload)
                    }
                
                return True, context
            else:
                return False, {"error": "invalid_secret_token", "platform": "telegram"}
                
        except Exception as e:
            logger.error(f"Error in Telegram webhook authentication: {e}")
            return False, {"error": "authentication_error", "details": str(e)}
    
    async def _authenticate_discord_webhook(self, request: Request, payload: bytes) -> Tuple[bool, Dict[str, Any]]:
        """Authenticate Discord webhook request."""
        try:
            # Get signature and timestamp from headers
            signature = request.headers.get('X-Signature-Ed25519')
            timestamp = request.headers.get('X-Signature-Timestamp')
            
            if not signature or not timestamp:
                logger.warning("Discord webhook missing signature or timestamp headers")
                return False, {"error": "missing_signature_headers"}
            
            # Verify signature
            is_valid = self.signature_verifier.verify_discord_signature(payload, signature, timestamp)
            
            if is_valid:
                # Parse payload for additional context
                try:
                    payload_data = json.loads(payload.decode('utf-8'))
                    context = {
                        "platform": "discord",
                        "authenticated": True,
                        "payload_size": len(payload),
                        "interaction_type": payload_data.get("type"),
                        "application_id": payload_data.get("application_id"),
                        "guild_id": payload_data.get("guild_id")
                    }
                except:
                    context = {
                        "platform": "discord",
                        "authenticated": True,
                        "payload_size": len(payload)
                    }
                
                return True, context
            else:
                return False, {"error": "invalid_signature", "platform": "discord"}
                
        except Exception as e:
            logger.error(f"Error in Discord webhook authentication: {e}")
            return False, {"error": "authentication_error", "details": str(e)}
    
    async def generate_service_token(self, service_name: str, permissions: List[str], 
                                   expires_in: int = 3600, max_uses: Optional[int] = None) -> str:
        """
        Generate a service token with Redis persistence and fallback support.
        
        Args:
            service_name: Name of the service requesting the token
            permissions: List of permissions for this token
            expires_in: Token expiration time in seconds (default: 1 hour)
            max_uses: Maximum number of times token can be used (optional)
            
        Returns:
            Generated service token string
            
        Raises:
            ServiceTokenStorageError: If token generation fails
        """
        try:
            # Generate token using Redis-based storage
            token = await self.service_token_storage.store_token(
                service_name=service_name,
                permissions=permissions,
                expires_in=expires_in,
                max_uses=max_uses
            )
            
            logger.info(f"Generated service token for {service_name} with permissions: {permissions}")
            return token
            
        except (ServiceTokenStorageError, RedisConnectionError) as e:
            logger.error(f"Failed to generate service token for {service_name}: {e}")
            raise ServiceTokenStorageError(f"Token generation failed: {e}")
        except Exception as e:
            logger.error(f"Unexpected error generating service token for {service_name}: {e}")
            raise ServiceTokenStorageError(f"Unexpected token generation error: {e}")
    
    async def validate_service_token(self, token: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Validate a service token with Redis persistence and fallback support.
        
        Args:
            token: Service token to validate
            
        Returns:
            Tuple of (is_valid, token_data or error_info)
        """
        try:
            # Retrieve and validate token using Redis-based storage
            token_data = await self.service_token_storage.get_token(token)
            
            # Update token usage
            await self.service_token_storage.update_token_usage(token)
            
            logger.info(f"Validated service token for service: {token_data.get('service_name', 'unknown')}")
            return True, token_data
            
        except TokenNotFoundError:
            logger.warning(f"Service token not found: {token[:8]}...")
            return False, {"error": "invalid_token", "details": "Token not found"}
        except TokenExpiredError:
            logger.warning(f"Service token expired: {token[:8]}...")
            return False, {"error": "token_expired", "details": "Token has expired"}
        except (ServiceTokenStorageError, RedisConnectionError) as e:
            logger.error(f"Service token validation error: {e}")
            return False, {"error": "validation_error", "details": "Token validation failed"}
        except Exception as e:
            logger.error(f"Unexpected error validating service token: {e}")
            return False, {"error": "validation_error", "details": "Unexpected validation error"}
    
    async def revoke_service_token(self, token: str) -> bool:
        """
        Revoke a service token with Redis persistence and fallback support.
        
        Args:
            token: Service token to revoke
            
        Returns:
            True if token was revoked successfully, False otherwise
        """
        try:
            # Revoke token using Redis-based storage
            await self.service_token_storage.revoke_token(token)
            
            logger.info(f"Revoked service token: {token[:8]}...")
            return True
            
        except TokenNotFoundError:
            logger.warning(f"Attempted to revoke non-existent service token: {token[:8]}...")
            return False
        except (ServiceTokenStorageError, RedisConnectionError) as e:
            logger.error(f"Failed to revoke service token: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error revoking service token: {e}")
            return False
    
    async def authenticate_api_request(self, api_key: str, platform: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Authenticate an API request using platform-specific API keys.
        
        Args:
            api_key: API key to validate
            platform: Platform name
            
        Returns:
            Tuple of (is_authenticated, context_data)
        """
        try:
            # Platform-specific API key validation
            if platform == "twitter":
                expected_key = settings.TWITTER_BOT_BEARER_TOKEN
            elif platform == "telegram":
                expected_key = settings.TELEGRAM_BOT_TOKEN
            elif platform == "discord":
                expected_key = settings.DISCORD_BOT_TOKEN
            else:
                return False, {"error": "unknown_platform"}
            
            if not expected_key:
                logger.error(f"API key not configured for platform: {platform}")
                return False, {"error": "api_key_not_configured"}
            
            # Validate API key
            is_valid = hmac.compare_digest(api_key, expected_key)
            
            if is_valid:
                context = {
                    "platform": platform,
                    "authenticated": True,
                    "auth_method": "api_key"
                }
                return True, context
            else:
                logger.warning(f"Invalid API key for platform: {platform}")
                return False, {"error": "invalid_api_key"}
                
        except Exception as e:
            logger.error(f"Error authenticating API request: {e}")
            return False, {"error": "authentication_failed", "details": str(e)}
    
    async def cleanup_expired_tokens(self) -> int:
        """
        Clean up expired service tokens with Redis persistence and fallback support.
        
        Returns:
            Number of tokens cleaned up
        """
        try:
            # Clean up expired tokens using Redis-based storage
            cleaned_count = await self.service_token_storage.cleanup_expired_tokens()
            
            if cleaned_count > 0:
                logger.info(f"Cleaned up {cleaned_count} expired service tokens")
            else:
                logger.debug("No expired service tokens to clean up")
                
            return cleaned_count
            
        except (ServiceTokenStorageError, RedisConnectionError) as e:
            logger.error(f"Failed to cleanup expired service tokens: {e}")
            return 0
        except Exception as e:
            logger.error(f"Unexpected error during service token cleanup: {e}")
            return 0


# Global bot authenticator instance
bot_authenticator = BotAuthenticator()


# Dependency functions for FastAPI
async def verify_webhook_signature(request: Request, platform: str):
    """
    FastAPI dependency for verifying webhook signatures.
    
    Args:
        request: FastAPI request object
        platform: Platform name
        
    Raises:
        HTTPException: If authentication fails
        
    Returns:
        Authentication context
    """
    is_authenticated, context = await bot_authenticator.authenticate_webhook_request(request, platform)
    
    if not is_authenticated:
        error_msg = context.get("error", "authentication_failed")
        logger.warning(f"Webhook authentication failed for {platform}: {error_msg}")
        raise HTTPException(
            status_code=401,
            detail=f"Webhook authentication failed: {error_msg}"
        )
    
    return context


async def verify_api_key(api_key: str, platform: str):
    """
    FastAPI dependency for verifying API keys.
    
    Args:
        api_key: API key to verify
        platform: Platform name
        
    Raises:
        HTTPException: If authentication fails
        
    Returns:
        Authentication context
    """
    is_authenticated, context = await bot_authenticator.authenticate_api_request(api_key, platform)
    
    if not is_authenticated:
        error_msg = context.get("error", "authentication_failed")
        logger.warning(f"API key authentication failed for {platform}: {error_msg}")
        raise HTTPException(
            status_code=401,
            detail=f"API authentication failed: {error_msg}"
        )
    
    return context