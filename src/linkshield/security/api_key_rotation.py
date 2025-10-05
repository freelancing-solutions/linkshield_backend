#!/usr/bin/env python3
"""
API Key Rotation Service

Provides automatic API key rotation, versioning, lifecycle management,
and emergency revocation capabilities for enhanced security.
"""

import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import uuid
import json

import redis.asyncio as redis
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete
from sqlalchemy.orm import selectinload

from linkshield.config.settings import get_settings
from linkshield.config.database import get_db_session
from linkshield.models.user import User, APIKey
from linkshield.services.notification_service import NotificationService


class APIKeyStatus(Enum):
    """API Key status enumeration"""
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass
class APIKeyRotationConfig:
    """Configuration for API key rotation"""
    rotation_interval_days: int = 90  # Default 90 days
    grace_period_days: int = 30  # Grace period for old keys
    max_active_keys: int = 2  # Maximum active keys per user
    notification_days_before: int = 7  # Notify N days before rotation
    emergency_revocation_enabled: bool = True


@dataclass
class APIKeyVersion:
    """API Key version information"""
    key_id: str
    version: int
    key_hash: str  # Hashed version for security
    status: APIKeyStatus
    created_at: datetime
    expires_at: datetime
    last_used: Optional[datetime] = None
    usage_count: int = 0
    revocation_reason: Optional[str] = None


class APIKeyRotationError(Exception):
    """API Key rotation specific errors"""
    pass


class APIKeyRotationService:
    """
    API Key Rotation Service
    
    Manages automatic API key rotation, versioning, and lifecycle management
    with support for graceful transitions and emergency revocation.
    """
    
    def __init__(self, redis_client: Optional[Redis] = None):
        """Initialize the API key rotation service"""
        self.settings = get_settings()
        self.redis_client = redis_client
        self.notification_service = NotificationService()
        self.config = APIKeyRotationConfig()
        
        # Redis keys for caching and tracking
        self.ROTATION_SCHEDULE_KEY = "api_key_rotation:schedule"
        self.KEY_USAGE_KEY = "api_key_rotation:usage:{key_id}"
        self.EMERGENCY_REVOCATION_KEY = "api_key_rotation:emergency_revoked"
    
    async def _get_redis_client(self) -> Redis:
        """Get Redis client instance"""
        if not self.redis_client:
            self.redis_client = redis.from_url(
                self.settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True
            )
        return self.redis_client
    
    def _generate_api_key(self) -> str:
        """Generate a new secure API key"""
        # Generate 32 bytes of random data and encode as base64
        key_bytes = secrets.token_bytes(32)
        key_b64 = secrets.token_urlsafe(32)
        
        # Add prefix for identification
        return f"lsk_live_{key_b64}"
    
    def _hash_api_key(self, api_key: str) -> str:
        """Create a secure hash of the API key for storage"""
        return hashlib.sha256(api_key.encode()).hexdigest()
    
    async def schedule_rotation(self, user_id: uuid.UUID, days_from_now: int = None) -> Dict[str, Any]:
        """
        Schedule API key rotation for a user
        
        Args:
            user_id: User ID to schedule rotation for
            days_from_now: Days from now to schedule rotation (default: config value)
            
        Returns:
            Rotation schedule information
        """
        try:
            if days_from_now is None:
                days_from_now = self.config.rotation_interval_days
            
            rotation_date = datetime.now(timezone.utc) + timedelta(days=days_from_now)
            
            redis_client = await self._get_redis_client()
            schedule_key = f"{self.ROTATION_SCHEDULE_KEY}:{user_id}"
            
            schedule_data = {
                "user_id": str(user_id),
                "scheduled_date": rotation_date.isoformat(),
                "notification_sent": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            
            await redis_client.setex(
                schedule_key,
                timedelta(days=days_from_now + 1),  # Expire after rotation + buffer
                json.dumps(schedule_data)
            )
            
            return {
                "user_id": str(user_id),
                "scheduled_date": rotation_date,
                "days_until_rotation": days_from_now,
                "notification_date": rotation_date - timedelta(days=self.config.notification_days_before)
            }
            
        except Exception as e:
            raise APIKeyRotationError(f"Failed to schedule rotation: {str(e)}")
    
    async def rotate_api_key(self, user_id: uuid.UUID, api_key_id: uuid.UUID) -> Dict[str, Any]:
        """
        Rotate an API key by creating a new version and deprecating the old one
        
        Args:
            user_id: User ID
            api_key_id: API key ID to rotate
            
        Returns:
            New API key information
        """
        try:
            async with get_db_session() as session:
                # Get the current API key
                result = await session.execute(
                    select(APIKey)
                    .where(APIKey.id == api_key_id)
                    .where(APIKey.user_id == user_id)
                    .where(APIKey.is_active == True)
                )
                current_key = result.scalar_one_or_none()
                
                if not current_key:
                    raise APIKeyRotationError("API key not found or already inactive")
                
                # Generate new API key
                new_key_value = self._generate_api_key()
                new_key_hash = self._hash_api_key(new_key_value)
                
                # Create new API key record
                new_api_key = APIKey(
                    id=uuid.uuid4(),
                    user_id=user_id,
                    name=f"{current_key.name} (Rotated)",
                    description=f"Rotated from key {current_key.id}",
                    key_hash=new_key_hash,
                    permissions=current_key.permissions,
                    expires_at=datetime.now(timezone.utc) + timedelta(days=self.config.rotation_interval_days),
                    is_active=True,
                    created_at=datetime.now(timezone.utc)
                )
                
                session.add(new_api_key)
                
                # Deprecate old key (keep for grace period)
                current_key.is_active = False
                current_key.deprecated_at = datetime.now(timezone.utc)
                current_key.replacement_key_id = new_api_key.id
                
                await session.commit()
                
                # Update Redis tracking
                redis_client = await self._get_redis_client()
                
                # Remove old key usage tracking
                old_usage_key = self.KEY_USAGE_KEY.format(key_id=current_key.id)
                await redis_client.delete(old_usage_key)
                
                # Initialize new key usage tracking
                new_usage_key = self.KEY_USAGE_KEY.format(key_id=new_api_key.id)
                await redis_client.setex(
                    new_usage_key,
                    timedelta(days=self.config.rotation_interval_days + self.config.grace_period_days),
                    json.dumps({
                        "usage_count": 0,
                        "first_used": None,
                        "last_used": None,
                        "created_at": datetime.now(timezone.utc).isoformat()
                    })
                )
                
                # Send rotation notification
                await self._send_rotation_notification(user_id, current_key, new_api_key)
                
                return {
                    "old_key_id": str(current_key.id),
                    "new_key_id": str(new_api_key.id),
                    "new_api_key": new_key_value,  # Only returned once for security
                    "key_preview": f"{new_key_value[:12]}...",
                    "expires_at": new_api_key.expires_at,
                    "grace_period_ends": datetime.now(timezone.utc) + timedelta(days=self.config.grace_period_days),
                    "permissions": new_api_key.permissions
                }
                
        except Exception as e:
            raise APIKeyRotationError(f"Failed to rotate API key: {str(e)}")
    
    async def emergency_revoke_key(self, user_id: uuid.UUID, api_key_id: uuid.UUID, reason: str) -> Dict[str, Any]:
        """
        Emergency revocation of an API key
        
        Args:
            user_id: User ID
            api_key_id: API key ID to revoke
            reason: Reason for emergency revocation
            
        Returns:
            Revocation confirmation
        """
        try:
            async with get_db_session() as session:
                # Get the API key
                result = await session.execute(
                    select(APIKey)
                    .where(APIKey.id == api_key_id)
                    .where(APIKey.user_id == user_id)
                )
                api_key = result.scalar_one_or_none()
                
                if not api_key:
                    raise APIKeyRotationError("API key not found")
                
                # Revoke the key immediately
                api_key.is_active = False
                api_key.revoked_at = datetime.now(timezone.utc)
                api_key.revocation_reason = reason
                
                await session.commit()
                
                # Add to emergency revocation list in Redis
                redis_client = await self._get_redis_client()
                revocation_data = {
                    "key_id": str(api_key_id),
                    "user_id": str(user_id),
                    "reason": reason,
                    "revoked_at": datetime.now(timezone.utc).isoformat()
                }
                
                await redis_client.sadd(
                    self.EMERGENCY_REVOCATION_KEY,
                    json.dumps(revocation_data)
                )
                
                # Send emergency revocation notification
                await self._send_emergency_revocation_notification(user_id, api_key, reason)
                
                return {
                    "key_id": str(api_key_id),
                    "revoked_at": api_key.revoked_at,
                    "reason": reason,
                    "status": "revoked"
                }
                
        except Exception as e:
            raise APIKeyRotationError(f"Failed to emergency revoke API key: {str(e)}")
    
    async def cleanup_expired_keys(self) -> Dict[str, Any]:
        """
        Clean up expired and deprecated keys that are past their grace period
        
        Returns:
            Cleanup statistics
        """
        try:
            cleanup_stats = {
                "expired_keys_removed": 0,
                "deprecated_keys_removed": 0,
                "grace_period_expired": 0
            }
            
            async with get_db_session() as session:
                current_time = datetime.now(timezone.utc)
                
                # Find expired keys
                expired_result = await session.execute(
                    select(APIKey)
                    .where(APIKey.expires_at < current_time)
                    .where(APIKey.is_active == True)
                )
                expired_keys = expired_result.scalars().all()
                
                for key in expired_keys:
                    key.is_active = False
                    key.expired_at = current_time
                    cleanup_stats["expired_keys_removed"] += 1
                
                # Find deprecated keys past grace period
                grace_cutoff = current_time - timedelta(days=self.config.grace_period_days)
                deprecated_result = await session.execute(
                    select(APIKey)
                    .where(APIKey.deprecated_at < grace_cutoff)
                    .where(APIKey.deprecated_at.isnot(None))
                )
                deprecated_keys = deprecated_result.scalars().all()
                
                for key in deprecated_keys:
                    # Permanently disable deprecated keys past grace period
                    key.permanently_disabled = True
                    cleanup_stats["grace_period_expired"] += 1
                
                await session.commit()
                
                return cleanup_stats
                
        except Exception as e:
            raise APIKeyRotationError(f"Failed to cleanup expired keys: {str(e)}")
    
    async def get_rotation_status(self, user_id: uuid.UUID) -> Dict[str, Any]:
        """
        Get rotation status for all user's API keys
        
        Args:
            user_id: User ID
            
        Returns:
            Rotation status information
        """
        try:
            async with get_db_session() as session:
                # Get all user's API keys
                result = await session.execute(
                    select(APIKey)
                    .where(APIKey.user_id == user_id)
                    .order_by(APIKey.created_at.desc())
                )
                api_keys = result.scalars().all()
                
                redis_client = await self._get_redis_client()
                rotation_status = []
                
                for key in api_keys:
                    # Check scheduled rotation
                    schedule_key = f"{self.ROTATION_SCHEDULE_KEY}:{user_id}"
                    schedule_data = await redis_client.get(schedule_key)
                    
                    # Get usage statistics
                    usage_key = self.KEY_USAGE_KEY.format(key_id=key.id)
                    usage_data = await redis_client.get(usage_key)
                    usage_stats = json.loads(usage_data) if usage_data else {}
                    
                    # Calculate days until expiration
                    days_until_expiry = None
                    if key.expires_at:
                        days_until_expiry = (key.expires_at - datetime.now(timezone.utc)).days
                    
                    key_status = {
                        "key_id": str(key.id),
                        "name": key.name,
                        "status": "active" if key.is_active else "inactive",
                        "created_at": key.created_at,
                        "expires_at": key.expires_at,
                        "days_until_expiry": days_until_expiry,
                        "usage_count": usage_stats.get("usage_count", 0),
                        "last_used": usage_stats.get("last_used"),
                        "scheduled_rotation": json.loads(schedule_data) if schedule_data else None,
                        "needs_rotation": days_until_expiry is not None and days_until_expiry <= self.config.notification_days_before
                    }
                    
                    rotation_status.append(key_status)
                
                return {
                    "user_id": str(user_id),
                    "total_keys": len(api_keys),
                    "active_keys": len([k for k in api_keys if k.is_active]),
                    "keys_needing_rotation": len([k for k in rotation_status if k.get("needs_rotation", False)]),
                    "rotation_config": asdict(self.config),
                    "keys": rotation_status
                }
                
        except Exception as e:
            raise APIKeyRotationError(f"Failed to get rotation status: {str(e)}")
    
    async def _send_rotation_notification(self, user_id: uuid.UUID, old_key: APIKey, new_key: APIKey):
        """Send notification about API key rotation"""
        try:
            await self.notification_service.send_api_key_rotation_notification(
                user_id=user_id,
                old_key_name=old_key.name,
                new_key_name=new_key.name,
                new_key_preview=f"{new_key.key_hash[:12]}...",
                expires_at=new_key.expires_at,
                grace_period_days=self.config.grace_period_days
            )
        except Exception as e:
            # Log error but don't fail the rotation
            print(f"Failed to send rotation notification: {str(e)}")
    
    async def _send_emergency_revocation_notification(self, user_id: uuid.UUID, api_key: APIKey, reason: str):
        """Send notification about emergency API key revocation"""
        try:
            await self.notification_service.send_emergency_revocation_notification(
                user_id=user_id,
                key_name=api_key.name,
                reason=reason,
                revoked_at=api_key.revoked_at
            )
        except Exception as e:
            # Log error but don't fail the revocation
            print(f"Failed to send emergency revocation notification: {str(e)}")


# Global instance
_api_key_rotation_service = None

def get_api_key_rotation_service() -> APIKeyRotationService:
    """Get global API key rotation service instance"""
    global _api_key_rotation_service
    if _api_key_rotation_service is None:
        _api_key_rotation_service = APIKeyRotationService()
    return _api_key_rotation_service