#!/usr/bin/env python3
"""
JWT Key Management Service

Provides secure JWT secret key rotation, multi-key support, and backward compatibility
during key transitions. Implements automated key rotation schedules and secure key storage.
"""

import json
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

import redis.asyncio as redis
from redis.asyncio import Redis
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

from linkshield.config.settings import get_settings


class KeyStatus(Enum):
    """JWT key status enumeration."""
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    REVOKED = "revoked"


@dataclass
class JWTKey:
    """
    Represents a JWT signing key with metadata.
    """
    key_id: str
    key_value: str
    status: KeyStatus
    created_at: datetime
    expires_at: datetime
    algorithm: str = "HS256"
    usage_count: int = 0
    last_used: Optional[datetime] = None


class JWTKeyManagerError(Exception):
    """Base exception for JWT key management errors."""
    pass


class KeyRotationError(JWTKeyManagerError):
    """Exception raised during key rotation operations."""
    pass


class KeyStorageError(JWTKeyManagerError):
    """Exception raised during key storage operations."""
    pass


class JWTKeyManager:
    """
    JWT Key Management Service with rotation and multi-key support.
    
    Features:
    - Secure key generation and storage
    - Automated key rotation
    - Multi-key support for backward compatibility
    - Key usage tracking and analytics
    - Encrypted key storage in Redis
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.redis_client: Optional[Redis] = None
        
        # Key management configuration
        self.key_rotation_interval = timedelta(days=30)  # Rotate keys every 30 days
        self.key_deprecation_period = timedelta(days=7)  # Keep deprecated keys for 7 days
        self.max_active_keys = 3  # Maximum number of active keys
        self.key_prefix = "linkshield:jwt_keys"
        self.metadata_key = f"{self.key_prefix}:metadata"
        
        # Initialize encryption for key storage
        self._init_encryption()
    
    def _init_encryption(self):
        """Initialize encryption for secure key storage."""
        # Use a derived key from the main secret for key encryption
        password = self.settings.SECRET_KEY.encode()
        salt = b"linkshield_jwt_key_salt"  # Fixed salt for consistency
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        self.fernet = Fernet(key)
    
    async def _get_redis_client(self) -> Redis:
        """Get Redis client connection."""
        if self.redis_client is None:
            self.redis_client = redis.from_url(
                self.settings.REDIS_URL,
                password=self.settings.REDIS_PASSWORD,
                decode_responses=True,
                socket_timeout=self.settings.REDIS_SOCKET_TIMEOUT,
                socket_connect_timeout=self.settings.REDIS_CONNECTION_TIMEOUT
            )
        return self.redis_client
    
    async def close(self):
        """Close Redis connection."""
        if self.redis_client:
            await self.redis_client.close()
            self.redis_client = None
    
    def _generate_key_id(self) -> str:
        """Generate a unique key identifier."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        random_suffix = secrets.token_hex(4)
        return f"jwt_key_{timestamp}_{random_suffix}"
    
    def _generate_secret_key(self, length: int = 64) -> str:
        """Generate a cryptographically secure secret key."""
        return secrets.token_urlsafe(length)
    
    def _encrypt_key(self, key_value: str) -> str:
        """Encrypt a key value for secure storage."""
        return self.fernet.encrypt(key_value.encode()).decode()
    
    def _decrypt_key(self, encrypted_key: str) -> str:
        """Decrypt a key value from storage."""
        return self.fernet.decrypt(encrypted_key.encode()).decode()
    
    async def _store_key(self, jwt_key: JWTKey) -> bool:
        """Store a JWT key in Redis with encryption."""
        try:
            redis_client = await self._get_redis_client()
            
            # Encrypt the key value before storage
            encrypted_key = self._encrypt_key(jwt_key.key_value)
            
            # Create storage object with encrypted key
            storage_data = {
                "key_id": jwt_key.key_id,
                "key_value": encrypted_key,
                "status": jwt_key.status.value,
                "created_at": jwt_key.created_at.isoformat(),
                "expires_at": jwt_key.expires_at.isoformat(),
                "algorithm": jwt_key.algorithm,
                "usage_count": jwt_key.usage_count,
                "last_used": jwt_key.last_used.isoformat() if jwt_key.last_used else None
            }
            
            # Store key data
            key_storage_key = f"{self.key_prefix}:{jwt_key.key_id}"
            await redis_client.hset(key_storage_key, mapping=storage_data)
            
            # Set expiration based on key expiration
            ttl = int((jwt_key.expires_at - datetime.now(timezone.utc)).total_seconds())
            if ttl > 0:
                await redis_client.expire(key_storage_key, ttl)
            
            # Update key list in metadata
            await self._update_key_metadata(jwt_key.key_id, "add")
            
            return True
            
        except Exception as e:
            raise KeyStorageError(f"Failed to store JWT key: {str(e)}")
    
    async def _load_key(self, key_id: str) -> Optional[JWTKey]:
        """Load a JWT key from Redis with decryption."""
        try:
            redis_client = await self._get_redis_client()
            key_storage_key = f"{self.key_prefix}:{key_id}"
            
            key_data = await redis_client.hgetall(key_storage_key)
            if not key_data:
                return None
            
            # Decrypt the key value
            decrypted_key = self._decrypt_key(key_data["key_value"])
            
            # Reconstruct JWTKey object
            return JWTKey(
                key_id=key_data["key_id"],
                key_value=decrypted_key,
                status=KeyStatus(key_data["status"]),
                created_at=datetime.fromisoformat(key_data["created_at"]),
                expires_at=datetime.fromisoformat(key_data["expires_at"]),
                algorithm=key_data["algorithm"],
                usage_count=int(key_data["usage_count"]),
                last_used=datetime.fromisoformat(key_data["last_used"]) if key_data["last_used"] else None
            )
            
        except Exception as e:
            raise KeyStorageError(f"Failed to load JWT key {key_id}: {str(e)}")
    
    async def _update_key_metadata(self, key_id: str, operation: str):
        """Update key metadata list."""
        try:
            redis_client = await self._get_redis_client()
            
            if operation == "add":
                await redis_client.sadd(self.metadata_key, key_id)
            elif operation == "remove":
                await redis_client.srem(self.metadata_key, key_id)
                
        except Exception as e:
            raise KeyStorageError(f"Failed to update key metadata: {str(e)}")
    
    async def create_new_key(self, expires_in_days: int = 37) -> JWTKey:
        """
        Create a new JWT signing key.
        
        Args:
            expires_in_days: Key expiration in days (default: 37 days for overlap)
            
        Returns:
            New JWTKey instance
        """
        try:
            key_id = self._generate_key_id()
            key_value = self._generate_secret_key()
            
            jwt_key = JWTKey(
                key_id=key_id,
                key_value=key_value,
                status=KeyStatus.ACTIVE,
                created_at=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc) + timedelta(days=expires_in_days),
                algorithm="HS256"
            )
            
            await self._store_key(jwt_key)
            return jwt_key
            
        except Exception as e:
            raise KeyRotationError(f"Failed to create new JWT key: {str(e)}")
    
    async def get_active_keys(self) -> List[JWTKey]:
        """Get all active JWT keys."""
        try:
            redis_client = await self._get_redis_client()
            key_ids = await redis_client.smembers(self.metadata_key)
            
            active_keys = []
            for key_id in key_ids:
                jwt_key = await self._load_key(key_id)
                if jwt_key and jwt_key.status == KeyStatus.ACTIVE:
                    # Check if key is still valid
                    if jwt_key.expires_at > datetime.now(timezone.utc):
                        active_keys.append(jwt_key)
                    else:
                        # Auto-expire old keys
                        await self.revoke_key(key_id)
            
            # Sort by creation date (newest first)
            active_keys.sort(key=lambda k: k.created_at, reverse=True)
            return active_keys
            
        except Exception as e:
            raise KeyStorageError(f"Failed to get active keys: {str(e)}")
    
    async def get_current_signing_key(self) -> JWTKey:
        """
        Get the current key for signing new tokens.
        
        Returns:
            The most recent active key
        """
        active_keys = await self.get_active_keys()
        
        if not active_keys:
            # No active keys, create a new one
            return await self.create_new_key()
        
        # Return the newest active key
        return active_keys[0]
    
    async def get_verification_keys(self) -> List[JWTKey]:
        """
        Get all keys that can be used for token verification.
        
        Returns:
            List of active and deprecated keys
        """
        try:
            redis_client = await self._get_redis_client()
            key_ids = await redis_client.smembers(self.metadata_key)
            
            verification_keys = []
            for key_id in key_ids:
                jwt_key = await self._load_key(key_id)
                if jwt_key and jwt_key.status in [KeyStatus.ACTIVE, KeyStatus.DEPRECATED]:
                    # Check if key is still valid for verification
                    if jwt_key.expires_at > datetime.now(timezone.utc):
                        verification_keys.append(jwt_key)
                    else:
                        # Auto-expire old keys
                        await self.revoke_key(key_id)
            
            return verification_keys
            
        except Exception as e:
            raise KeyStorageError(f"Failed to get verification keys: {str(e)}")
    
    async def rotate_keys(self) -> Tuple[JWTKey, List[str]]:
        """
        Perform key rotation: create new key and deprecate old ones.
        
        Returns:
            Tuple of (new_key, deprecated_key_ids)
        """
        try:
            # Get current active keys
            active_keys = await self.get_active_keys()
            
            # Create new signing key
            new_key = await self.create_new_key()
            
            # Deprecate old keys (keep them for verification)
            deprecated_key_ids = []
            for old_key in active_keys:
                if len(active_keys) >= self.max_active_keys:
                    await self.deprecate_key(old_key.key_id)
                    deprecated_key_ids.append(old_key.key_id)
            
            return new_key, deprecated_key_ids
            
        except Exception as e:
            raise KeyRotationError(f"Failed to rotate keys: {str(e)}")
    
    async def deprecate_key(self, key_id: str) -> bool:
        """
        Deprecate a key (keep for verification but don't use for signing).
        
        Args:
            key_id: Key identifier to deprecate
            
        Returns:
            True if successful
        """
        try:
            jwt_key = await self._load_key(key_id)
            if not jwt_key:
                return False
            
            # Update key status
            jwt_key.status = KeyStatus.DEPRECATED
            
            # Extend expiration for deprecation period
            jwt_key.expires_at = datetime.now(timezone.utc) + self.key_deprecation_period
            
            await self._store_key(jwt_key)
            return True
            
        except Exception as e:
            raise KeyStorageError(f"Failed to deprecate key {key_id}: {str(e)}")
    
    async def revoke_key(self, key_id: str) -> bool:
        """
        Revoke a key completely (cannot be used for verification).
        
        Args:
            key_id: Key identifier to revoke
            
        Returns:
            True if successful
        """
        try:
            redis_client = await self._get_redis_client()
            
            # Remove key data
            key_storage_key = f"{self.key_prefix}:{key_id}"
            await redis_client.delete(key_storage_key)
            
            # Update metadata
            await self._update_key_metadata(key_id, "remove")
            
            return True
            
        except Exception as e:
            raise KeyStorageError(f"Failed to revoke key {key_id}: {str(e)}")
    
    async def update_key_usage(self, key_id: str) -> bool:
        """
        Update key usage statistics.
        
        Args:
            key_id: Key identifier
            
        Returns:
            True if successful
        """
        try:
            jwt_key = await self._load_key(key_id)
            if not jwt_key:
                return False
            
            # Update usage statistics
            jwt_key.usage_count += 1
            jwt_key.last_used = datetime.now(timezone.utc)
            
            await self._store_key(jwt_key)
            return True
            
        except Exception as e:
            raise KeyStorageError(f"Failed to update key usage for {key_id}: {str(e)}")
    
    async def check_rotation_needed(self) -> bool:
        """
        Check if key rotation is needed based on age and usage.
        
        Returns:
            True if rotation is needed
        """
        try:
            current_key = await self.get_current_signing_key()
            
            # Check if current key is approaching expiration
            time_until_expiry = current_key.expires_at - datetime.now(timezone.utc)
            
            # Rotate if less than 7 days until expiry
            if time_until_expiry < timedelta(days=7):
                return True
            
            # Check if key is older than rotation interval
            key_age = datetime.now(timezone.utc) - current_key.created_at
            if key_age >= self.key_rotation_interval:
                return True
            
            return False
            
        except Exception:
            # If we can't check, assume rotation is needed for safety
            return True
    
    async def get_key_statistics(self) -> Dict[str, Any]:
        """
        Get key management statistics.
        
        Returns:
            Dictionary with key statistics
        """
        try:
            active_keys = await self.get_active_keys()
            verification_keys = await self.get_verification_keys()
            
            total_usage = sum(key.usage_count for key in verification_keys)
            
            return {
                "active_keys_count": len(active_keys),
                "verification_keys_count": len(verification_keys),
                "total_key_usage": total_usage,
                "current_key_id": active_keys[0].key_id if active_keys else None,
                "rotation_needed": await self.check_rotation_needed(),
                "last_rotation": active_keys[0].created_at.isoformat() if active_keys else None
            }
            
        except Exception as e:
            raise KeyStorageError(f"Failed to get key statistics: {str(e)}")
    
    async def cleanup_expired_keys(self) -> int:
        """
        Clean up expired keys from storage.
        
        Returns:
            Number of keys cleaned up
        """
        try:
            redis_client = await self._get_redis_client()
            key_ids = await redis_client.smembers(self.metadata_key)
            
            cleaned_count = 0
            for key_id in key_ids:
                jwt_key = await self._load_key(key_id)
                if jwt_key and jwt_key.expires_at <= datetime.now(timezone.utc):
                    await self.revoke_key(key_id)
                    cleaned_count += 1
            
            return cleaned_count
            
        except Exception as e:
            raise KeyStorageError(f"Failed to cleanup expired keys: {str(e)}")


# Global instance
_jwt_key_manager: Optional[JWTKeyManager] = None


def get_jwt_key_manager() -> JWTKeyManager:
    """Get the global JWT key manager instance."""
    global _jwt_key_manager
    if _jwt_key_manager is None:
        _jwt_key_manager = JWTKeyManager()
    return _jwt_key_manager