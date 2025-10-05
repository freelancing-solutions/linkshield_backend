#!/usr/bin/env python3
"""
LinkShield Backend Token Service

Service for JWT token generation, validation, and management.
Integrates with the blacklist service and JWT key manager for secure token revocation
and key rotation support.
"""

import logging
import uuid
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone, timedelta
import jwt

from linkshield.security.jwt_blacklist import get_jwt_blacklist_service, JWTBlacklistService, BlacklistReason
from linkshield.security.jwt_key_manager import get_jwt_key_manager, JWTKeyManager
from linkshield.config.settings import get_settings
from linkshield.models.user import User

logger = logging.getLogger(__name__)


class TokenGenerationError(Exception):
    """Exception raised when token generation fails."""
    pass


class TokenValidationError(Exception):
    """Exception raised when token validation fails."""
    pass


class TokenService:
    """
    Service for JWT token operations including generation, validation, and revocation.
    
    Provides comprehensive token management with blacklist integration and JWT key
    rotation support for enhanced security.
    """
    
    def __init__(
        self, 
        blacklist_service: Optional[JWTBlacklistService] = None,
        key_manager: Optional[JWTKeyManager] = None
    ):
        """
        Initialize the token service.
        
        Args:
            blacklist_service: JWT blacklist service instance
            key_manager: JWT key manager instance
        """
        self.blacklist_service = blacklist_service or get_jwt_blacklist_service()
        self.key_manager = key_manager or get_jwt_key_manager()
        self.settings = get_settings()
        self.logger = logger
        
        # Token configuration
        self.access_token_expire_minutes = getattr(self.settings, 'ACCESS_TOKEN_EXPIRE_MINUTES', 30)
        self.refresh_token_expire_days = getattr(self.settings, 'REFRESH_TOKEN_EXPIRE_DAYS', 7)
        self.algorithm = getattr(self.settings, 'JWT_ALGORITHM', 'HS256')
        # Note: secret_key is now managed by the key manager
        self.secret_key = getattr(self.settings, 'JWT_SECRET_KEY', 'your-secret-key')
    
    async def generate_access_token(
        self,
        user: User,
        additional_claims: Optional[Dict[str, Any]] = None,
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Generate an access token for a user using the current signing key.
        
        Args:
            user: User object
            additional_claims: Additional claims to include
            expires_delta: Custom expiration time
            
        Returns:
            JWT access token string
            
        Raises:
            TokenGenerationError: If token generation fails
        """
        try:
            # Get current signing key from key manager
            current_key = await self.key_manager.get_current_signing_key()
            
            # Calculate expiration time
            if expires_delta:
                expire = datetime.now(timezone.utc) + expires_delta
            else:
                expire = datetime.now(timezone.utc) + timedelta(minutes=self.access_token_expire_minutes)
            
            # Generate unique token ID
            jti = str(uuid.uuid4())
            
            # Build token payload
            payload = {
                "sub": str(user.id),  # Subject (user ID)
                "username": user.username,
                "email": user.email,
                "roles": [role.name for role in user.roles] if hasattr(user, 'roles') else [],
                "jti": jti,  # JWT ID for blacklist tracking
                "kid": current_key.key_id,  # Key ID for verification
                "type": "access",
                "iat": datetime.now(timezone.utc),  # Issued at
                "exp": expire,  # Expiration time
                "iss": "linkshield-backend",  # Issuer
                "aud": "linkshield-client"  # Audience
            }
            
            # Add additional claims if provided
            if additional_claims:
                payload.update(additional_claims)
            
            # Generate token using current key
            token = jwt.encode(
                payload,
                current_key.key_value,
                algorithm=current_key.algorithm,
                headers={"kid": current_key.key_id}
            )
            
            # Update key usage statistics
            await self.key_manager.update_key_usage(current_key.key_id)
            
            self.logger.info(f"Generated access token for user {user.id} with key {current_key.key_id}")
            return token
            
        except Exception as e:
            self.logger.error(f"Failed to generate access token for user {user.id}: {e}")
            raise TokenGenerationError(f"Token generation failed: {e}")
    
    async def generate_refresh_token(
        self,
        user: User,
        additional_claims: Optional[Dict[str, Any]] = None,
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Generate a refresh token for a user using the current signing key.
        
        Args:
            user: User object
            additional_claims: Additional claims to include
            expires_delta: Custom expiration time
            
        Returns:
            JWT refresh token string
            
        Raises:
            TokenGenerationError: If token generation fails
        """
        try:
            # Get current signing key from key manager
            current_key = await self.key_manager.get_current_signing_key()
            
            # Calculate expiration time
            if expires_delta:
                expire = datetime.now(timezone.utc) + expires_delta
            else:
                expire = datetime.now(timezone.utc) + timedelta(days=self.refresh_token_expire_days)
            
            # Generate unique token ID
            jti = str(uuid.uuid4())
            
            # Build token payload (minimal for refresh tokens)
            payload = {
                "sub": str(user.id),
                "username": user.username,
                "jti": jti,
                "kid": current_key.key_id,  # Key ID for verification
                "type": "refresh",
                "iat": datetime.now(timezone.utc),
                "exp": expire,
                "iss": "linkshield-backend",
                "aud": "linkshield-client"
            }
            
            # Add additional claims if provided
            if additional_claims:
                payload.update(additional_claims)
            
            # Generate token using current key
            token = jwt.encode(
                payload,
                current_key.key_value,
                algorithm=current_key.algorithm,
                headers={"kid": current_key.key_id}
            )
            
            # Update key usage statistics
            await self.key_manager.update_key_usage(current_key.key_id)
            
            self.logger.info(f"Generated refresh token for user {user.id} with key {current_key.key_id}")
            return token
            
        except Exception as e:
            self.logger.error(f"Failed to generate refresh token for user {user.id}: {e}")
            raise TokenGenerationError(f"Token generation failed: {e}")
    
    async def generate_token_pair(
        self,
        user: User,
        additional_claims: Optional[Dict[str, Any]] = None
    ) -> Dict[str, str]:
        """
        Generate both access and refresh tokens for a user.
        
        Args:
            user: User object
            additional_claims: Additional claims to include
            
        Returns:
            Dictionary with access_token and refresh_token
            
        Raises:
            TokenGenerationError: If token generation fails
        """
        try:
            access_token = await self.generate_access_token(user, additional_claims)
            refresh_token = await self.generate_refresh_token(user, additional_claims)
            
            return {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
                "expires_in": self.access_token_expire_minutes * 60  # seconds
            }
            
        except Exception as e:
            self.logger.error(f"Error generating token pair for user {user.id}: {e}")
            raise TokenGenerationError(f"Failed to generate token pair: {e}")
    
    async def validate_token(self, token: str) -> Dict[str, Any]:
        """
        Validate a JWT token using key manager and check blacklist.
        
        Args:
            token: JWT token string
            
        Returns:
            Decoded token payload
            
        Raises:
            TokenValidationError: If token is invalid or blacklisted
        """
        try:
            # First check if token is blacklisted
            is_blacklisted = await self.blacklist_service.is_token_blacklisted(token)
            if is_blacklisted:
                entry = await self.blacklist_service.get_blacklist_entry(token)
                reason = entry.reason.value if entry else "unknown"
                raise TokenValidationError(f"Token is blacklisted: {reason}")
            
            # Decode token header to get key ID
            unverified_header = jwt.get_unverified_header(token)
            key_id = unverified_header.get("kid")
            
            if not key_id:
                # Fallback to legacy validation for tokens without key ID
                payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            else:
                # Get verification key from key manager
                verification_key = await self.key_manager.get_verification_key(key_id)
                if not verification_key:
                    raise TokenValidationError(f"Unknown key ID: {key_id}")
                
                # Decode and validate JWT with specific key
                payload = jwt.decode(
                    token,
                    verification_key.key_value,
                    algorithms=[verification_key.algorithm]
                )
            
            # Additional validation
            self._validate_token_payload(payload)
            
            return payload
            
        except jwt.ExpiredSignatureError:
            raise TokenValidationError("Token has expired")
        except jwt.InvalidTokenError as e:
            raise TokenValidationError(f"Invalid token: {e}")
        except TokenValidationError:
            raise  # Re-raise validation errors
        except Exception as e:
            self.logger.error(f"Unexpected error validating token: {e}")
            raise TokenValidationError(f"Token validation failed: {e}")
    
    def _validate_token_payload(self, payload: Dict[str, Any]) -> None:
        """
        Validate token payload claims.
        
        Args:
            payload: Decoded JWT payload
            
        Raises:
            TokenValidationError: If payload is invalid
        """
        # Check required claims
        required_claims = ["sub", "jti", "type", "iat", "exp", "iss", "aud"]
        for claim in required_claims:
            if claim not in payload:
                raise TokenValidationError(f"Missing required claim: {claim}")
        
        # Validate issuer and audience
        if payload.get("iss") != "linkshield-backend":
            raise TokenValidationError("Invalid token issuer")
        
        if payload.get("aud") != "linkshield-client":
            raise TokenValidationError("Invalid token audience")
        
        # Validate token type
        token_type = payload.get("type")
        if token_type not in ["access", "refresh"]:
            raise TokenValidationError(f"Invalid token type: {token_type}")
    
    async def revoke_token(
        self,
        token: str,
        reason: str = "user_logout",
        admin_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> bool:
        """
        Revoke a JWT token by adding it to the blacklist.
        
        Args:
            token: JWT token to revoke
            reason: Reason for revocation
            admin_id: ID of admin performing revocation
            ip_address: IP address of the request
            user_agent: User agent of the request
            
        Returns:
            Success status
        """
        try:
            # Validate reason
            if reason not in [r.value for r in BlacklistReason]:
                reason = BlacklistReason.USER_LOGOUT.value
            
            # Add to blacklist
            entry = await self.blacklist_service.blacklist_token(
                token=token,
                reason=reason,
                admin_id=admin_id,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            self.logger.info(f"Token revoked: {entry.jti} (reason: {reason})")
            return True
            
        except Exception as e:
            self.logger.error(f"Error revoking token: {e}")
            return False
    
    async def revoke_user_tokens(
        self,
        user_id: str,
        reason: str = "security_incident",
        admin_id: Optional[str] = None,
        exclude_current_session: bool = True,
        current_session_id: Optional[str] = None
    ) -> int:
        """
        Revoke all tokens for a specific user.
        
        Args:
            user_id: User ID whose tokens to revoke
            reason: Reason for bulk revocation
            admin_id: ID of admin performing revocation
            exclude_current_session: Whether to exclude current session
            current_session_id: Current session ID to exclude
            
        Returns:
            Number of tokens revoked
        """
        try:
            # Validate reason
            if reason not in [r.value for r in BlacklistReason]:
                reason = BlacklistReason.SECURITY_INCIDENT.value
            
            # Perform bulk revocation
            revoked_count = await self.blacklist_service.blacklist_user_tokens(
                user_id=user_id,
                reason=reason,
                admin_id=admin_id
            )
            
            self.logger.info(
                f"Bulk token revocation for user {user_id}: {revoked_count} tokens (reason: {reason})"
            )
            
            return revoked_count
            
        except Exception as e:
            self.logger.error(f"Error in bulk token revocation for user {user_id}: {e}")
            return 0
    
    async def refresh_access_token(self, refresh_token: str) -> Dict[str, str]:
        """
        Generate a new access token using a refresh token.
        
        Args:
            refresh_token: Valid refresh token
            
        Returns:
            New token pair
            
        Raises:
            TokenValidationError: If refresh token is invalid
        """
        try:
            # Validate refresh token
            payload = await self.validate_token(refresh_token)
            
            # Check token type
            if payload.get("type") != "refresh":
                raise TokenValidationError("Invalid token type for refresh")
            
            # Get user information from token
            user_id = payload.get("sub")
            username = payload.get("username")
            
            # Create a minimal user object for token generation
            # In a real implementation, you might fetch the full user from database
            class MinimalUser:
                def __init__(self, id: str, username: str):
                    self.id = id
                    self.username = username
                    self.email = f"{username}@example.com"  # Placeholder
                    self.roles = []  # Would be fetched from database
            
            user = MinimalUser(user_id, username)
            
            # Generate new token pair
            new_tokens = await self.generate_token_pair(user)
            
            # Optionally revoke the old refresh token
            await self.revoke_token(refresh_token, reason="token_refresh")
            
            return new_tokens
            
        except TokenValidationError:
            raise
        except Exception as e:
            self.logger.error(f"Error refreshing access token: {e}")
            raise TokenValidationError(f"Token refresh failed: {e}")
    
    async def get_token_info(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a token without full validation.
        
        Args:
            token: JWT token string
            
        Returns:
            Token information or None if invalid
        """
        try:
            # Decode without verification for info purposes
            payload = jwt.decode(token, options={"verify_signature": False})
            
            # Check if blacklisted
            is_blacklisted = await self.blacklist_service.is_token_blacklisted(token)
            blacklist_entry = None
            if is_blacklisted:
                blacklist_entry = await self.blacklist_service.get_blacklist_entry(token)
            
            return {
                "jti": payload.get("jti"),
                "user_id": payload.get("sub"),
                "username": payload.get("username"),
                "type": payload.get("type"),
                "issued_at": payload.get("iat"),
                "expires_at": payload.get("exp"),
                "is_blacklisted": is_blacklisted,
                "blacklist_reason": blacklist_entry.reason.value if blacklist_entry else None,
                "blacklist_date": blacklist_entry.revoked_at.isoformat() if blacklist_entry else None
            }
            
        except Exception as e:
            self.logger.error(f"Error getting token info: {e}")
            return None
    
    async def cleanup_expired_tokens(self) -> int:
        """
        Clean up expired tokens from the blacklist.
        
        Returns:
            Number of tokens cleaned up
        """
        try:
            cleaned_count = await self.blacklist_service.cleanup_expired_entries()
            self.logger.info(f"Cleaned up {cleaned_count} expired blacklist entries")
            return cleaned_count
            
        except Exception as e:
            self.logger.error(f"Error cleaning up expired tokens: {e}")
            return 0
    
    async def get_service_stats(self) -> Dict[str, Any]:
        """
        Get token service statistics.
        
        Returns:
            Service statistics
        """
        try:
            blacklist_stats = await self.blacklist_service.get_blacklist_stats()
            
            return {
                "service": "token_service",
                "blacklist_stats": blacklist_stats,
                "configuration": {
                    "access_token_expire_minutes": self.access_token_expire_minutes,
                    "refresh_token_expire_days": self.refresh_token_expire_days,
                    "algorithm": self.algorithm
                },
                "last_updated": datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error getting service stats: {e}")
            return {}


# Global instance for easy access
_token_service: Optional[TokenService] = None


def get_token_service(blacklist_service: Optional[JWTBlacklistService] = None) -> TokenService:
    """
    Get or create the global token service instance.
    
    Args:
        blacklist_service: JWT blacklist service instance
        
    Returns:
        TokenService instance
    """
    global _token_service
    
    if _token_service is None:
        _token_service = TokenService(blacklist_service=blacklist_service)
    
    return _token_service