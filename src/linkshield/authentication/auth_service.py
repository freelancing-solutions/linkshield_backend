#!/usr/bin/env python3
"""
LinkShield Backend Authentication Service

Pure business logic authentication service handling password hashing, JWT token creation,
password validation, and authentication utilities without database dependencies.
"""

import hashlib
import secrets
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional

import bcrypt
import jwt
from email_validator import validate_email, EmailNotValidError

from linkshield.config.settings import get_settings
from linkshield.services.security_service import SecurityService
from linkshield.security.jwt_blacklist import get_jwt_blacklist_service, JWTBlacklistError


class AuthenticationError(Exception):
    """
    Base authentication error.
    """
    pass


class InvalidCredentialsError(AuthenticationError):
    """
    Invalid credentials error.
    """
    pass


class AccountLockedError(AuthenticationError):
    """
    Account locked error.
    """
    pass


class EmailNotVerifiedError(AuthenticationError):
    """
    Email not verified error.
    """
    pass


class TokenExpiredError(AuthenticationError):
    """
    Token expired error.
    """
    pass


class AuthService:
    """
    Pure business logic authentication service.
    
    Handles password hashing, JWT token creation, password validation,
    and authentication utilities without database operations.
    """
    
    def __init__(self, security_service: SecurityService):
        """
        Initialize AuthService with security service dependency.
        
        Args:
            security_service: Security service for validation logic
        """
        self.security_service = security_service
        self.settings = get_settings()
        
        # Security configuration
        self.max_login_attempts = 5
        self.lockout_duration = timedelta(minutes=30)
        self.session_duration = timedelta(days=7)
        self.password_reset_duration = timedelta(hours=1)
        self.email_verification_duration = timedelta(days=1)
    
    def hash_password(self, password: str) -> str:
        """
        Hash password using bcrypt.
        
        Args:
            password: Plain text password
            
        Returns:
            Hashed password string
        """
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def verify_password(self, password: str, password_hash: str) -> bool:
        """
        Verify password against hash.
        
        Args:
            password: Plain text password
            password_hash: Stored password hash
            
        Returns:
            True if password matches hash
        """
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    
    def validate_email_format(self, email: str) -> str:
        """
        Validate and normalize email format.

        Args:
            email: Email address to validate

        Returns:
            Normalized email address

        Raises:
            AuthenticationError: If email format is invalid
        """
        try:
            validated_email = validate_email(email)
            # `ValidatedEmail.normalized` is the recommended attribute
            return getattr(validated_email, 'normalized', validated_email.email)
        except EmailNotValidError as e:
            raise AuthenticationError(f"Invalid email format: {str(e)}")

    def validate_email(self, email: str) -> str:
        """Compatibility alias for validate_email_format used by controllers/routes.

        Returns the normalized email or raises AuthenticationError on invalid input.
        """
        return self.validate_email_format(email)

    def is_password_strong(self, password: str) -> bool:
        """
        Check if password meets strength requirements.
        
        Args:
            password: Password to validate
            
        Returns:
            True if password meets requirements
        """
        if len(password) < 8:
            return False
        
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        return has_upper and has_lower and has_digit and has_special

    def check_password_strength(self, password: str) -> bool:
        """Compatibility alias for is_password_strong used by controllers/routes."""
        return self.is_password_strong(password)

    def create_access_token(
        self, 
        user_id: uuid.UUID, 
        session_id: uuid.UUID, 
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Create JWT access token with unique JTI for blacklist support.
        
        Args:
            user_id: User ID
            session_id: Session ID
            expires_delta: Optional custom expiration time
            
        Returns:
            JWT token string
        """
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + self.session_duration
        
        # Generate unique JWT ID for blacklist support
        jti = str(uuid.uuid4())
        
        payload = {
            "jti": jti,  # JWT ID for blacklist tracking
            "session_id": str(session_id),
            "user_id": str(user_id),
            "exp": expire,
            "iat": datetime.now(timezone.utc)
        }
        
        return jwt.encode(payload, self.settings.SECRET_KEY, algorithm="HS256")
    
    async def verify_jwt_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verify and decode JWT token with blacklist validation.
        
        Args:
            token: JWT token string
            
        Returns:
            Decoded token payload or None if invalid/blacklisted
        """
        try:
            # First check if token is blacklisted
            blacklist_service = get_jwt_blacklist_service()
            if await blacklist_service.is_token_blacklisted(token):
                return None
            
            # Verify JWT signature and expiration
            payload = jwt.decode(token, self.settings.SECRET_KEY, algorithms=["HS256"])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
        except Exception:
            # On any other error (Redis connection, etc.), fail securely
            return None
    
    def generate_secure_token(self, length: int = 32) -> str:
        """
        Generate secure random token.
        
        Args:
            length: Token length in bytes
            
        Returns:
            URL-safe token string
        """
        return secrets.token_urlsafe(length)
    
    def generate_api_key(self) -> str:
        """
        Generate API key with LinkShield prefix.
        
        Returns:
            API key string
        """
        return f"ls_{secrets.token_urlsafe(32)}"
    
    def hash_api_key(self, api_key: str) -> str:
        """
        Hash API key for storage.
        
        Args:
            api_key: Plain API key
            
        Returns:
            Hashed API key
        """
        return hashlib.sha256(api_key.encode()).hexdigest()
    
    def is_account_locked(self, failed_attempts: int, locked_until: Optional[datetime]) -> bool:
        """
        Check if account should be locked based on failed attempts.
        
        Args:
            failed_attempts: Number of failed login attempts
            locked_until: Account lock expiration time
            
        Returns:
            True if account is locked
        """
        if locked_until and locked_until > datetime.now(timezone.utc):
            return True
        
        if failed_attempts >= self.max_login_attempts:
            return True
        
        return False
    
    def calculate_lockout_time(self) -> datetime:
        """
        Calculate account lockout expiration time.
        
        Returns:
            Lockout expiration datetime
        """
        return datetime.now(timezone.utc) + self.lockout_duration
    
    async def logout_user(
        self, 
        token: str, 
        reason: str = "user_logout",
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> bool:
        """
        Logout user by blacklisting their JWT token.
        
        Args:
            token: JWT token to revoke
            reason: Reason for logout
            ip_address: IP address of the request
            user_agent: User agent of the request
            
        Returns:
            True if logout successful, False otherwise
        """
        try:
            blacklist_service = get_jwt_blacklist_service()
            await blacklist_service.blacklist_token(
                token=token,
                reason=reason,
                ip_address=ip_address,
                user_agent=user_agent
            )
            return True
        except JWTBlacklistError:
            return False
        except Exception:
            # Log error in production
            return False
    
    async def revoke_user_tokens(
        self,
        user_id: str,
        reason: str = "security_incident",
        admin_id: Optional[str] = None
    ) -> int:
        """
        Revoke all tokens for a specific user.
        
        Args:
            user_id: User ID whose tokens to revoke
            reason: Reason for revocation
            admin_id: ID of admin performing the action
            
        Returns:
            Number of tokens revoked
        """
        try:
            blacklist_service = get_jwt_blacklist_service()
            return await blacklist_service.blacklist_user_tokens(
                user_id=user_id,
                reason=reason,
                admin_id=admin_id
            )
        except Exception:
            # Log error in production
            return 0
    
    async def is_token_valid(self, token: str) -> bool:
        """
        Check if token is valid (not expired, not blacklisted).
        
        Args:
            token: JWT token to validate
            
        Returns:
            True if token is valid, False otherwise
        """
        payload = await self.verify_jwt_token(token)
        return payload is not None