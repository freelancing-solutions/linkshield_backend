"""User controller for handling user management business logic.

This module contains the UserController class that handles all business logic
for user authentication, registration, profile management, API key management,
session management, and email verification. It now includes database operations
that were previously in AuthService and EmailService.
"""

import uuid
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple

from fastapi import HTTPException, status, BackgroundTasks, Request
from sqlalchemy.orm import Session
from sqlalchemy import and_, desc
from sqlalchemy.exc import IntegrityError

from src.controllers.base_controller import BaseController
from src.models.user import (
    User, UserSession, APIKey, PasswordResetToken,
    EmailVerificationToken
)
from src.models.email import EmailLog, EmailType, EmailRequest

from src.services.security_service import SecurityService
from src.authentication.auth_service import AuthService
from src.services.email_service import EmailService
from src.services.background_tasks import BackgroundEmailService


class InvalidCredentialsError(Exception):
    """Exception raised for invalid user credentials."""
    pass


class UserRegistrationError(Exception):
    """Exception raised for user registration errors."""
    pass


class UserController(BaseController):
    """Controller for user management operations.
    
    Handles all business logic related to user management including:
    - User registration and authentication
    - Profile management
    - Password management
    - API key management
    - Session management
    - Email verification
    - Account settings
    """
    
    def __init__(
        self,
        security_service: SecurityService,
        auth_service: AuthService,
        email_service: EmailService,
        background_email_service: BackgroundEmailService = None
    ):
        """Initialize user controller.
        
        Args:
            security_service: Security service for validation
            auth_service: Authentication service
            email_service: Email service for sending emails
            background_email_service: Background email service for async operations
        """
        super().__init__(security_service, auth_service, email_service)
        self.background_email_service = background_email_service
        
        # Rate limits
        self.registration_rate_limit = 5  # per hour
        self.login_rate_limit = 10  # per 15 minutes
        self.password_reset_rate_limit = 3  # per hour
        self.api_key_rate_limit = 10  # per day
    
    async def register_user(
        self,
        email: str,
        password: str,
        full_name: str,
        company: Optional[str] = None,
        accept_terms: bool = False,
        marketing_consent: bool = False,
        request: Optional[Request] = None,
        background_tasks: Optional[BackgroundTasks] = None
    ) -> User:
        """Register a new user account.
        
        Args:
            email: User email address
            password: User password
            full_name: User full name
            company: Company name (optional)
            accept_terms: Terms of service acceptance
            marketing_consent: Marketing communications consent
            request: HTTP request for rate limiting
            background_tasks: FastAPI background tasks
            
        Returns:
            User: Created user instance
            
        Raises:
            HTTPException: If registration fails or rate limit exceeded
        """
        # Validate terms acceptance
        if not accept_terms:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Terms of service must be accepted"
            )
        
        # Check registration rate limits
        if request:
            client_ip = request.client.host
            if not await self.check_rate_limit(
                client_ip, "registration", self.registration_rate_limit, window_seconds=3600
            ):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Registration rate limit exceeded. Please try again later."
                )
        
        # Validate email format
        if not self.auth_service.validate_email(email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email format"
            )
        
        # Validate password strength
        if not self.auth_service.check_password_strength(password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password does not meet security requirements"
            )
        
        try:
            async with self.get_db_session() as db:
                # Check if user already exists
                existing_user = (
                    db.query(User)
                    .filter(User.email == email.lower())
                    .first()
                )
                
                if existing_user:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="User with this email already exists"
                    )
                
                # Hash password
                password_hash = self.auth_service.hash_password(password)
                
                # Create user
                user = User(
                    id=uuid.uuid4(),
                    email=email.lower(),
                    password_hash=password_hash,
                    full_name=full_name,
                    company=company,
                    marketing_consent=marketing_consent,
                    is_active=True,
                    is_verified=False,
                    subscription_tier="free",
                    created_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc)
                )
                
                db.add(user)
                db.commit()
                db.refresh(user)
            
            # Create email verification token
            verification_token = await self._create_email_verification_token(user)
            
            # Queue verification email for background sending
            if self.background_email_service:
                self.background_email_service.queue_verification_email(
                    email,
                    full_name.split()[0] if full_name else "User",  # First name
                    verification_token.token
                )
            elif background_tasks:
                background_tasks.add_task(
                    self._send_verification_email,
                    email,
                    full_name,
                    verification_token.token
                )
            
            # Log the operation
            self.log_operation(
                "User registered",
                user_id=user.id,
                details={
                    "email": email,
                    "full_name": full_name,
                    "company": company,
                    "marketing_consent": marketing_consent
                }
            )
            
            return user
            
        except HTTPException:
            raise
        except IntegrityError:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User with this email already exists"
            )
        except Exception as e:
            raise self.handle_database_error(e, "user registration")
    
    async def login_user(
        self,
        email: str,
        password: str,
        remember_me: bool = False,
        device_info: Optional[Dict[str, str]] = None,
        request: Optional[Request] = None
    ) -> Tuple[str, User, UserSession]:
        """Authenticate user and create session.
        
        Args:
            email: User email address
            password: User password
            remember_me: Extended session duration
            device_info: Device information
            request: HTTP request for rate limiting
            
        Returns:
            Tuple: (access_token, user, session)
            
        Raises:
            HTTPException: If authentication fails or rate limit exceeded
        """
        # Check login rate limits
        if request:
            client_ip = request.client.host
            if not await self.check_rate_limit(
                client_ip, "login", self.login_rate_limit, window_seconds=900
            ):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Login rate limit exceeded. Please try again later."
                )
        
        try:
            async with self.get_db_session() as db:
                # Find user by email
                user = (
                    db.query(User)
                    .filter(User.email == email.lower())
                    .first()
                )
                
                if not user:
                    raise InvalidCredentialsError("Invalid email or password")
                
                # Check if account is locked
                if self._is_account_locked(user):
                    raise HTTPException(
                        status_code=status.HTTP_423_LOCKED,
                        detail="Account is temporarily locked due to too many failed login attempts"
                    )
                
                # Verify password
                if not self.auth_service.verify_password(password, user.password_hash):
                    # Record failed login attempt
                    await self._record_failed_login(user)
                    raise InvalidCredentialsError("Invalid email or password")
                
                # Reset failed login attempts on successful login
                user.failed_login_attempts = 0
                user.locked_until = None
                
                if not user.is_active:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Account is deactivated"
                    )
                
                # Update last login timestamp
                user.last_login_at = datetime.now(timezone.utc)
                db.add(user)
                db.commit()
                db.refresh(user)
            
            # Create user session
            session_duration = timedelta(days=30 if remember_me else 1)
            session = await self._create_user_session(
                user, session_duration, device_info, request
            )
            
            # Generate access token
            access_token = self.auth_service.create_access_token(
                user_id=user.id,
                session_id=session.id,
                expires_delta=session_duration
            )
            
            # Log the operation
            self.log_operation(
                "User logged in",
                user_id=user.id,
                details={
                    "email": email,
                    "remember_me": remember_me,
                    "session_id": str(session.id)
                }
            )
            
            return access_token, user, session
            
        except InvalidCredentialsError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        except HTTPException:
            raise
        except Exception as e:
            raise self.handle_database_error(e, "user login")
    
    async def logout_user(
        self,
        user: User,
        session_id: Optional[uuid.UUID] = None
    ) -> None:
        """Logout user and invalidate session.
        
        Args:
            user: Current user
            session_id: Session ID to invalidate
            
        Raises:
            HTTPException: If logout fails
        """
        try:
            async with self.get_db_session() as session:
                if session_id:
                    # Invalidate specific session
                    session_obj = (
                        session.query(UserSession)
                        .filter(
                            and_(
                                UserSession.id == session_id,
                                UserSession.user_id == user.id,
                                UserSession.is_active == True
                            )
                        )
                        .first()
                    )
                    
                    if session_obj:
                        session_obj.is_active = False
                        session_obj.ended_at = datetime.utcnow()
                else:
                    # Invalidate all user sessions
                    session.query(UserSession).filter(
                        and_(
                            UserSession.user_id == user.id,
                            UserSession.is_active == True
                        )
                    ).update({
                        "is_active": False,
                        "ended_at": datetime.utcnow()
                    })
            
            # Log the operation
            self.log_operation(
                "User logged out",
                user_id=user.id,
                details={"session_id": str(session_id) if session_id else "all_sessions"}
            )
            
        except Exception as e:
            raise self.handle_database_error(e, "user logout")
    
    async def get_user_profile(self, user: User) -> User:
        """Get user profile information.
        
        Args:
            user: Current user
            
        Returns:
            User: User profile data
        """
        self.log_operation(
            "User profile retrieved",
            user_id=user.id
        )
        
        return user
    
    async def update_user_profile(
        self,
        user: User,
        full_name: Optional[str] = None,
        company: Optional[str] = None,
        profile_picture_url: Optional[str] = None,
        marketing_consent: Optional[bool] = None,
        timezone: Optional[str] = None,
        language: Optional[str] = None
    ) -> User:
        """Update user profile information.
        
        Args:
            user: Current user
            full_name: Updated full name
            company: Updated company
            profile_picture_url: Updated profile picture URL
            marketing_consent: Updated marketing consent
            timezone: Updated timezone
            language: Updated language
            
        Returns:
            User: Updated user instance
            
        Raises:
            HTTPException: If update fails
        """
        try:
            # Update provided fields
            if full_name is not None:
                user.full_name = full_name
            if company is not None:
                user.company = company
            if profile_picture_url is not None:
                user.profile_picture_url = profile_picture_url
            if marketing_consent is not None:
                user.marketing_consent = marketing_consent
            if timezone is not None:
                user.timezone = timezone
            if language is not None:
                user.language = language
            
            user.updated_at = datetime.now(timezone.utc)
            
            async with self.get_db_session() as session:
                session.add(user)
                await session.refresh(user)
            
            # Log the operation
            self.log_operation(
                "User profile updated",
                user_id=user.id,
                details={
                    "updated_fields": {
                        "full_name": full_name,
                        "company": company,
                        "marketing_consent": marketing_consent,
                        "timezone": timezone,
                        "language": language
                    }
                }
            )
            
            return user
            
        except Exception as e:
            raise self.handle_database_error(e, "profile update")
    
    async def change_password(
        self,
        user: User,
        current_password: str,
        new_password: str
    ) -> None:
        """Change user password.
        
        Args:
            user: Current user
            current_password: Current password for verification
            new_password: New password
            
        Raises:
            HTTPException: If password change fails
        """
        try:
            # Verify current password
            if not self.auth_service.verify_password(current_password, user.password_hash):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Current password is incorrect"
                )
            
            # Check if new password is different
            if self.auth_service.verify_password(new_password, user.password_hash):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="New password must be different from current password"
                )
            
            # Validate new password strength
            if not self.auth_service.check_password_strength(new_password):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="New password does not meet security requirements"
                )
            
            # Update password and invalidate sessions within context manager
            async with self.get_db_session() as db:
                user.password_hash = self.auth_service.hash_password(new_password)
                user.password_changed_at = datetime.now(timezone.utc)
                user.updated_at = datetime.now(timezone.utc)
                
                # Invalidate all existing sessions except current one
                # This forces re-authentication on other devices
                db.query(UserSession).filter(
                    and_(
                        UserSession.user_id == user.id,
                        UserSession.is_active == True
                    )
                ).update({
                    "is_active": False,
                    "ended_at": datetime.now(timezone.utc)
                })
                
                db.add(user)
                db.commit()
            
            # Log the operation
            self.log_operation(
                "Password changed",
                user_id=user.id,
                details={"sessions_invalidated": True}
            )
            
        except HTTPException:
            raise
        except Exception as e:
            raise self.handle_database_error(e, "password change")
    
    async def request_password_reset(
        self,
        email: str,
        request: Optional[Request] = None,
        background_tasks: Optional[BackgroundTasks] = None
    ) -> None:
        """Request password reset for user.
        
        Args:
            email: User email address
            request: HTTP request for rate limiting
            background_tasks: FastAPI background tasks
            
        Raises:
            HTTPException: If rate limit exceeded
        """
        # Check password reset rate limits
        if request:
            client_ip = request.client.host
            if not await self.check_rate_limit(
                client_ip, "password_reset", self.password_reset_rate_limit, window_seconds=3600
            ):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Password reset rate limit exceeded. Please try again later."
                )
        
        # Find user by email within context manager
        async with self.get_db_session() as session:
            user = (
                session.query(User)
                .filter(User.email == email.lower())
                .first()
            )
        
        # Always return success to prevent email enumeration
        if user and user.is_active:
            try:
                # Create password reset token
                reset_token = await self._create_password_reset_token(user)
                
                # Queue password reset email for background sending
                if self.background_email_service:
                    self.background_email_service.queue_password_reset_email(
                        email,
                        user.full_name.split()[0] if user.full_name else "User",  # First name
                        reset_token.token
                    )
                elif background_tasks:
                    background_tasks.add_task(
                        self._send_password_reset_email,
                        user,
                        reset_token.token
                    )
                
                # Log the operation
                self.log_operation(
                    "Password reset requested",
                    user_id=user.id,
                    details={"email": email}
                )
                
            except Exception as e:
                # Log error but don't expose it to prevent enumeration
                self.logger.error(f"Password reset failed for {email}: {str(e)}")
    
    async def reset_password(
        self,
        token: str,
        new_password: str,
        request: Optional[Request] = None
    ) -> None:
        """Reset password using reset token.
        
        Args:
            token: Password reset token
            new_password: New password
            request: HTTP request for logging
            
        Raises:
            HTTPException: If token is invalid or expired
        """
        try:
            # Validate new password strength
            if not self.auth_service.check_password_strength(new_password):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="New password does not meet security requirements"
                )
            
            # Find and validate reset token within context manager
            async with self.get_db_session() as db:
                reset_token = (
                    db.query(PasswordResetToken)
                    .filter(
                        and_(
                            PasswordResetToken.token == token,
                            PasswordResetToken.is_used == False,
                            PasswordResetToken.expires_at > datetime.now(timezone.utc)
                        )
                    )
                    .first()
                )
                
                if not reset_token:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Invalid or expired reset token"
                    )
                
                # Get user
                user = (
                    db.query(User)
                    .filter(User.id == reset_token.user_id)
                    .first()
                )
                
                if not user or not user.is_active:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Invalid reset token"
                    )
                
                # Update password
                user.password_hash = self.auth_service.hash_password(new_password)
                user.password_changed_at = datetime.now(timezone.utc)
                user.updated_at = datetime.now(timezone.utc)
                
                # Mark token as used
                reset_token.is_used = True
                reset_token.used_at = datetime.now(timezone.utc)
                
                # Invalidate all user sessions
                db.query(UserSession).filter(
                    and_(
                        UserSession.user_id == user.id,
                        UserSession.is_active == True
                    )
                ).update({
                    "is_active": False,
                    "ended_at": datetime.now(timezone.utc)
                })
                
                db.add(user)
                db.add(reset_token)
                db.commit()
            
            # Log the operation
            self.log_operation(
                "Password reset completed",
                user_id=user.id,
                details={"token_id": str(reset_token.id)}
            )
            
        except HTTPException:
            raise
        except Exception as e:
            raise self.handle_database_error(e, "password reset")
    
    async def create_api_key(
        self,
        user: User,
        name: str,
        description: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        permissions: List[str] = None
    ) -> Tuple[APIKey, str]:
        """Create API key for user.
        
        Args:
            user: Current user
            name: API key name
            description: API key description
            expires_at: Expiration date
            permissions: API key permissions
            
        Returns:
            Tuple: (api_key, raw_key)
            
        Raises:
            HTTPException: If creation fails or rate limit exceeded
        """
        # Check API key rate limits
        if not await self.check_rate_limit(
            user.id, "api_key_creation", self.api_key_rate_limit, window_seconds=86400
        ):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="API key creation rate limit exceeded"
            )
        
        # Set default permissions
        if permissions is None:
            permissions = ["url_check"]
        
        # Validate permissions
        valid_permissions = ["url_check", "report_create", "report_read", "admin"]
        invalid_perms = set(permissions) - set(valid_permissions)
        if invalid_perms:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid permissions: {', '.join(invalid_perms)}"
            )
        
        # Check if user already has too many API keys within context manager
        async with self.get_db_session() as session:
            existing_keys_count = (
                session.query(APIKey)
                .filter(
                    and_(
                        APIKey.user_id == user.id,
                        APIKey.is_active == True
                    )
                )
                .count()
            )
        
        max_keys = 10 if user.subscription_tier == "premium" else 3
        if existing_keys_count >= max_keys:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Maximum {max_keys} API keys allowed"
            )
        
        try:
            # Generate API key
            raw_key = secrets.token_urlsafe(32)
            key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
            
            # Create API key record within context manager
            async with self.get_db_session() as db:
                api_key = APIKey(
                    id=uuid.uuid4(),
                    user_id=user.id,
                    name=name,
                    description=description,
                    key_hash=key_hash,
                    key_preview=raw_key[:8] + "...",
                    permissions=permissions,
                    expires_at=expires_at,
                    is_active=True,
                    created_at=datetime.now(timezone.utc)
                )
                
                db.add(api_key)
                db.commit()
                db.refresh(api_key)
            
            # Log the operation
            self.log_operation(
                "API key created",
                user_id=user.id,
                details={
                    "key_id": str(api_key.id),
                    "name": name,
                    "permissions": permissions
                }
            )
            
            return api_key, raw_key
            
        except Exception as e:
            raise self.handle_database_error(e, "API key creation")
    
    async def list_api_keys(
        self,
        user: User,
        request: Optional[Request] = None
    ) -> List[Dict[str, Any]]:
        """List user's API keys.
        
        Args:
            user: User to list API keys for
            request: HTTP request for logging
            
        Returns:
            List of API key info (without raw keys)
        """
        try:
            async with self.get_db_session() as db:
                api_keys = (
                    db.query(APIKey)
                    .filter(
                        and_(
                            APIKey.user_id == user.id,
                            APIKey.is_active == True
                        )
                    )
                    .order_by(APIKey.created_at.desc())
                    .all()
                )
            
            return [
                {
                    "id": str(key.id),
                    "name": key.name,
                    "description": key.description,
                    "key_preview": key.key_preview,
                    "permissions": key.permissions,
                    "expires_at": key.expires_at.isoformat() if key.expires_at else None,
                    "last_used_at": key.last_used_at.isoformat() if key.last_used_at else None,
                    "created_at": key.created_at.isoformat()
                }
                for key in api_keys
            ]
            
        except Exception as e:
            raise self.handle_database_error(e, "API key listing")
    
    async def delete_api_key(
        self,
        user: User,
        key_id: uuid.UUID
    ) -> None:
        """Delete user's API key.
        
        Args:
            user: Current user
            key_id: API key ID to delete
            
        Raises:
            HTTPException: If key not found or access denied
        """
        try:
            async with self.get_db_session() as db:
                api_key = (
                    db.query(APIKey)
                    .filter(
                        and_(
                            APIKey.id == key_id,
                            APIKey.user_id == user.id,
                            APIKey.is_active == True
                        )
                    )
                    .first()
                )
                
                if not api_key:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="API key not found"
                    )
                
                # Soft delete API key
                api_key.is_active = False
                api_key.deleted_at = datetime.now(timezone.utc)
                
                db.add(api_key)
                db.commit()
            
            # Log the operation
            self.log_operation(
                "API key deleted",
                user_id=user.id,
                details={"key_id": str(key_id), "name": api_key.name}
            )
                
        except HTTPException:
            raise
        except Exception as e:
            raise self.handle_database_error(e, "API key deletion")
    
    async def list_user_sessions(
        self,
        user: User,
        request: Optional[Request] = None
    ) -> List[Dict[str, Any]]:
        """List user's active sessions.
        
        Args:
            user: Current user
            request: HTTP request for logging
            
        Returns:
            List of user session info
        """
        try:
            async with self.get_db_session() as db:
                user_sessions = (
                    db.query(UserSession)
                    .filter(
                        and_(
                            UserSession.user_id == user.id,
                            UserSession.is_active == True,
                            UserSession.expires_at > datetime.now(timezone.utc)
                        )
                    )
                    .order_by(UserSession.created_at.desc())
                    .all()
                )
            
            # Log the operation
            self.log_operation(
                "User sessions listed",
                user_id=user.id,
                details={"count": len(user_sessions)}
            )
            
            return [
                {
                    "id": str(session.id),
                    "device_info": session.device_info,
                    "ip_address": session.ip_address,
                    "user_agent": session.user_agent,
                    "created_at": session.created_at.isoformat(),
                    "last_activity_at": session.last_activity_at.isoformat() if session.last_activity_at else None,
                    "expires_at": session.expires_at.isoformat() if session.expires_at else None,
                    "is_current": session.id == getattr(request, 'session_id', None) if request else False
                }
                for session in user_sessions
            ]
            
        except Exception as e:
            raise self.handle_database_error(e, "user sessions listing")
    
    async def terminate_session(
        self,
        user: User,
        session_id: uuid.UUID
    ) -> None:
        """Terminate specific user session.
        
        Args:
            user: Current user
            session_id: Session ID to terminate
            
        Raises:
            HTTPException: If session not found or access denied
        """
        try:
            async with self.get_db_session() as db:
                user_session = (
                    db.query(UserSession)
                    .filter(
                        and_(
                            UserSession.id == session_id,
                            UserSession.user_id == user.id,
                            UserSession.is_active == True
                        )
                    )
                    .first()
                )
                
                if not user_session:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Session not found"
                    )
                
                # Terminate session
                user_session.is_active = False
                user_session.ended_at = datetime.now(timezone.utc)
                
                db.add(user_session)
                db.commit()
            
            # Log the operation
            self.log_operation(
                "Session terminated",
                user_id=user.id,
                details={"session_id": str(session_id)}
            )
                
        except HTTPException:
            raise
        except Exception as e:
            raise self.handle_database_error(e, "session termination")
    
    async def terminate_all_sessions(
        self,
        user: User,
        request: Optional[Request] = None
    ) -> int:
        """Terminate all user sessions.
        
        Args:
            user: Current user
            request: HTTP request for logging
            
        Returns:
            Number of sessions terminated
        """
        try:
            async with self.get_db_session() as db:
                # Get count of active sessions
                active_sessions_count = (
                    db.query(UserSession)
                    .filter(
                        and_(
                            UserSession.user_id == user.id,
                            UserSession.is_active == True
                        )
                    )
                    .count()
                )
                
                # Terminate all active sessions
                db.query(UserSession).filter(
                    and_(
                        UserSession.user_id == user.id,
                        UserSession.is_active == True
                    )
                ).update({
                    "is_active": False,
                    "ended_at": datetime.now(timezone.utc)
                })
                
                db.commit()
            
            # Log the operation
            self.log_operation(
                "All sessions terminated",
                user_id=user.id,
                details={"sessions_terminated": active_sessions_count}
            )
            
            return active_sessions_count
            
        except Exception as e:
            raise self.handle_database_error(e, "session termination")
    
    async def verify_email(
        self,
        token: str
    ) -> User:
        """Verify user email address.
        
        Args:
            token: Email verification token
            
        Returns:
            User: Verified user
            
        Raises:
            HTTPException: If token is invalid or expired
        """
        try:
            async with self.get_db_session() as db:
                # Find and validate verification token
                verification_token = (
                    db.query(EmailVerificationToken)
                    .filter(
                        and_(
                            EmailVerificationToken.token == token,
                            EmailVerificationToken.is_used == False,
                            EmailVerificationToken.expires_at > datetime.now(timezone.utc)
                        )
                    )
                    .first()
                )
                
                if not verification_token:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Invalid or expired verification token"
                    )
                
                # Get user
                user = (
                    db.query(User)
                    .filter(User.id == verification_token.user_id)
                    .first()
                )
                
                if not user:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Invalid verification token"
                    )
                
                # Mark email as verified
                user.is_verified = True
                user.email_verified_at = datetime.now(timezone.utc)
                user.updated_at = datetime.now(timezone.utc)
                
                # Mark token as used
                verification_token.is_used = True
                verification_token.used_at = datetime.now(timezone.utc)
                
                db.add(user)
                db.add(verification_token)
                db.commit()
                db.refresh(user)
            
            # Log the operation
            self.log_operation(
                "Email verified",
                user_id=user.id,
                details={"token_id": str(verification_token.id)}
            )
            
            return user
            
        except HTTPException:
            raise
        except Exception as e:
            raise self.handle_database_error(e, "email verification")
    
    async def resend_verification_email(
        self,
        user: User,
        request: Optional[Request] = None
    ) -> None:
        """Resend email verification.
        
        Args:
            user: User to resend verification for
            request: HTTP request for logging
            
        Raises:
            HTTPException: If user already verified or rate limit exceeded
        """
        try:
            # Check if user is already verified
            if user.is_verified:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email is already verified"
                )
            
            # Check rate limit
            if not self.security_service.check_rate_limit(
                f"verification_resend:{user.id}",
                max_attempts=3,
                window_minutes=15
            ):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many verification email requests"
                )
            
            # Create new verification token
            verification_token = await self._create_email_verification_token(user)
            
            # Queue verification email
            await self._send_verification_email(user, verification_token.token)
            
            # Log the operation
            self.log_operation(
                "Verification email resent",
                user_id=user.id,
                details={"token_id": str(verification_token.id)}
            )
            
        except HTTPException:
            raise
        except Exception as e:
            raise self.handle_database_error(e, "verification email resend")
    
    # Private helper methods
    
    async def _create_user_session(
        self,
        user: User,
        duration: timedelta,
        device_info: Optional[Dict[str, str]] = None,
        request: Optional[Request] = None
    ) -> UserSession:
        """Create user session.
        
        Args:
            user: User to create session for
            duration: Session duration
            device_info: Device information
            request: HTTP request for IP/user agent
            
        Returns:
            UserSession: Created session
        """
        async with self.get_db_session() as db:
            user_session = UserSession(
                id=uuid.uuid4(),
                user_id=user.id,
                device_info=device_info,
                ip_address=request.client.host if request else None,
                user_agent=request.headers.get("user-agent") if request else None,
                is_active=True,
                expires_at=datetime.now(timezone.utc) + duration,
                last_activity_at=datetime.now(timezone.utc),
                created_at=datetime.now(timezone.utc)
            )
            
            db.add(user_session)
            db.commit()
            db.refresh(user_session)
            
            return user_session
    
    async def _create_email_verification_token(self, user: User) -> EmailVerificationToken:
        """Create email verification token.
        
        Args:
            user: User to create token for
            
        Returns:
            EmailVerificationToken: Created token
        """
        async with self.get_db_session() as db:
            # Invalidate existing tokens
            db.query(EmailVerificationToken).filter(
                and_(
                    EmailVerificationToken.user_id == user.id,
                    EmailVerificationToken.is_used == False
                )
            ).update({"is_used": True, "used_at": datetime.now(timezone.utc)})
            
            # Create new token
            token = EmailVerificationToken(
                id=uuid.uuid4(),
                user_id=user.id,
                token=secrets.token_urlsafe(32),
                expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
                is_used=False,
                created_at=datetime.now(timezone.utc)
            )
            
            db.add(token)
            db.commit()
            db.refresh(token)
            
            return token
    
    async def _create_password_reset_token(self, user: User) -> PasswordResetToken:
        """Create password reset token.
        
        Args:
            user: User to create token for
            
        Returns:
            PasswordResetToken: Created token
        """
        async with self.get_db_session() as db:
            # Invalidate existing tokens
            db.query(PasswordResetToken).filter(
                and_(
                    PasswordResetToken.user_id == user.id,
                    PasswordResetToken.is_used == False
                )
            ).update({"is_used": True, "used_at": datetime.now(timezone.utc)})
            
            # Create new token
            token = PasswordResetToken(
                id=uuid.uuid4(),
                user_id=user.id,
                token=secrets.token_urlsafe(32),
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                is_used=False,
                created_at=datetime.now(timezone.utc)
            )
            
            db.add(token)
            db.commit()
            db.refresh(token)
            
            return token
    
    async def _send_verification_email(
        self,
        user: User,
        token: str
    ) -> None:
        """Send email verification email.
        
        Args:
            user: User to send verification email to
            token: Verification token
        """
        if self.email_service:
            from src.models.email import EmailRequest, EmailType
            from src.config.settings import get_settings
            
            settings = get_settings()
            verification_url = f"{settings.APP_URL}/verify-email?token={token}"
            
            email_request = EmailRequest(
                to=user.email,
                subject=f"Verify your {settings.APP_NAME} account",
                email_type=EmailType.VERIFICATION,
                template_variables={
                    "user_name": user.full_name.split()[0] if user.full_name else "User",
                    "verification_url": verification_url,
                    "expiry_hours": 24,
                    "current_year": datetime.now().year
                }
            )
            
            await self.email_service.send_email(email_request, EmailType.VERIFICATION.value)
        else:
            # Fallback: just log the email
            self.logger.info(
                f"Sending verification email to {user.email} for {user.full_name} with token {token}"
            )
    
    async def _send_password_reset_email(
        self,
        user: User,
        token: str
    ) -> None:
        """Send password reset email.
        
        Args:
            user: User to send password reset email to
            token: Password reset token
        """
        if self.email_service:
            from src.models.email import EmailRequest, EmailType
            from src.config.settings import get_settings
            
            settings = get_settings()
            reset_url = f"{settings.APP_URL}/reset-password?token={token}"
            
            email_request = EmailRequest(
                to=user.email,
                subject=f"Reset your {settings.APP_NAME} password",
                email_type=EmailType.PASSWORD_RESET,
                template_variables={
                    "user_name": user.full_name.split()[0] if user.full_name else "User",
                    "reset_url": reset_url,
                    "expiry_hours": 1,
                    "current_year": datetime.now().year
                }
            )
            
            await self.email_service.send_email(email_request, EmailType.PASSWORD_RESET.value)
        else:
            # Fallback: just log the email
            self.logger.info(
                f"Sending password reset email to {user.email} with token {token}"
            )