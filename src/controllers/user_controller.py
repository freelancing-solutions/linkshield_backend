"""User controller for handling user management business logic.

This module contains the UserController class that handles all business logic
for user authentication, registration, profile management, API key management,
session management, and email verification.
"""

import uuid
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple

from fastapi import HTTPException, status, BackgroundTasks, Request
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc
from pydantic import ValidationError

from src.controllers.base_controller import BaseController
from src.models.user import (
    User, UserSession, APIKey, PasswordResetToken,
    EmailVerificationToken, UserRole, SubscriptionTier
)
from src.models.subscription import UserSubscription, SubscriptionPlan
from src.services.security_service import (
    SecurityService, AuthenticationError, RateLimitError
)
from src.authentication.auth_service import (
    AuthService, UserRegistrationError, InvalidCredentialsError
)


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
        db_session: Session,
        security_service: SecurityService = None,
        auth_service: AuthService = None
    ):
        """Initialize user controller.
        
        Args:
            db_session: Database session for operations
            security_service: Security service for validation
            auth_service: Authentication service
        """
        super().__init__(db_session, security_service, auth_service)
        
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
        
        # Check if user already exists
        existing_user = (
            self.db_session.query(User)
            .filter(User.email == email.lower())
            .first()
        )
        
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User with this email already exists"
            )
        
        try:
            # Create user using auth service
            user = await self.auth_service.register_user(
                email=email,
                password=password,
                full_name=full_name,
                company=company,
                marketing_consent=marketing_consent
            )
            
            # Create email verification token
            verification_token = await self._create_email_verification_token(user)
            
            # Send verification email in background
            if background_tasks:
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
            
        except UserRegistrationError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
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
            # Authenticate user
            user = await self.auth_service.authenticate_user(email, password)
            
            if not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Account is deactivated"
                )
            
            # Create user session
            session_duration = timedelta(days=30 if remember_me else 1)
            session = await self._create_user_session(
                user, session_duration, device_info, request
            )
            
            # Generate access token
            access_token = await self.auth_service.create_access_token(
                user_id=user.id,
                session_id=session.id,
                expires_delta=session_duration
            )
            
            # Update last login timestamp
            user.last_login_at = datetime.utcnow()
            await self.db_session.commit()
            
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
            if session_id:
                # Invalidate specific session
                session = (
                    self.db_session.query(UserSession)
                    .filter(
                        and_(
                            UserSession.id == session_id,
                            UserSession.user_id == user.id,
                            UserSession.is_active == True
                        )
                    )
                    .first()
                )
                
                if session:
                    session.is_active = False
                    session.ended_at = datetime.utcnow()
            else:
                # Invalidate all user sessions
                self.db_session.query(UserSession).filter(
                    and_(
                        UserSession.user_id == user.id,
                        UserSession.is_active == True
                    )
                ).update({
                    "is_active": False,
                    "ended_at": datetime.utcnow()
                })
            
            await self.db_session.commit()
            
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
            await self.db_session.commit()
            await self.db_session.refresh(user)
            
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
            if not await self.auth_service.verify_password(current_password, user.password_hash):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Current password is incorrect"
                )
            
            # Check if new password is different
            if await self.auth_service.verify_password(new_password, user.password_hash):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="New password must be different from current password"
                )
            
            # Update password
            user.password_hash = await self.auth_service.hash_password(new_password)
            user.password_changed_at = datetime.utcnow()
            user.updated_at = datetime.utcnow()
            
            # Invalidate all existing sessions except current one
            # This forces re-authentication on other devices
            self.db_session.query(UserSession).filter(
                and_(
                    UserSession.user_id == user.id,
                    UserSession.is_active == True
                )
            ).update({
                "is_active": False,
                "ended_at": datetime.utcnow()
            })
            
            await self.db_session.commit()
            
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
        
        # Find user by email
        user = (
            self.db_session.query(User)
            .filter(User.email == email.lower())
            .first()
        )
        
        # Always return success to prevent email enumeration
        if user and user.is_active:
            try:
                # Create password reset token
                reset_token = await self._create_password_reset_token(user)
                
                # Send reset email in background
                if background_tasks:
                    background_tasks.add_task(
                        self._send_password_reset_email,
                        email,
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
            # Find and validate reset token
            reset_token = (
                self.db_session.query(PasswordResetToken)
                .filter(
                    and_(
                        PasswordResetToken.token == token,
                        PasswordResetToken.is_used == False,
                        PasswordResetToken.expires_at > datetime.utcnow()
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
                self.db_session.query(User)
                .filter(User.id == reset_token.user_id)
                .first()
            )
            
            if not user or not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid reset token"
                )
            
            # Update password
            user.password_hash = await self.auth_service.hash_password(new_password)
            user.password_changed_at = datetime.utcnow()
            user.updated_at = datetime.utcnow()
            
            # Mark token as used
            reset_token.is_used = True
            reset_token.used_at = datetime.utcnow()
            
            # Invalidate all user sessions
            self.db_session.query(UserSession).filter(
                and_(
                    UserSession.user_id == user.id,
                    UserSession.is_active == True
                )
            ).update({
                "is_active": False,
                "ended_at": datetime.utcnow()
            })
            
            await self.db_session.commit()
            
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
        
        # Check if user already has too many API keys
        existing_keys_count = (
            self.db_session.query(APIKey)
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
            
            # Create API key record
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
                created_at=datetime.utcnow()
            )
            
            self.db_session.add(api_key)
            await self.db_session.commit()
            await self.db_session.refresh(api_key)
            
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
    
    async def list_api_keys(self, user: User) -> List[APIKey]:
        """List user's API keys.
        
        Args:
            user: Current user
            
        Returns:
            List[APIKey]: User's API keys
        """
        api_keys = (
            self.db_session.query(APIKey)
            .filter(
                and_(
                    APIKey.user_id == user.id,
                    APIKey.is_active == True
                )
            )
            .order_by(desc(APIKey.created_at))
            .all()
        )
        
        self.log_operation(
            "API keys listed",
            user_id=user.id,
            details={"count": len(api_keys)}
        )
        
        return api_keys
    
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
        api_key = (
            self.db_session.query(APIKey)
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
        
        try:
            # Soft delete API key
            api_key.is_active = False
            api_key.deleted_at = datetime.utcnow()
            
            await self.db_session.commit()
            
            # Log the operation
            self.log_operation(
                "API key deleted",
                user_id=user.id,
                details={"key_id": str(key_id), "name": api_key.name}
            )
            
        except Exception as e:
            raise self.handle_database_error(e, "API key deletion")
    
    async def list_user_sessions(self, user: User) -> List[UserSession]:
        """List user's active sessions.
        
        Args:
            user: Current user
            
        Returns:
            List[UserSession]: User's active sessions
        """
        sessions = (
            self.db_session.query(UserSession)
            .filter(
                and_(
                    UserSession.user_id == user.id,
                    UserSession.is_active == True,
                    UserSession.expires_at > datetime.utcnow()
                )
            )
            .order_by(desc(UserSession.last_activity_at))
            .all()
        )
        
        self.log_operation(
            "User sessions listed",
            user_id=user.id,
            details={"count": len(sessions)}
        )
        
        return sessions
    
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
        session = (
            self.db_session.query(UserSession)
            .filter(
                and_(
                    UserSession.id == session_id,
                    UserSession.user_id == user.id,
                    UserSession.is_active == True
                )
            )
            .first()
        )
        
        if not session:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found"
            )
        
        try:
            # Terminate session
            session.is_active = False
            session.ended_at = datetime.utcnow()
            
            await self.db_session.commit()
            
            # Log the operation
            self.log_operation(
                "Session terminated",
                user_id=user.id,
                details={"session_id": str(session_id)}
            )
            
        except Exception as e:
            raise self.handle_database_error(e, "session termination")
    
    async def terminate_all_sessions(self, user: User) -> int:
        """Terminate all user sessions.
        
        Args:
            user: Current user
            
        Returns:
            int: Number of sessions terminated
        """
        try:
            # Get count of active sessions
            active_sessions_count = (
                self.db_session.query(UserSession)
                .filter(
                    and_(
                        UserSession.user_id == user.id,
                        UserSession.is_active == True
                    )
                )
                .count()
            )
            
            # Terminate all active sessions
            self.db_session.query(UserSession).filter(
                and_(
                    UserSession.user_id == user.id,
                    UserSession.is_active == True
                )
            ).update({
                "is_active": False,
                "ended_at": datetime.utcnow()
            })
            
            await self.db_session.commit()
            
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
            # Find and validate verification token
            verification_token = (
                self.db_session.query(EmailVerificationToken)
                .filter(
                    and_(
                        EmailVerificationToken.token == token,
                        EmailVerificationToken.is_used == False,
                        EmailVerificationToken.expires_at > datetime.utcnow()
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
                self.db_session.query(User)
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
            user.email_verified_at = datetime.utcnow()
            user.updated_at = datetime.utcnow()
            
            # Mark token as used
            verification_token.is_used = True
            verification_token.used_at = datetime.utcnow()
            
            await self.db_session.commit()
            await self.db_session.refresh(user)
            
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
        background_tasks: Optional[BackgroundTasks] = None
    ) -> None:
        """Resend email verification.
        
        Args:
            user: Current user
            background_tasks: FastAPI background tasks
            
        Raises:
            HTTPException: If user is already verified or rate limit exceeded
        """
        if user.is_verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email is already verified"
            )
        
        # Check rate limits
        if not await self.check_rate_limit(
            user.id, "email_verification", 3, window_seconds=3600
        ):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Email verification rate limit exceeded"
            )
        
        try:
            # Create new verification token
            verification_token = await self._create_email_verification_token(user)
            
            # Send verification email in background
            if background_tasks:
                background_tasks.add_task(
                    self._send_verification_email,
                    user.email,
                    user.full_name,
                    verification_token.token
                )
            
            # Log the operation
            self.log_operation(
                "Verification email resent",
                user_id=user.id
            )
            
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
        session = UserSession(
            id=uuid.uuid4(),
            user_id=user.id,
            device_info=device_info,
            ip_address=request.client.host if request else None,
            user_agent=request.headers.get("user-agent") if request else None,
            is_active=True,
            expires_at=datetime.utcnow() + duration,
            last_activity_at=datetime.utcnow(),
            created_at=datetime.utcnow()
        )
        
        self.db_session.add(session)
        await self.db_session.commit()
        await self.db_session.refresh(session)
        
        return session
    
    async def _create_email_verification_token(self, user: User) -> EmailVerificationToken:
        """Create email verification token.
        
        Args:
            user: User to create token for
            
        Returns:
            EmailVerificationToken: Created token
        """
        # Invalidate existing tokens
        self.db_session.query(EmailVerificationToken).filter(
            and_(
                EmailVerificationToken.user_id == user.id,
                EmailVerificationToken.is_used == False
            )
        ).update({"is_used": True, "used_at": datetime.utcnow()})
        
        # Create new token
        token = EmailVerificationToken(
            id=uuid.uuid4(),
            user_id=user.id,
            token=secrets.token_urlsafe(32),
            expires_at=datetime.utcnow() + timedelta(hours=24),
            is_used=False,
            created_at=datetime.utcnow()
        )
        
        self.db_session.add(token)
        await self.db_session.commit()
        await self.db_session.refresh(token)
        
        return token
    
    async def _create_password_reset_token(self, user: User) -> PasswordResetToken:
        """Create password reset token.
        
        Args:
            user: User to create token for
            
        Returns:
            PasswordResetToken: Created token
        """
        # Invalidate existing tokens
        self.db_session.query(PasswordResetToken).filter(
            and_(
                PasswordResetToken.user_id == user.id,
                PasswordResetToken.is_used == False
            )
        ).update({"is_used": True, "used_at": datetime.utcnow()})
        
        # Create new token
        token = PasswordResetToken(
            id=uuid.uuid4(),
            user_id=user.id,
            token=secrets.token_urlsafe(32),
            expires_at=datetime.utcnow() + timedelta(hours=1),
            is_used=False,
            created_at=datetime.utcnow()
        )
        
        self.db_session.add(token)
        await self.db_session.commit()
        await self.db_session.refresh(token)
        
        return token
    
    async def _send_verification_email(
        self,
        email: str,
        full_name: str,
        token: str
    ) -> None:
        """Send email verification email.
        
        Args:
            email: User email address
            full_name: User full name
            token: Verification token
        """
        # This would implement actual email sending
        # For now, just log the email
        self.logger.info(
            f"Sending verification email to {email} for {full_name} with token {token}"
        )
    
    async def _send_password_reset_email(
        self,
        email: str,
        token: str
    ) -> None:
        """Send password reset email.
        
        Args:
            email: User email address
            token: Reset token
        """
        # This would implement actual email sending
        # For now, just log the email
        self.logger.info(
            f"Sending password reset email to {email} with token {token}"
        )