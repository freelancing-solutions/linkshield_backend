#!/usr/bin/env python3
"""
LinkShield Backend Authentication Service

Comprehensive authentication service handling user registration, login, session management,
password security, email verification, and multi-factor authentication.
"""

import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, Tuple, List

import bcrypt
import jwt
from email_validator import validate_email, EmailNotValidError
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

from src.config.settings import get_settings
from src.models.user import (
    User, UserSession, APIKey, PasswordResetToken, 
    EmailVerificationToken, UserStatus, UserRole
)

from src.services.email_service import EmailService
from src.services.background_tasks import BackgroundEmailService
from src.services.security_service import SecurityService


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
    Authentication service for user management and security.
    """
    
    def __init__(
        self, 
        get_db_session: AsyncSession, 
        email_service: EmailService,
        security_service: SecurityService
    ):
        self.db = get_db_session
        self.email_service = email_service
        self.security_service = security_service
        self.settings = get_settings()
        
        # Security configuration
        self.max_login_attempts = 5
        self.lockout_duration = timedelta(minutes=30)
        self.session_duration = timedelta(days=7)
        self.password_reset_duration = timedelta(hours=1)
        self.email_verification_duration = timedelta(days=1)
    
    def register_user(
        self, 
        email: str, 
        password: str, 
        first_name: str, 
        last_name: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Tuple[User, str]:
        """
        Register a new user account.
        
        Returns:
            Tuple of (User, verification_token)
        """
        # Validate email format
        try:
            validated_email = validate_email(email)
            email = validated_email.email
        except EmailNotValidError as e:
            raise AuthenticationError(f"Invalid email format: {str(e)}")
        
        # Check if user already exists
        existing_user = self.db.query(User).filter(User.email == email).first()
        if existing_user:
            raise AuthenticationError("User with this email already exists")
        
        # Validate password strength
        if not self._is_password_strong(password):
            raise AuthenticationError(
                "Password must be at least 8 characters long and contain uppercase, "
                "lowercase, number, and special character"
            )
        
        # Check for suspicious registration patterns
        if ip_address and self.security_service.is_suspicious_ip(ip_address):
            raise AuthenticationError("Registration from this IP is not allowed")
        
        # Hash password
        password_hash = self._hash_password(password)
        
        # Create user
        user = User(
            email=email,
            password_hash=password_hash,
            first_name=first_name,
            last_name=last_name,
            status=UserStatus.PENDING_VERIFICATION,
            role=UserRole.USER,
            registration_ip=ip_address,
            last_login_ip=ip_address,
            user_agent=user_agent
        )
        
        self.db.add(user)
        self.db.flush()  # Get user ID
        
        # Create email verification token
        verification_token = self._create_email_verification_token(user.id)
        
        # Queue verification email for background sending
        self.email_service.queue_verification_email(
            user.email, 
            user.first_name, 
            verification_token
        )
        
        self.db.commit()
        
        return user, verification_token
    
    def authenticate_user(
        self, 
        email: str, 
        password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Tuple[User, str]:
        """
        Authenticate user credentials.
        
        Returns:
            Tuple of (User, session_token)
        """
        # Find user by email
        user = self.db.query(User).filter(User.email == email).first()
        if not user:
            raise InvalidCredentialsError("Invalid email or password")
        
        # Check account status
        if user.status == UserStatus.SUSPENDED:
            raise AccountLockedError("Account is suspended")
        
        if user.status == UserStatus.PENDING_VERIFICATION:
            raise EmailNotVerifiedError("Email address not verified")
        
        # Check if account is locked due to failed attempts
        if self._is_account_locked(user):
            raise AccountLockedError(
                f"Account locked due to too many failed login attempts. "
                f"Try again after {self.lockout_duration.total_seconds() // 60} minutes."
            )
        
        # Verify password
        if not self._verify_password(password, user.password_hash):
            self._record_failed_login(user, ip_address)
            raise InvalidCredentialsError("Invalid email or password")
        
        # Check for suspicious login patterns
        if ip_address and self.security_service.is_suspicious_login(user.id, ip_address):
            # Queue security alert email for background sending
            from src.models.email import EmailRequest, EmailType
            security_alert_request = EmailRequest(
                to=user.email,
                subject=f"Security Alert - New login to your {self.settings.APP_NAME} account",
                email_type=EmailType.SECURITY_ALERT,
                template_variables={
                    "user_name": user.first_name,
                    "login_ip": ip_address,
                    "login_time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "current_year": datetime.now().year
                }
            )
            self.email_service.queue_email(
                security_alert_request, 
                EmailType.SECURITY_ALERT.value,
                priority=2  # High priority for security alerts
            )
        
        # Update user login information
        user.last_login_at = datetime.now(timezone.utc)
        user.last_login_ip = ip_address
        user.user_agent = user_agent
        user.failed_login_attempts = 0
        user.locked_until = None
        
        # Create session
        session_token = self._create_user_session(user.id, ip_address, user_agent)
        
        self.db.commit()
        
        return user, session_token
    
    def verify_session(self, session_token: str) -> Optional[User]:
        """
        Verify and return user from session token.
        """
        try:
            # Decode JWT token
            payload = jwt.decode(
                session_token,
                self.settings.SECRET_KEY,
                algorithms=["HS256"]
            )
            
            session_id = payload.get("session_id")
            user_id = payload.get("user_id")
            
            if not session_id or not user_id:
                return None
            
            # Find session in database
            session = self.db.query(UserSession).filter(
                and_(
                    UserSession.id == session_id,
                    UserSession.user_id == user_id,
                    UserSession.is_active == True,
                    UserSession.expires_at > datetime.now(timezone.utc)
                )
            ).first()
            
            if not session:
                return None
            
            # Update session activity
            session.last_activity = datetime.now(timezone.utc)
            self.db.commit()
            
            return session.user
            
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def logout_user(self, session_token: str) -> bool:
        """
        Logout user by invalidating session.
        """
        try:
            payload = jwt.decode(
                session_token,
                self.settings.SECRET_KEY,
                algorithms=["HS256"]
            )
            
            session_id = payload.get("session_id")
            
            if session_id:
                session = self.db.query(UserSession).filter(
                    UserSession.id == session_id
                ).first()
                
                if session:
                    session.is_active = False
                    session.logged_out_at = datetime.now(timezone.utc)
                    self.db.commit()
                    return True
            
        except jwt.InvalidTokenError:
            pass
        
        return False
    
    def verify_email(self, token: str) -> bool:
        """
        Verify user email with verification token.
        """
        verification = self.db.query(EmailVerificationToken).filter(
            and_(
                EmailVerificationToken.token == token,
                EmailVerificationToken.is_used == False,
                EmailVerificationToken.expires_at > datetime.now(timezone.utc)
            )
        ).first()
        
        if not verification:
            return False
        
        # Update user status
        user = verification.user
        user.status = UserStatus.ACTIVE
        user.email_verified_at = datetime.now(timezone.utc)
        
        # Mark token as used
        verification.is_used = True
        verification.used_at = datetime.now(timezone.utc)
        
        self.db.commit()
        
        return True
    
    def request_password_reset(self, email: str) -> bool:
        """
        Request password reset for user.
        """
        user = self.db.query(User).filter(User.email == email).first()
        if not user:
            # Don't reveal if email exists
            return True
        
        # Create password reset token
        reset_token = self._create_password_reset_token(user.id)
        
        # Queue password reset email for background sending
        self.email_service.queue_password_reset_email(
            user.email, 
            user.first_name, 
            reset_token
        )
        
        self.db.commit()
        
        return True
    
    def reset_password(self, token: str, new_password: str) -> bool:
        """
        Reset user password with reset token.
        """
        reset_token = self.db.query(PasswordResetToken).filter(
            and_(
                PasswordResetToken.token == token,
                PasswordResetToken.is_used == False,
                PasswordResetToken.expires_at > datetime.now(timezone.utc)
            )
        ).first()
        
        if not reset_token:
            return False
        
        # Validate new password
        if not self._is_password_strong(new_password):
            raise AuthenticationError(
                "Password must be at least 8 characters long and contain uppercase, "
                "lowercase, number, and special character"
            )
        
        # Update user password
        user = reset_token.user
        user.password_hash = self._hash_password(new_password)
        user.password_changed_at = datetime.now(timezone.utc)
        
        # Mark token as used
        reset_token.is_used = True
        reset_token.used_at = datetime.now(timezone.utc)
        
        # Invalidate all user sessions
        self.db.query(UserSession).filter(
            and_(
                UserSession.user_id == user.id,
                UserSession.is_active == True
            )
        ).update({"is_active": False})
        
        self.db.commit()
        
        return True
    
    def change_password(self, user_id: uuid.UUID, current_password: str, new_password: str) -> bool:
        """
        Change user password (requires current password).
        """
        user = self.db.query(User).filter(User.id == user_id).first()
        if not user:
            return False
        
        # Verify current password
        if not self._verify_password(current_password, user.password_hash):
            raise InvalidCredentialsError("Current password is incorrect")
        
        # Validate new password
        if not self._is_password_strong(new_password):
            raise AuthenticationError(
                "Password must be at least 8 characters long and contain uppercase, "
                "lowercase, number, and special character"
            )
        
        # Update password
        user.password_hash = self._hash_password(new_password)
        user.password_changed_at = datetime.now(timezone.utc)
        
        self.db.commit()
        
        return True
    
    def create_api_key(self, user_id: uuid.UUID, name: str, permissions: List[str]) -> str:
        """
        Create API key for user.
        """
        # Generate secure API key
        key = f"ls_{secrets.token_urlsafe(32)}"
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        
        api_key = APIKey(
            user_id=user_id,
            name=name,
            key_hash=key_hash,
            permissions=permissions
        )
        
        self.db.add(api_key)
        self.db.commit()
        
        return key
    
    def verify_api_key(self, api_key: str) -> Optional[User]:
        """
        Verify API key and return associated user.
        """
        if not api_key.startswith("ls_"):
            return None
        
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        api_key_record = self.db.query(APIKey).filter(
            and_(
                APIKey.key_hash == key_hash,
                APIKey.is_active == True,
                or_(
                    APIKey.expires_at.is_(None),
                    APIKey.expires_at > datetime.now(timezone.utc)
                )
            )
        ).first()
        
        if not api_key_record:
            return None
        
        # Update last used
        api_key_record.last_used_at = datetime.now(timezone.utc)
        api_key_record.usage_count += 1
        self.db.commit()
        
        return api_key_record.user
    
    def revoke_api_key(self, user_id: uuid.UUID, api_key_id: uuid.UUID) -> bool:
        """
        Revoke API key.
        """
        api_key = self.db.query(APIKey).filter(
            and_(
                APIKey.id == api_key_id,
                APIKey.user_id == user_id
            )
        ).first()
        
        if not api_key:
            return False
        
        api_key.is_active = False
        api_key.revoked_at = datetime.now(timezone.utc)
        self.db.commit()
        
        return True
    
    def get_user_sessions(self, user_id: uuid.UUID) -> List[UserSession]:
        """
        Get active sessions for user.
        """
        return self.db.query(UserSession).filter(
            and_(
                UserSession.user_id == user_id,
                UserSession.is_active == True,
                UserSession.expires_at > datetime.now(timezone.utc)
            )
        ).order_by(UserSession.last_activity.desc()).all()
    
    def revoke_session(self, user_id: uuid.UUID, session_id: uuid.UUID) -> bool:
        """
        Revoke specific user session.
        """
        session = self.db.query(UserSession).filter(
            and_(
                UserSession.id == session_id,
                UserSession.user_id == user_id
            )
        ).first()
        
        if not session:
            return False
        
        session.is_active = False
        session.logged_out_at = datetime.now(timezone.utc)
        self.db.commit()
        
        return True
    
    def revoke_all_sessions(self, user_id: uuid.UUID, except_session_id: Optional[uuid.UUID] = None) -> int:
        """
        Revoke all user sessions except optionally one.
        """
        query = self.db.query(UserSession).filter(
            and_(
                UserSession.user_id == user_id,
                UserSession.is_active == True
            )
        )
        
        if except_session_id:
            query = query.filter(UserSession.id != except_session_id)
        
        count = query.count()
        query.update({
            "is_active": False,
            "logged_out_at": datetime.now(timezone.utc)
        })
        
        self.db.commit()
        
        return count
    
    # Private helper methods
    
    def _hash_password(self, password: str) -> str:
        """
        Hash password using bcrypt.
        """
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def _verify_password(self, password: str, password_hash: str) -> bool:
        """
        Verify password against hash.
        """
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    
    def _is_password_strong(self, password: str) -> bool:
        """
        Check if password meets strength requirements.
        """
        if len(password) < 8:
            return False
        
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        return has_upper and has_lower and has_digit and has_special
    
    def _is_account_locked(self, user: User) -> bool:
        """
        Check if user account is locked.
        """
        if user.locked_until and user.locked_until > datetime.now(timezone.utc):
            return True
        
        if user.failed_login_attempts >= self.max_login_attempts:
            return True
        
        return False
    
    def _record_failed_login(self, user: User, ip_address: Optional[str] = None) -> None:
        """
        Record failed login attempt.
        """
        user.failed_login_attempts += 1
        user.last_failed_login_at = datetime.now(timezone.utc)
        user.last_failed_login_ip = ip_address
        
        if user.failed_login_attempts >= self.max_login_attempts:
            user.locked_until = datetime.now(timezone.utc) + self.lockout_duration
    
    def _create_user_session(self, user_id: uuid.UUID, ip_address: Optional[str], user_agent: Optional[str]) -> str:
        """
        Create user session and return JWT token.
        """
        session = UserSession(
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=datetime.now(timezone.utc) + self.session_duration
        )
        
        self.db.add(session)
        self.db.flush()  # Get session ID
        
        # Create JWT token
        payload = {
            "session_id": str(session.id),
            "user_id": str(user_id),
            "exp": session.expires_at,
            "iat": datetime.now(timezone.utc)
        }
        
        token = jwt.encode(payload, self.settings.SECRET_KEY, algorithm="HS256")
        
        return token
    
    def _create_email_verification_token(self, user_id: uuid.UUID) -> str:
        """
        Create email verification token.
        """
        token = secrets.token_urlsafe(32)
        
        verification = EmailVerificationToken(
            user_id=user_id,
            token=token,
            expires_at=datetime.now(timezone.utc) + self.email_verification_duration
        )
        
        self.db.add(verification)
        
        return token
    
    def _create_password_reset_token(self, user_id: uuid.UUID) -> str:
        """
        Create password reset token.
        """
        token = secrets.token_urlsafe(32)
        
        reset_token = PasswordResetToken(
            user_id=user_id,
            token=token,
            expires_at=datetime.now(timezone.utc) + self.password_reset_duration
        )
        
        self.db.add(reset_token)
        
        return token