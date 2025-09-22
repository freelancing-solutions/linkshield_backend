#!/usr/bin/env python3
"""
LinkShield Backend User Management Routes

API routes for user authentication, registration, profile management, and account settings.
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Path, BackgroundTasks, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, validator
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc

from src.config.database import get_db_session, AsyncSession
from src.config.settings import get_settings
from src.models.user import User, UserSession, APIKey, PasswordResetToken, EmailVerificationToken, UserRole, SubscriptionPlan
from src.models.subscription import UserSubscription, SubscriptionPlan
from src.services.security_service import SecurityService, AuthenticationError, RateLimitError
from src.authentication.auth_service import AuthService,  InvalidCredentialsError
from src.controllers.user_controller import UserController
from src.services.email_service import EmailService

from src.services.depends import (
    get_security_service, get_auth_service, get_email_service
)


# Initialize router
router = APIRouter(prefix="/api/v1/user", tags=["User Management"])
security = HTTPBearer()
settings = get_settings()


# Dependency injection functions
def get_user_controller(
    security_service: SecurityService = Depends(get_security_service),
    auth_service: AuthService = Depends(get_auth_service),
    email_service: EmailService = Depends(get_email_service) ) -> UserController:
    """Get UserController instance with refactored service dependencies."""
    return UserController(
        security_service=security_service,
        auth_service=auth_service,
        email_service=email_service)


# Request/Response Models
class UserRegistrationRequest(BaseModel):
    """
    User registration request model.
    """
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=8, max_length=128, description="User password")
    full_name: str = Field(..., min_length=1, max_length=100, description="User full name")
    company: Optional[str] = Field(None, max_length=100, description="Company name")
    accept_terms: bool = Field(..., description="Terms of service acceptance")
    marketing_consent: bool = Field(default=False, description="Marketing communications consent")
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        
        # Check for at least one uppercase, lowercase, digit, and special character
        has_upper = any(c.isupper() for c in v)
        has_lower = any(c.islower() for c in v)
        has_digit = any(c.isdigit() for c in v)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in v)
        
        if not all([has_upper, has_lower, has_digit, has_special]):
            raise ValueError("Password must contain uppercase, lowercase, digit, and special character")
        
        return v
    
    @validator('accept_terms')
    def validate_terms(cls, v):
        if not v:
            raise ValueError("Terms of service must be accepted")
        return v


class UserLoginRequest(BaseModel):
    """
    User login request model.
    """
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., description="User password")
    remember_me: bool = Field(default=False, description="Extended session duration")
    device_info: Optional[Dict[str, str]] = Field(None, description="Device information")


# Response models for ORM → Pydantic serialization
class SubscriptionPlanResponse(BaseModel):
    """
    Serializable subscription plan model.
    """
    id: int
    name: str
    price: float
    active: bool

    class Config:
        from_attributes = True


class UserResponse(BaseModel):
    """
    User response model with serialized subscription plan.
    """
    id: uuid.UUID
    email: str
    full_name: str
    company: Optional[str]
    role: UserRole
    subscription_plan: Optional[SubscriptionPlanResponse]  # Use serializable Pydantic model
    is_active: bool
    is_verified: bool
    profile_picture_url: Optional[str]
    created_at: datetime
    last_login_at: Optional[datetime]

    class Config:
        from_attributes = True


class LoginResponse(BaseModel):
    """
    Login response model.
    """
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse
    session_id: str


class ProfileUpdateRequest(BaseModel):
    """
    Profile update request model.
    """
    full_name: Optional[str] = Field(None, min_length=1, max_length=100)
    company: Optional[str] = Field(None, max_length=100)
    profile_picture_url: Optional[str] = Field(None, max_length=500)
    marketing_consent: Optional[bool] = None
    timezone: Optional[str] = Field(None, max_length=50)
    language: Optional[str] = Field(None, max_length=10)


class PasswordChangeRequest(BaseModel):
    """
    Password change request model.
    """
    current_password: str = Field(..., description="Current password")
    new_password: str = Field(..., min_length=8, max_length=128, description="New password")
    
    @validator('new_password')
    def validate_new_password(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        
        has_upper = any(c.isupper() for c in v)
        has_lower = any(c.islower() for c in v)
        has_digit = any(c.isdigit() for c in v)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in v)
        
        if not all([has_upper, has_lower, has_digit, has_special]):
            raise ValueError("Password must contain uppercase, lowercase, digit, and special character")
        
        return v


class ForgotPasswordRequest(BaseModel):
    """
    Password reset request model.
    """
    email: EmailStr = Field(..., description="User email address")


class ResetPasswordRequest(BaseModel):
    """
    Password reset confirmation model.
    """
    token: str = Field(..., description="Reset token")
    new_password: str = Field(..., min_length=8, max_length=128, description="New password")
    
    @validator('new_password')
    def validate_new_password(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        
        has_upper = any(c.isupper() for c in v)
        has_lower = any(c.islower() for c in v)
        has_digit = any(c.isdigit() for c in v)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in v)
        
        if not all([has_upper, has_lower, has_digit, has_special]):
            raise ValueError("Password must contain uppercase, lowercase, digit, and special character")
        
        return v


class EmailVerificationRequest(BaseModel):
    """
    Email verification request model.
    """
    token: str = Field(..., description="Verification token")


class ResendVerificationRequest(BaseModel):
    """
    Resend verification request model.
    """
    email: EmailStr = Field(..., description="User email address")


class CreateAPIKeyRequest(BaseModel):
    """
    API key creation request model.
    """
    name: str = Field(..., min_length=1, max_length=100, description="API key name")
    description: Optional[str] = Field(None, max_length=500, description="API key description")
    expires_at: Optional[datetime] = Field(None, description="Expiration date")
    permissions: List[str] = Field(default=["url_check"], description="API key permissions")


class APIKeyResponse(BaseModel):
    """
    API key response model.
    """
    id: uuid.UUID
    name: str
    description: Optional[str]
    key_preview: str  # Only first 8 characters
    permissions: List[str]
    is_active: bool
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]
    created_at: datetime
    
    class Config:
        from_attributes = True


class SessionResponse(BaseModel):
    """
    User session response model.
    """
    id: uuid.UUID
    device_info: Optional[Dict[str, Any]]
    ip_address: Optional[str]
    user_agent: Optional[str]
    is_active: bool
    expires_at: datetime
    last_activity_at: datetime
    created_at: datetime
    
    class Config:
        from_attributes = True


# Dependency functions
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db_session)) -> User:
    """
    Get current authenticated user.
    """
    try:
        # Initialize services without database session
        security_service = SecurityService()
        
        # Verify JWT token
        token_data = security_service.verify_jwt_token(credentials.credentials)
        user_id = token_data.get("user_id")
        session_id = token_data.get("session_id")
        
        if not user_id or not session_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Validate session using database operations directly
        is_valid, session = await _validate_user_session_in_db(db, session_id, user_id)
        if not is_valid:
            raise HTTPException(status_code=401, detail="Session expired")
        
        # Get user from database
        user = await _get_user_by_id(db, user_id)
        if not user or not user.is_active:
            raise HTTPException(status_code=401, detail="User not found or inactive")
        
        return user
    
    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail="Authentication failed")


async def check_rate_limits(request: Request, db: Session = Depends(get_db_session)) -> None:
    """
    Check rate limits for authentication endpoints.
    """
    # Initialize SecurityService without database session
    security_service = SecurityService()
    client_ip = request.client.host
    
    # Rate limit checking logic would need to be implemented in controller
    # For now, we'll use SecurityService for validation logic only
    # TODO: Move rate limit data storage to controller
    pass


# Authentication Routes
@router.post("/register", response_model=UserResponse, summary="Register new user")
async def register_user(
    request: UserRegistrationRequest,
    background_tasks: BackgroundTasks,
    req: Request,
    controller: UserController = Depends(get_user_controller)
):
    """
    Register a new user account.
    
    **Requirements:**
    - Valid email address
    - Strong password (8+ chars, uppercase, lowercase, digit, special char)
    - Acceptance of terms of service
    
    **Process:**
    1. Validates input data
    2. Checks for existing users
    3. Creates user account
    4. Sends email verification
    5. Returns user profile

    """
    return await controller.register_user(request, background_tasks, req)


@router.post("/login", response_model=LoginResponse, summary="User login")
async def login_user(
    request: UserLoginRequest,
    req: Request,
    
    controller: UserController = Depends(get_user_controller)
):
    """
    Authenticate user and create session.
    
    **Features:**
    - Email/password authentication
    - Session management
    - Device tracking
    - Rate limiting protection
    """
    return await controller.login_user(request, req)


@router.post("/logout", summary="User logout")
async def logout_user(
    user: User = Depends(get_current_user),
    credentials: HTTPAuthorizationCredentials = Depends(security),
    controller: UserController = Depends(get_user_controller)
):
    """
    Logout user and invalidate session.
    
    """
    return await controller.logout_user(user, credentials)


# Profile Management Routes
@router.get("/profile", response_model=UserResponse, summary="Get user profile")
async def get_user_profile(
    user: User = Depends(get_current_user),
    controller: UserController = Depends(get_user_controller)
):
    """
    Get current user profile.
    
    Delegates business logic to UserController.
    """
    return await controller.get_user_profile(user)


@router.put("/profile", response_model=UserResponse, summary="Update user profile")
async def update_user_profile(
    request: ProfileUpdateRequest,
    user: User = Depends(get_current_user),
    controller: UserController = Depends(get_user_controller)
):
    """
    Update user profile information.
    
    Delegates business logic to UserController.
    """
    return await controller.update_user_profile(request, user)


@router.post("/change-password", summary="Change user password")
async def change_password(
    request: PasswordChangeRequest,
    user: User = Depends(get_current_user),
    controller: UserController = Depends(get_user_controller)
):
    """
    Change user password.
    
    Delegates business logic to UserController.
    """
    return await controller.change_password(request, user)


@router.post("/forgot-password", summary="Request password reset")
async def forgot_password(
    request: ForgotPasswordRequest,
    req: Request,
    background_tasks: BackgroundTasks,
    controller: UserController = Depends(get_user_controller)
):
    """
    Request password reset email.
    
    Delegates business logic to UserController.
    """
    return await controller.forgot_password(request, req, background_tasks)


@router.post("/reset-password", summary="Reset password with token")
async def reset_password(
    request: ResetPasswordRequest,
    controller: UserController = Depends(get_user_controller)
):
    """
    Reset password using reset token.
    
    Delegates business logic to UserController.
    """
    return await controller.reset_password(request)


@router.post("/verify-email", summary="Verify email address")
async def verify_email(
    request: EmailVerificationRequest,
    controller: UserController = Depends(get_user_controller)
):
    """
    Verify email address using verification token.
    
    Delegates business logic to UserController.
    """
    return await controller.verify_email(request)


@router.post("/resend-verification", summary="Resend email verification")
async def resend_verification(
    request: ResendVerificationRequest,
    background_tasks: BackgroundTasks,
    controller: UserController = Depends(get_user_controller)
):
    """
    Resend email verification.
    
    Delegates business logic to UserController.
    """
    return await controller.resend_verification(request, background_tasks)


# API Key Management Routes
@router.get("/api-keys", response_model=List[APIKeyResponse], summary="Get user API keys")
async def get_api_keys(
    user: User = Depends(get_current_user),
    controller: UserController = Depends(get_user_controller)
):
    """
    Get user's API keys.
    
    Delegates business logic to UserController.
    """
    return await controller.get_api_keys(user)


@router.post("/api-keys", response_model=APIKeyResponse, summary="Create new API key")
async def create_api_key(
    request: CreateAPIKeyRequest,
    user: User = Depends(get_current_user),
    controller: UserController = Depends(get_user_controller)
):
    """
    Create a new API key.
    
    Delegates business logic to UserController.
    """
    return await controller.create_api_key(request, user)


@router.delete("/api-keys/{key_id}", summary="Delete API key")
async def delete_api_key(
    key_id: str = Path(..., description="API key ID"),
    user: User = Depends(get_current_user),
    controller: UserController = Depends(get_user_controller)
):
    """
    Delete an API key.
    
    Delegates business logic to UserController.
    """
    return await controller.delete_api_key(key_id, user)


# Session Management Routes
@router.get("/sessions", response_model=List[SessionResponse], summary="Get user sessions")
async def get_user_sessions(
    user: User = Depends(get_current_user),
    controller: UserController = Depends(get_user_controller)
):
    """
    Get user's active sessions.
    
    Delegates business logic to UserController.
    """
    return await controller.get_user_sessions(user)


@router.delete("/sessions/{session_id}", summary="Delete user session")
async def delete_user_session(
    session_id: str = Path(..., description="Session ID"),
    user: User = Depends(get_current_user),
    controller: UserController = Depends(get_user_controller)
):
    """
    Delete a specific user session.
    
    Delegates business logic to UserController.
    """
    return await controller.delete_user_session(session_id, user)


@router.delete("/sessions", summary="Terminate all sessions")
async def terminate_all_sessions(
    user: User = Depends(get_current_user),
    controller: UserController = Depends(get_user_controller)
):
    """
    Terminate all user sessions except current one.
    """
    # Get current session ID from token (would need to be passed)
    # For now, terminate all sessions
    pass


# Email Verification Routes
@router.post("/verify-email/{token}", summary="Verify email address")
async def verify_email_with_token(
    token: str = Path(..., description="Verification token"),
    controller: UserController = Depends(get_user_controller)
):
    """
    Verify user email address with token from URL.
    
    Delegates business logic to UserController.
    """
    request = EmailVerificationRequest(token=token)
    return await controller.verify_email(request)


@router.post("/resend-verification", summary="Resend verification email")
async def resend_verification_email(
    background_tasks: BackgroundTasks,
    user: User = Depends(get_current_user),
    controller: UserController = Depends(get_user_controller)
):
    """
    Resend email verification.
    
    Delegates business logic to UserController.
    """
    request = ResendVerificationRequest(email=user.email)
    return await controller.resend_verification(request, background_tasks)


# Helper functions for database operations
async def _validate_user_session_in_db(db: Session, session_id: str, user_id: str) -> tuple[bool, Optional[UserSession]]:
    """
    Validate user session in database.
    """
    try:
        session = db.query(UserSession).filter(
            and_(
                UserSession.id == session_id,
                UserSession.user_id == user_id,
                UserSession.is_active == True,
                UserSession.expires_at > datetime.now(timezone.utc)
            )
        ).first()
        
        if session:
            # Update last activity
            session.last_activity_at = datetime.now(timezone.utc)
            db.commit()
            return True, session
        
        return False, None
    except Exception:
        return False, None


async def _get_user_by_id(db: Session, user_id: str) -> Optional[User]:
    """
    Get user by ID from database.
    """
    try:
        return db.query(User).filter(User.id == user_id).first()
    except Exception:
        return None


# Background task functions
async def send_verification_email(email: str, full_name: str, token: str):
    """
    Send email verification email.
    """
    # Implementation would depend on email service
    print(f"Sending verification email to {email} with token {token}")


async def send_password_reset_email(email: str, token: str):
    """
    Send password reset email.
    """
    # Implementation would depend on email service
    print(f"Sending password reset email to {email} with token {token}")