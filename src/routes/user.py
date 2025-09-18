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

from src.config.database import get_db
from src.config.settings import get_settings
from src.models.user import User, UserSession, APIKey, PasswordResetToken, EmailVerificationToken, UserRole, SubscriptionTier
from src.models.subscription import UserSubscription, SubscriptionPlan
from src.services.security_service import SecurityService, AuthenticationError, RateLimitError
from src.authentication.auth_service import AuthService, UserRegistrationError, InvalidCredentialsError


# Initialize router
router = APIRouter(prefix="/api/v1/user", tags=["User Management"])
security = HTTPBearer()
settings = get_settings()


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


class UserResponse(BaseModel):
    """
    User response model.
    """
    id: uuid.UUID
    email: str
    full_name: str
    company: Optional[str]
    role: UserRole
    subscription_tier: SubscriptionTier
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


class PasswordResetRequest(BaseModel):
    """
    Password reset request model.
    """
    email: EmailStr = Field(..., description="User email address")


class PasswordResetConfirmRequest(BaseModel):
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


class APIKeyRequest(BaseModel):
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


class UserSessionResponse(BaseModel):
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
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)) -> User:
    """
    Get current authenticated user.
    """
    try:
        auth_service = AuthService(db)
        security_service = SecurityService(db)
        
        # Verify JWT token
        token_data = security_service.verify_jwt_token(credentials.credentials)
        user_id = token_data.get("user_id")
        session_id = token_data.get("session_id")
        
        if not user_id or not session_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Validate session
        is_valid, session = security_service.validate_session(session_id, user_id)
        if not is_valid:
            raise HTTPException(status_code=401, detail="Session expired")
        
        # Get user
        user = db.query(User).filter(User.id == user_id).first()
        if not user or not user.is_active:
            raise HTTPException(status_code=401, detail="User not found or inactive")
        
        return user
    
    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail="Authentication failed")


async def check_rate_limits(request: Request, db: Session = Depends(get_db)) -> None:
    """
    Check rate limits for authentication endpoints.
    """
    security_service = SecurityService(db)
    client_ip = request.client.host
    
    # Check authentication rate limit
    is_allowed, limit_info = security_service.check_rate_limit(client_ip, "auth_requests", client_ip)
    if not is_allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Authentication rate limit exceeded. Try again in {limit_info['retry_after']:.0f} seconds",
            headers={"Retry-After": str(int(limit_info['retry_after']))}
        )


# Authentication Routes
@router.post("/register", response_model=UserResponse, summary="Register new user")
async def register_user(
    request: UserRegistrationRequest,
    background_tasks: BackgroundTasks,
    req: Request,
    db: Session = Depends(get_db)
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
    try:
        # Check rate limits
        await check_rate_limits(req, db)
        
        # Initialize services
        auth_service = AuthService(db)
        security_service = SecurityService(db)
        
        # Register user
        user = await auth_service.register_user(
            email=request.email,
            password=request.password,
            full_name=request.full_name,
            company=request.company,
            marketing_consent=request.marketing_consent,
            ip_address=req.client.host,
            user_agent=req.headers.get("user-agent")
        )
        
        # Send verification email
        background_tasks.add_task(
            send_verification_email,
            user.email,
            user.full_name,
            str(user.id)
        )
        
        # Log security event
        security_service.log_security_event(
            "user_registered",
            {
                "email": request.email,
                "company": request.company,
                "marketing_consent": request.marketing_consent
            },
            user_id=str(user.id),
            ip_address=req.client.host
        )
        
        return UserResponse.from_orm(user)
    
    except UserRegistrationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail="Registration failed")


@router.post("/login", response_model=LoginResponse, summary="User login")
async def login_user(
    request: UserLoginRequest,
    req: Request,
    db: Session = Depends(get_db)
):
    """
    Authenticate user and create session.
    
    **Features:**
    - Email/password authentication
    - Session management
    - Device tracking
    - Rate limiting protection
    """
    try:
        # Check rate limits
        await check_rate_limits(req, db)
        
        # Initialize services
        auth_service = AuthService(db)
        security_service = SecurityService(db)
        
        # Authenticate user
        user, session = await auth_service.authenticate_user(
            email=request.email,
            password=request.password,
            ip_address=req.client.host,
            user_agent=req.headers.get("user-agent"),
            device_info=request.device_info,
            remember_me=request.remember_me
        )
        
        # Generate JWT token
        token_data = {
            "user_id": str(user.id),
            "session_id": str(session.id),
            "email": user.email,
            "role": user.role.value
        }
        
        expires_in = 86400 * 30 if request.remember_me else 86400  # 30 days or 1 day
        access_token = security_service.create_jwt_token(token_data, expires_in)
        
        # Update last login
        user.last_login_at = datetime.now(timezone.utc)
        db.commit()
        
        # Log security event
        security_service.log_security_event(
            "user_login",
            {
                "session_id": str(session.id),
                "remember_me": request.remember_me
            },
            user_id=str(user.id),
            ip_address=req.client.host
        )
        
        return LoginResponse(
            access_token=access_token,
            expires_in=expires_in,
            user=UserResponse.from_orm(user),
            session_id=str(session.id)
        )
    
    except InvalidCredentialsError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except RateLimitError as e:
        raise HTTPException(status_code=429, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail="Login failed")


@router.post("/logout", summary="User logout")
async def logout_user(
    user: User = Depends(get_current_user),
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    """
    Logout user and invalidate session.
    """
    try:
        # Initialize services
        security_service = SecurityService(db)
        
        # Get session ID from token
        token_data = security_service.verify_jwt_token(credentials.credentials)
        session_id = token_data.get("session_id")
        
        if session_id:
            # Invalidate session
            session = db.query(UserSession).filter(
                and_(
                    UserSession.id == session_id,
                    UserSession.user_id == user.id
                )
            ).first()
            
            if session:
                session.is_active = False
                session.ended_at = datetime.now(timezone.utc)
                db.commit()
        
        # Log security event
        security_service.log_security_event(
            "user_logout",
            {"session_id": session_id},
            user_id=str(user.id)
        )
        
        return {"message": "Successfully logged out"}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail="Logout failed")


# Profile Management Routes
@router.get("/profile", response_model=UserResponse, summary="Get user profile")
async def get_user_profile(
    user: User = Depends(get_current_user)
):
    """
    Get current user profile information.
    """
    return UserResponse.from_orm(user)


@router.put("/profile", response_model=UserResponse, summary="Update user profile")
async def update_user_profile(
    request: ProfileUpdateRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Update user profile information.
    """
    try:
        # Update user fields
        if request.full_name is not None:
            user.full_name = request.full_name
        
        if request.company is not None:
            user.company = request.company
        
        if request.profile_picture_url is not None:
            user.profile_picture_url = request.profile_picture_url
        
        if request.marketing_consent is not None:
            user.marketing_consent = request.marketing_consent
        
        if request.timezone is not None:
            user.timezone = request.timezone
        
        if request.language is not None:
            user.language = request.language
        
        user.updated_at = datetime.now(timezone.utc)
        db.commit()
        
        return UserResponse.from_orm(user)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail="Profile update failed")


@router.post("/change-password", summary="Change user password")
async def change_password(
    request: PasswordChangeRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Change user password.
    """
    try:
        # Initialize services
        auth_service = AuthService(db)
        security_service = SecurityService(db)
        
        # Change password
        await auth_service.change_password(
            user_id=user.id,
            current_password=request.current_password,
            new_password=request.new_password
        )
        
        # Invalidate all other sessions
        db.query(UserSession).filter(
            and_(
                UserSession.user_id == user.id,
                UserSession.is_active == True
            )
        ).update({"is_active": False, "ended_at": datetime.now(timezone.utc)})
        
        db.commit()
        
        # Log security event
        security_service.log_security_event(
            "password_changed",
            {},
            user_id=str(user.id)
        )
        
        return {"message": "Password changed successfully"}
    
    except InvalidCredentialsError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail="Password change failed")


@router.post("/request-password-reset", summary="Request password reset")
async def request_password_reset(
    request: PasswordResetRequest,
    background_tasks: BackgroundTasks,
    req: Request,
    db: Session = Depends(get_db)
):
    """
    Request password reset email.
    """
    try:
        # Check rate limits
        await check_rate_limits(req, db)
        
        # Initialize services
        auth_service = AuthService(db)
        
        # Request password reset
        reset_token = await auth_service.request_password_reset(
            email=request.email,
            ip_address=req.client.host
        )
        
        if reset_token:
            # Send reset email
            background_tasks.add_task(
                send_password_reset_email,
                request.email,
                reset_token.token
            )
        
        # Always return success to prevent email enumeration
        return {"message": "If the email exists, a password reset link has been sent"}
    
    except Exception as e:
        # Don't reveal errors to prevent enumeration
        return {"message": "If the email exists, a password reset link has been sent"}


@router.post("/reset-password", summary="Reset password with token")
async def reset_password(
    request: PasswordResetConfirmRequest,
    req: Request,
    db: Session = Depends(get_db)
):
    """
    Reset password using reset token.
    """
    try:
        # Initialize services
        auth_service = AuthService(db)
        security_service = SecurityService(db)
        
        # Reset password
        user = await auth_service.reset_password(
            token=request.token,
            new_password=request.new_password,
            ip_address=req.client.host
        )
        
        # Invalidate all user sessions
        db.query(UserSession).filter(
            and_(
                UserSession.user_id == user.id,
                UserSession.is_active == True
            )
        ).update({"is_active": False, "ended_at": datetime.now(timezone.utc)})
        
        db.commit()
        
        # Log security event
        security_service.log_security_event(
            "password_reset_completed",
            {},
            user_id=str(user.id),
            ip_address=req.client.host
        )
        
        return {"message": "Password reset successfully"}
    
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")


# API Key Management Routes
@router.post("/api-keys", response_model=Dict[str, Any], summary="Create API key")
async def create_api_key(
    request: APIKeyRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Create a new API key for the user.
    """
    try:
        # Initialize services
        auth_service = AuthService(db)
        
        # Create API key
        api_key, key_value = await auth_service.create_api_key(
            user_id=user.id,
            name=request.name,
            description=request.description,
            permissions=request.permissions,
            expires_at=request.expires_at
        )
        
        return {
            "api_key": {
                "id": str(api_key.id),
                "name": api_key.name,
                "description": api_key.description,
                "permissions": api_key.permissions,
                "expires_at": api_key.expires_at,
                "created_at": api_key.created_at
            },
            "key": key_value,  # Only returned once
            "message": "API key created successfully. Save this key securely - it won't be shown again."
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail="API key creation failed")


@router.get("/api-keys", response_model=List[APIKeyResponse], summary="List API keys")
async def list_api_keys(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    List user's API keys.
    """
    api_keys = db.query(APIKey).filter(APIKey.user_id == user.id).order_by(desc(APIKey.created_at)).all()
    
    return [
        APIKeyResponse(
            id=key.id,
            name=key.name,
            description=key.description,
            key_preview=key.key_hash[:8] + "...",
            permissions=key.permissions,
            is_active=key.is_active,
            expires_at=key.expires_at,
            last_used_at=key.last_used_at,
            created_at=key.created_at
        )
        for key in api_keys
    ]


@router.delete("/api-keys/{key_id}", summary="Delete API key")
async def delete_api_key(
    key_id: uuid.UUID = Path(..., description="API key ID"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Delete an API key.
    """
    api_key = db.query(APIKey).filter(
        and_(
            APIKey.id == key_id,
            APIKey.user_id == user.id
        )
    ).first()
    
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")
    
    db.delete(api_key)
    db.commit()
    
    return {"message": "API key deleted successfully"}


# Session Management Routes
@router.get("/sessions", response_model=List[UserSessionResponse], summary="List user sessions")
async def list_user_sessions(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    List user's active sessions.
    """
    sessions = db.query(UserSession).filter(
        and_(
            UserSession.user_id == user.id,
            UserSession.is_active == True
        )
    ).order_by(desc(UserSession.last_activity_at)).all()
    
    return [UserSessionResponse.from_orm(session) for session in sessions]


@router.delete("/sessions/{session_id}", summary="Terminate session")
async def terminate_session(
    session_id: uuid.UUID = Path(..., description="Session ID"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Terminate a specific session.
    """
    session = db.query(UserSession).filter(
        and_(
            UserSession.id == session_id,
            UserSession.user_id == user.id,
            UserSession.is_active == True
        )
    ).first()
    
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session.is_active = False
    session.ended_at = datetime.now(timezone.utc)
    db.commit()
    
    return {"message": "Session terminated successfully"}


@router.delete("/sessions", summary="Terminate all sessions")
async def terminate_all_sessions(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Terminate all user sessions except current one.
    """
    # Get current session ID from token (would need to be passed)
    # For now, terminate all sessions
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
    
    return {"message": "All sessions terminated successfully"}


# Email Verification Routes
@router.post("/verify-email/{token}", summary="Verify email address")
async def verify_email(
    token: str = Path(..., description="Verification token"),
    db: Session = Depends(get_db)
):
    """
    Verify user email address.
    """
    try:
        # Initialize services
        auth_service = AuthService(db)
        
        # Verify email
        user = await auth_service.verify_email(token)
        
        return {"message": "Email verified successfully"}
    
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid or expired verification token")


@router.post("/resend-verification", summary="Resend verification email")
async def resend_verification_email(
    background_tasks: BackgroundTasks,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Resend email verification.
    """
    if user.is_verified:
        raise HTTPException(status_code=400, detail="Email already verified")
    
    try:
        # Initialize services
        auth_service = AuthService(db)
        
        # Create new verification token
        token = await auth_service.create_email_verification_token(user.id)
        
        # Send verification email
        background_tasks.add_task(
            send_verification_email,
            user.email,
            user.full_name,
            token.token
        )
        
        return {"message": "Verification email sent"}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to send verification email")


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