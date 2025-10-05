#!/usr/bin/env python3
"""
LinkShield Backend User Management Routes

Thin HTTP layer; all business logic & response models imported from controller.
"""
from datetime import datetime
from typing import List, Optional, Dict

from fastapi import APIRouter, Depends, Path, BackgroundTasks, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field

from linkshield.authentication.auth_service import AuthService
from linkshield.authentication.dependencies import get_current_user
from linkshield.config.settings import get_settings
from linkshield.controllers.user_controller import (
    UserController,
    UserResponse,
    LoginResponse,
    APIKeyResponse,
    SessionResponse,
)
from linkshield.models.user import User
from linkshield.services.depends import get_security_service, get_auth_service, get_email_service
from linkshield.services.security_service import SecurityService
from linkshield.services.advanced_rate_limiter import rate_limit, RateLimitScope

# ------------------------------------------------------------------
# Router
# ------------------------------------------------------------------
router = APIRouter(prefix="/api/v1/user", tags=["User Management"])
security = HTTPBearer()
settings = get_settings()


# ------------------------------------------------------------------
# Dependency injection
# ------------------------------------------------------------------
def get_user_controller(
    security_service: SecurityService = Depends(get_security_service),
    auth_service: AuthService = Depends(get_auth_service),
    email_service = Depends(get_email_service),
) -> UserController:
    return UserController(
        security_service=security_service,
        auth_service=auth_service,
        email_service=email_service,
    )


# ------------------------------------------------------------------
# Shared request models (kept in routes for FastAPI validation)
# ------------------------------------------------------------------
class UserRegistrationRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    first_name: Optional[str] = Field(None, max_length=100)
    last_name: Optional[str] = Field(None, max_length=100)
    username: Optional[str] = Field(None, max_length=50)
    avatar_url: Optional[str] = Field(None, max_length=500)
    accept_terms: bool
    marketing_consent: bool = False


class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str
    remember_me: bool = False
    device_info: Optional[Dict[str, str]] = None


class ProfileUpdateRequest(BaseModel):
    full_name: Optional[str] = Field(None, min_length=1, max_length=100)
    company: Optional[str] = Field(None, max_length=100)
    profile_picture_url: Optional[str] = Field(None, max_length=500)
    marketing_consent: Optional[bool] = None
    timezone: Optional[str] = Field(None, max_length=50)
    language: Optional[str] = Field(None, max_length=10)


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8, max_length=128)


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8, max_length=128)


class EmailVerificationRequest(BaseModel):
    token: str


class ResendVerificationRequest(BaseModel):
    email: EmailStr


class CreateAPIKeyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    expires_at: Optional[datetime] = None
    permissions: List[str] = ["url_check"]



# ------------------------------------------------------------------
# Routes (thin layer) – now with full doc-strings
# ------------------------------------------------------------------

@router.post("/register", response_model=UserResponse, summary="Register new user")
@rate_limit(scope=RateLimitScope.AUTH_REGISTRATION)
async def register_user(
    request: UserRegistrationRequest,
    background_tasks: BackgroundTasks,
    req: Request,
    controller: UserController = Depends(get_user_controller),
) -> UserResponse:
    """
    Register a new user account with progressive rate limiting.

    **Request body** – `UserRegistrationRequest`
    - `email`: valid e-mail address (unique)
    - `password`: 8-128 chars, must contain upper, lower, digit, special
    - `first_name`, `last_name`, `username`, `avatar_url`: optional
    - `accept_terms`: must be `true`
    - `marketing_consent`: optional boolean (default `false`)

    **Response** – `UserResponse` (full serialized user profile)

    **Side-effects**
    - Creates user row (password hashed)
    - Generates e-mail verification token
    - Queues verification e-mail (background task)

    **Rate-limit**: 5 registrations / hour / IP (progressive restriction)

    **Errors**:
    - 400  – validation or terms not accepted
    - 409  – e-mail already registered
    - 429  – rate-limit exceeded
    """
    return await controller.register_user(request_model=request, background_tasks=background_tasks, req=req)


@router.post("/login", response_model=LoginResponse, summary="User login")
@rate_limit(scope=RateLimitScope.AUTH_LOGIN)
async def login(
    request_model: UserLoginRequest,
    request: Request,
    user_controller: UserController = Depends(get_user_controller),
) -> LoginResponse:
    """
    User login endpoint with progressive rate limiting and failed login tracking.
    
    Progressive rate limiting:
    - 10 login attempts / 15 min / IP (sliding window)
    - Failed login attempts trigger additional rate limiting
    - Account lockout after 5 failed attempts
    
    Returns:
        LoginResponse: Access token and user information
        
    Raises:
        HTTPException: 401 for invalid credentials, 423 for locked account, 429 for rate limit exceeded
    """
    try:
        return await user_controller.login_user(request_model=request_model, req=request)
    except HTTPException as e:
        # If login failed due to invalid credentials, apply failed login rate limiting
        if e.status_code == 401:
            # Apply additional rate limiting for failed login attempts
            from linkshield.services.advanced_rate_limiter import get_advanced_rate_limiter
            rate_limiter = get_advanced_rate_limiter()
            
            # Get client IP for failed login tracking
            client_ip = request.client.host if request.client else "unknown"
            
            # Check failed login rate limit
            failed_login_result = await rate_limiter.check_rate_limit(
                scope=RateLimitScope.AUTH_LOGIN_FAILED,
                identifier=client_ip,
                user_id=None,  # No user ID for failed login
                subscription_plan="free"  # Default plan for failed attempts
            )
            
            if not failed_login_result.allowed:
                # If failed login rate limit exceeded, return 429 instead of 401
                raise HTTPException(
                    status_code=429,
                    detail="Too many failed login attempts. Please try again later.",
                    headers={"Retry-After": str(failed_login_result.retry_after)}
                )
        
        # Re-raise the original exception
        raise e


@router.post("/logout", summary="User logout")
async def logout_user(
    user: User = Depends(get_current_user),
    credentials: HTTPAuthorizationCredentials = Depends(security),
    controller: UserController = Depends(get_user_controller),
) -> None:
    """
    Invalidate the caller’s session (or all sessions if token missing).

    Requires valid bearer token. Returns 204 No Content on success.
    """
    await controller.logout_user(user=user, credentials=credentials)


@router.get("/profile", response_model=UserResponse, summary="Get user profile")
async def get_user_profile(
    user: User = Depends(get_current_user),
    controller: UserController = Depends(get_user_controller),
) -> UserResponse:
    """
    Return the authenticated user’s full profile.

    **Response** – `UserResponse`
    """
    return await controller.get_user_profile(user=user)


@router.put("/profile", response_model=UserResponse, summary="Update user profile")
async def update_user_profile(
    request: ProfileUpdateRequest,
    user: User = Depends(get_current_user),
    controller: UserController = Depends(get_user_controller),
) -> UserResponse:
    """
    Update editable profile fields.

    **Request body** – `ProfileUpdateRequest` (all fields optional)
    - `full_name`
    - `company`
    - `profile_picture_url`
    - `marketing_consent`
    - `timezone`
    - `language`

    **Response** – updated `UserResponse`
    """
    return await controller.update_user_profile(request_model=request, user=user)


@router.post("/change-password", summary="Change user password")
@rate_limit(scope=RateLimitScope.AUTH_CHANGE_PASSWORD)
async def change_password(
    request: PasswordChangeRequest,
    user: User = Depends(get_current_user),
    controller: UserController = Depends(get_user_controller),
) -> None:
    """
    Change password while authenticated with progressive rate limiting.

    **Request body** – `PasswordChangeRequest`
    - `current_password`: must match stored hash
    - `new_password`: must meet strength rules and differ from current

    **Side-effects**
    - Hashes new password
    - Invalidates **all** existing sessions (forces re-login)

    **Rate-limit**: 5 password changes / hour / user (progressive restriction)

    **Errors**:
    - 400 – current password wrong / new password weak or identical
    - 429 – rate-limit exceeded
    """
    await controller.change_password(request_model=request, user=user)


@router.post("/forgot-password", summary="Request password reset")
@rate_limit(scope=RateLimitScope.AUTH_PASSWORD_RESET)
async def forgot_password(
    request: ForgotPasswordRequest,
    req: Request,
    background_tasks: BackgroundTasks,
    controller: UserController = Depends(get_user_controller),
) -> None:
    """
    Request a password-reset e-mail with progressive rate limiting.

    **Request body** – `ForgotPasswordRequest`
    - `email`: address to receive reset link

    **Behavior**
    - Always returns 204 (does not reveal whether e-mail exists)
    - If account exists & active → generates single-use token (1 h expiry)
    - Queues reset e-mail as background task

    **Rate-limit**: 3 password reset requests / hour / IP (progressive restriction)

    **Errors**:
    - 429 – rate-limit exceeded
    """
    await controller.forgot_password(request_model=request, req=req, background_tasks=background_tasks)


@router.post("/reset-password", summary="Reset password with token")
async def reset_password(
    request: ResetPasswordRequest,
    controller: UserController = Depends(get_user_controller),
) -> None:
    """
    Complete password reset flow.

    **Request body** – `ResetPasswordRequest`
    - `token`: from e-mail link
    - `new_password`: must meet strength rules

    **Side-effects**
    - Hashes new password
    - Invalidates **all** sessions
    - Marks token used

    **Note**: Rate limiting handled by token validation (single-use tokens)

    **Errors**:
    - 400 – invalid, expired, or already-used token
    """
    await controller.reset_password(request_model=request)


@router.post("/verify-email", summary="Verify email address")
@rate_limit(scope=RateLimitScope.AUTH_EMAIL_VERIFICATION)
async def verify_email(
    request: EmailVerificationRequest,
    controller: UserController = Depends(get_user_controller),
) -> UserResponse:
    """
    Verify e-mail address using token received in inbox with progressive rate limiting.

    **Request body** – `EmailVerificationRequest`
    - `token`: 24-hour valid token

    **Response** – updated `UserResponse` (`is_verified=true`)

    **Rate-limit**: 5 email verifications / hour / IP (progressive restriction)

    **Errors**:
    - 400 – invalid, expired, or already-used token
    - 429 – rate-limit exceeded
    """
    return await controller.verify_email(request_model=request)


@router.post("/resend-verification", summary="Resend email verification")
@rate_limit(scope=RateLimitScope.AUTH_RESEND_VERIFICATION)
async def resend_verification(
    request: ResendVerificationRequest,
    background_tasks: BackgroundTasks,
    controller: UserController = Depends(get_user_controller),
) -> None:
    """
    Re-send verification e-mail for an unverified account with progressive rate limiting.

    **Request body** – `ResendVerificationRequest`
    - `email`: address to re-send to

    **Behavior**
    - Returns 204 regardless of existence or verification state
    - If unverified account exists → new token generated & e-mail queued

    **Rate-limit**: 3 resend verification requests / hour / IP (progressive restriction)

    **Errors**:
    - 429 – rate-limit exceeded
    """
    await controller.resend_verification(request_model=request, background_tasks=background_tasks)


@router.get("/api-keys", response_model=List[APIKeyResponse], summary="Get user API keys")
async def get_api_keys(
    user: User = Depends(get_current_user),
    controller: UserController = Depends(get_user_controller),
) -> List[APIKeyResponse]:
    """
    List caller’s active API keys (metadata only – secrets are shown once at creation).

    **Response** – `List[APIKeyResponse]`
    - `id`, `name`, `description`, `key_preview` (first 8 chars)
    - `permissions`, `is_active`, `expires_at`, `last_used_at`, `created_at`
    """
    return await controller.get_api_keys(user=user)


@router.post("/api-keys", response_model=APIKeyResponse, summary="Create new API key")
async def create_api_key(
    request: CreateAPIKeyRequest,
    user: User = Depends(get_current_user),
    controller: UserController = Depends(get_user_controller),
) -> APIKeyResponse:
    """
    Generate a new API key for programmatic access.

    **Request body** – `CreateAPIKeyRequest`
    - `name`: human-readable label
    - `description`: optional
    - `expires_at`: optional UTC datetime
    - `permissions`: list of strings (default `["url_check"]`)

    **Response** – `APIKeyResponse` (includes full key in `key_preview`)

    **Limits**:
    - Free tier: 3 keys max
    - Premium tier: 10 keys max

    **Errors**:
    - 400 – limit reached or invalid permission
    """
    response, _ = await controller.create_api_key(request_model=request, user=user)
    return response


@router.delete("/api-keys/{key_id}", summary="Delete API key")
async def delete_api_key(
    key_id: str = Path(..., description="API key ID"),
    user: User = Depends(get_current_user),
    controller: UserController = Depends(get_user_controller),
) -> None:
    """
    Soft-delete (revoke) an API key.

    **Path parameter**
    - `key_id`: UUID of key to delete

    **Response** – 204 No Content on success
    **Errors** – 404 if key not found or not owned by caller
    """
    await controller.delete_api_key(key_id=key_id, user=user)


@router.get("/sessions", response_model=List[SessionResponse], summary="Get user sessions")
async def get_user_sessions(
    user: User = Depends(get_current_user),
    controller: UserController = Depends(get_user_controller),
) -> List[SessionResponse]:
    """
    List caller’s active sessions (excluding expired).

    **Response** – `List[SessionResponse]`
    - `id`, `device_info`, `ip_address`, `user_agent`
    - `is_active`, `expires_at`, `last_activity_at`, `created_at`
    """
    return await controller.get_user_sessions(user=user)


@router.delete("/sessions/{session_id}", summary="Delete user session")
async def delete_user_session(
    session_id: str = Path(..., description="Session ID"),
    user: User = Depends(get_current_user),
    controller: UserController = Depends(get_user_controller),
) -> None:
    """
    Terminate a specific session (log it out).

    **Path parameter**
    - `session_id`: UUID of session to terminate

    **Response** – 204 No Content
    **Errors** – 404 if session not found or not owned by caller
    """
    await controller.delete_user_session(session_id=session_id, user=user)


@router.delete("/sessions", summary="Terminate all sessions")
async def terminate_all_sessions(
    user: User = Depends(get_current_user),
    controller: UserController = Depends(get_user_controller),
) -> None:
    """
    Revoke **all** of the caller’s sessions **except the current one**
    (effectively a global logout on all devices).

    **Response** – 204 No Content
    """
    await controller.terminate_all_sessions(user=user)
