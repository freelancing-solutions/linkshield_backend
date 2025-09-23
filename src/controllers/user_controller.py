#!/usr/bin/env python3
"""
User controller for LinkShield.

All business logic + Pydantic response models live here.
Public methods return typed models and use keyword-only arguments.
"""

from __future__ import annotations
import uuid
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple, Any as AnyType

from fastapi import HTTPException, status, BackgroundTasks, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import and_, select, update
from sqlalchemy.exc import IntegrityError

from src.controllers.base_controller import BaseController
from src.models.user import User, UserSession, APIKey, PasswordResetToken, EmailVerificationToken
from src.models.email import EmailRequest, EmailType
from src.services.security_service import SecurityService
from src.authentication.auth_service import AuthService
from src.services.email_service import EmailService
from src.utils import utc_datetime


class InvalidCredentialsError(Exception):
    """Raised when credentials are invalid."""


# ------------------------------------------------------------------
# Pydantic response models (live close to business logic)
# ------------------------------------------------------------------
class SubscriptionPlanResponse(BaseModel):
    id: int
    name: str
    price: float
    active: bool

    class Config:
        from_attributes = True


class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    username: Optional[str]
    first_name: Optional[str]
    last_name: Optional[str]
    full_name: str
    role: str
    status: str
    subscription_plan: str
    subscription_active: bool
    is_active: bool
    is_verified: bool
    avatar_url: Optional[str]
    bio: Optional[str]
    website: Optional[str]
    location: Optional[str]
    email_notifications: bool
    marketing_emails: bool
    created_at: datetime
    updated_at: datetime
    last_login_at: Optional[datetime]
    email_verified_at: Optional[datetime]

    class Config:
        from_attributes = True


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse
    session_id: str


class APIKeyResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: Optional[str]
    key_preview: str
    permissions: List[str]
    is_active: bool
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


class SessionResponse(BaseModel):
    id: uuid.UUID
    device_info: Optional[str]
    ip_address: Optional[str]
    user_agent: Optional[str]
    is_active: bool
    expires_at: datetime
    last_activity_at: datetime
    created_at: datetime

    class Config:
        from_attributes = True


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------
def _to_user_response(user: User) -> UserResponse:
    return UserResponse(
        id=user.id,
        email=user.email,
        username=user.username,
        first_name=user.first_name,
        last_name=user.last_name,
        full_name=user.get_full_name(),
        role=user.role.value,
        status=user.status.value,
        subscription_plan=user.subscription_plan.value,
        subscription_active=user.is_subscription_active(),
        is_active=user.is_active,
        is_verified=user.is_verified,
        avatar_url=user.avatar_url,
        bio=user.bio,
        website=user.website,
        location=user.location,
        email_notifications=user.email_notifications,
        marketing_emails=user.marketing_emails,
        created_at=user.created_at,
        updated_at=user.updated_at,
        last_login_at=user.last_login_at,
        email_verified_at=user.email_verified_at,
    )


# ------------------------------------------------------------------
# Controller
# ------------------------------------------------------------------
class UserController(BaseController):
    def __init__(
        self,
        *,
        security_service: SecurityService,
        auth_service: AuthService,
        email_service: EmailService,
    ) -> None:
        super().__init__(security_service, auth_service, email_service)

        self.registration_rate_limit = 5
        self.login_rate_limit = 10
        self.password_reset_rate_limit = 3
        self.api_key_rate_limit = 10

    # --------------------------------------------------------------
    # Public route-friendly methods (keyword-only, return Pydantic)
    # --------------------------------------------------------------
    async def register_user(
        self,
        *,
        request_model: AnyType,
        background_tasks: Optional[BackgroundTasks] = None,
        req: Optional[Request] = None,
    ) -> UserResponse:
        data = request_model
        email = getattr(data, "email", None) or (data.get("email") if isinstance(data, dict) else None)
        password = getattr(data, "password", None) or (data.get("password") if isinstance(data, dict) else None)
        first_name = getattr(data, "first_name", None) or (data.get("first_name") if isinstance(data, dict) else None)
        last_name = getattr(data, "last_name", None) or (data.get("last_name") if isinstance(data, dict) else None)
        username = getattr(data, "username", None) or (data.get("username") if isinstance(data, dict) else None)
        avatar_url = getattr(data, "avatar_url", None) or (data.get("avatar_url") if isinstance(data, dict) else None)
        accept_terms = getattr(data, "accept_terms", False) or (data.get("accept_terms") if isinstance(data, dict) else False)
        marketing_consent = getattr(data, "marketing_consent", False) or (data.get("marketing_consent") if isinstance(data, dict) else False)

        if not accept_terms:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Terms of service must be accepted")

        if req:
            ip = getattr(req.client, "host", None)
            if ip and not await self.check_rate_limit(ip, "registration", self.registration_rate_limit, window_seconds=3600):
                raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Registration rate limit exceeded")

        if not self.auth_service.validate_email(email):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email format")

        if not self.auth_service.check_password_strength(password):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password does not meet security requirements")

        try:
            async with self.get_db_session() as session:
                stmt = select(User).where(User.email == email.lower())
                result = await session.execute(stmt)
                existing = result.scalar_one_or_none()
                if existing:
                    raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User already exists")

                user = User(
                    id=uuid.uuid4(),
                    email=email.lower(),
                    username=username,
                    first_name=first_name,
                    last_name=last_name,
                    avatar_url=avatar_url,
                    marketing_emails=marketing_consent,
                    is_active=True,
                )
                user.set_password(password)
                session.add(user)
                await session.commit()
                await session.refresh(user)

            token = await self._create_email_verification_token(user)
            if background_tasks:
                background_tasks.add_task(self._send_verification_email, user=user, token=token.token_hash)
            else:
                try:
                    await self._send_verification_email(user=user, token=token.token_hash)
                except Exception:
                    pass

            self.log_operation("User registered", user_id=user.id, details={"email": email})
            return _to_user_response(user)

        except HTTPException:
            raise
        except IntegrityError:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User already exists")
        except Exception as e:
            raise self.handle_database_error(e, "user registration")

    async def login_user(
        self,
        *,
        request_model: AnyType,
        req: Optional[Request] = None,
    ) -> LoginResponse:
        data = request_model
        email = getattr(data, "email", None) or (data.get("email") if isinstance(data, dict) else None)
        password = getattr(data, "password", None) or (data.get("password") if isinstance(data, dict) else None)
        remember_me = getattr(data, "remember_me", False) or (data.get("remember_me") if isinstance(data, dict) else False)
        device_info = getattr(data, "device_info", None) or (data.get("device_info") if isinstance(data, dict) else None)

        if req:
            ip = getattr(req.client, "host", None)
            if ip and not await self.check_rate_limit(ip, "login", self.login_rate_limit, window_seconds=900):
                raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Login rate limit exceeded")

        try:
            async with self.get_db_session() as session:
                stmt = select(User).where(User.email == email.lower())
                result = await session.execute(stmt)
                user = result.scalar_one_or_none()

                if not user:
                    raise InvalidCredentialsError("Invalid email or password")

                if self._is_account_locked(user=user):
                    raise HTTPException(status_code=status.HTTP_423_LOCKED, detail="Account locked")

                if not self.auth_service.verify_password(password, user.password_hash):
                    await self._record_failed_login(user=user)
                    raise InvalidCredentialsError("Invalid email or password")

                user.failed_login_attempts = 0
                user.locked_until = None
                if not user.is_active:
                    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account deactivated")

                user.last_login_at = utc_datetime()
                session.add(user)
                await session.commit()
                await session.refresh(user)

            session_duration = timedelta(days=30 if remember_me else 1)
            session = await self._create_user_session(user=user, duration=session_duration, device_info=device_info, request=req)
            access_token = self.auth_service.create_access_token(
                user_id=user.id,
                session_id=session.id,
                expires_delta=session_duration,
            )

            self.log_operation("User logged in", user_id=user.id, details={"session_id": str(session.id)})
            return LoginResponse(
                access_token=access_token,
                token_type="bearer",
                expires_in=int(session_duration.total_seconds()),
                user=_to_user_response(user),
                session_id=str(session.id),
            )

        except InvalidCredentialsError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
        except HTTPException:
            raise
        except Exception as e:
            raise self.handle_database_error(e, "user login")

    async def logout_user(
        self,
        *,
        user: User,
        credentials: Optional[AnyType] = None,
    ) -> None:
        try:
            session_id = None
            if credentials and hasattr(credentials, "credentials"):
                try:
                    token_data = self.auth_service.verify_jwt_token(credentials.credentials)
                    session_id = token_data.get("session_id")
                except Exception:
                    session_id = None

            async with self.get_db_session() as session:
                if session_id:
                    stmt = select(UserSession).where(
                        and_(
                            UserSession.id == session_id,
                            UserSession.user_id == user.id,
                            UserSession.is_active == True,
                        )
                    )
                    result = await session.execute(stmt)
                    ses = result.scalar_one_or_none()
                    if ses:
                        ses.is_active = False
                        ses.ended_at = datetime.now(timezone.utc)
                        session.add(ses)
                        await session.commit()
                else:
                    stmt = (
                        update(UserSession)
                        .where(
                            and_(
                                UserSession.user_id == user.id,
                                UserSession.is_active == True,
                            )
                        )
                        .values({"is_active": False, "ended_at": datetime.now(timezone.utc)})
                    )
                    await session.execute(stmt)
                    await session.commit()

            self.log_operation(
                "User logged out",
                user_id=user.id,
                details={"session_id": str(session_id) if session_id else "all"},
            )
        except Exception as e:
            raise self.handle_database_error(e, "user logout")

    async def get_user_profile(self, *, user: User) -> UserResponse:
        self.log_operation("User profile retrieved", user_id=user.id)
        return _to_user_response(user)

    async def update_user_profile(self, *, request_model: AnyType, user: User) -> UserResponse:
        data = request_model
        full_name = getattr(data, "full_name", None)
        company = getattr(data, "company", None)
        profile_picture_url = getattr(data, "profile_picture_url", None)
        marketing_consent = getattr(data, "marketing_consent", None)
        tz = getattr(data, "timezone", None)
        language = getattr(data, "language", None)

        try:
            if full_name is not None:
                user.full_name = full_name
            if company is not None:
                user.company = company
            if profile_picture_url is not None:
                user.profile_picture_url = profile_picture_url
            if marketing_consent is not None:
                user.marketing_consent = marketing_consent
            if tz is not None:
                user.timezone = tz
            if language is not None:
                user.language = language

            user.updated_at = datetime.now(timezone.utc)
            async with self.get_db_session() as session:
                session.add(user)
                await session.commit()
                await session.refresh(user)

            self.log_operation("User profile updated", user_id=user.id)
            return _to_user_response(user)

        except Exception as e:
            raise self.handle_database_error(e, "profile update")

    async def change_password(self, *, request_model: AnyType, user: User) -> None:
        current_password = getattr(request_model, "current_password", None)
        new_password = getattr(request_model, "new_password", None)

        try:
            if not self.auth_service.verify_password(current_password, user.password_hash):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password incorrect")
            if self.auth_service.verify_password(new_password, user.password_hash):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New password must differ")
            if not self.auth_service.check_password_strength(new_password):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New password does not meet requirements")

            async with self.get_db_session() as session:
                user.password_hash = self.auth_service.hash_password(new_password)
                user.password_changed_at = datetime.now(timezone.utc)
                user.updated_at = datetime.now(timezone.utc)
                stmt = (
                    update(UserSession)
                    .where(
                        and_(
                            UserSession.user_id == user.id,
                            UserSession.is_active == True,
                        )
                    )
                    .values({"is_active": False, "ended_at": datetime.now(timezone.utc)})
                )
                await session.execute(stmt)
                session.add(user)
                await session.commit()

            self.log_operation("Password changed", user_id=user.id)
        except HTTPException:
            raise
        except Exception as e:
            raise self.handle_database_error(e, "password change")

    async def forgot_password(
        self,
        *,
        request_model: AnyType,
        req: Optional[Request] = None,
        background_tasks: Optional[BackgroundTasks] = None,
    ) -> None:
        email = getattr(request_model, "email", None) or (request_model.get("email") if isinstance(request_model, dict) else None)
        await self.request_password_reset(email=email, request=req, background_tasks=background_tasks)

    async def reset_password(self, *, request_model: AnyType) -> None:
        token = getattr(request_model, "token", None) or (request_model.get("token") if isinstance(request_model, dict) else None)
        new_password = getattr(request_model, "new_password", None) or (request_model.get("new_password") if isinstance(request_model, dict) else None)
        await self._reset_password_impl(token=token, new_password=new_password)

    async def get_api_keys(self, *, user: User) -> List[APIKeyResponse]:
        keys = await self.list_api_keys(user=user)
        return [
            APIKeyResponse(
                id=k.id,
                name=k.name,
                description=k.description,
                key_preview=k.key_prefix,
                permissions=k.permissions or [],
                is_active=k.is_active,
                expires_at=k.expires_at,
                last_used_at=k.last_used_at,
                created_at=k.created_at,
            )
            for k in keys
        ]

    async def create_api_key(
        self,
        *,
        request_model: AnyType,
        user: User,
    ) -> Tuple[APIKeyResponse, str]:
        data = request_model
        name = getattr(data, "name", None) or (data.get("name") if isinstance(data, dict) else None)
        description = getattr(data, "description", None) or (data.get("description") if isinstance(data, dict) else None)
        expires_at = getattr(data, "expires_at", None) or (data.get("expires_at") if isinstance(data, dict) else None)
        permissions = getattr(data, "permissions", None) or (data.get("permissions") if isinstance(data, dict) else None)
        api_key, raw_key = await self._create_api_key_impl(
            user=user,
            name=name,
            description=description,
            expires_at=expires_at,
            permissions=permissions,
        )
        return (
            APIKeyResponse(
                id=api_key.id,
                name=api_key.name,
                description=api_key.description,
                key_preview=api_key.key_prefix,
                permissions=api_key.permissions or [],
                is_active=api_key.is_active,
                expires_at=api_key.expires_at,
                last_used_at=api_key.last_used_at,
                created_at=api_key.created_at,
            ),
            raw_key,
        )

    async def delete_api_key(self, *, key_id: AnyType, user: User) -> None:
        try:
            key_uuid = uuid.UUID(str(key_id))
        except Exception:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid API key id")
        await self._delete_api_key_impl(user=user, key_id=key_uuid)

    async def get_user_sessions(self, *, user: User) -> List[SessionResponse]:
        sessions = await self.list_user_sessions(user=user)
        return [
            SessionResponse(
                id=s.id,
                device_info=s.device_info,
                ip_address=s.ip_address,
                user_agent=s.user_agent,
                is_active=s.is_active,
                expires_at=s.expires_at,
                last_activity_at=s.last_accessed_at,
                created_at=s.created_at,
            )
            for s in sessions
        ]

    async def delete_user_session(self, *, session_id: AnyType, user: User) -> None:
        try:
            sess_uuid = uuid.UUID(str(session_id))
        except Exception:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid session id")
        await self.terminate_session(user=user, session_id=sess_uuid)

    async def terminate_all_sessions(self, *, user: User) -> int:
        return await self.terminate_all_sessions_impl(user=user)

    async def verify_email(self, *, request_model: AnyType) -> UserResponse:
        token = getattr(request_model, "token", None) or (request_model.get("token") if isinstance(request_model, dict) else None)
        user = await self._verify_email_impl(token=token)
        return _to_user_response(user)

    async def resend_verification(
        self,
        *,
        request_model: AnyType,
        background_tasks: Optional[BackgroundTasks] = None,
    ) -> None:
        email = getattr(request_model, "email", None) or (request_model.get("email") if isinstance(request_model, dict) else None)
        try:
            async with self.get_db_session() as session:
                stmt = select(User).where(User.email == email.lower())
                result = await session.execute(stmt)
                user = result.scalar_one_or_none()
                if not user or user.is_verified:
                    return None
                token = await self._create_email_verification_token(user=user)
                if background_tasks:
                    background_tasks.add_task(self._send_verification_email, user=user, token=token.token_hash)
                else:
                    await self._send_verification_email(user=user, token=token.token_hash)
                self.log_operation("Verification email resent (public)", user_id=user.id)
        except Exception as e:
            self.logger.error(f"Resend verification failed for {email}: {e}")
            return None

    # ------------------------------------------------------------------
    # Private implementations (unchanged internals omitted for brevity)
    # ------------------------------------------------------------------
    async def _create_api_key_impl(
        self,
        *,
        user: User,
        name: str,
        description: Optional[str],
        expires_at: Optional[datetime],
        permissions: Optional[List[str]],
    ) -> Tuple[APIKey, str]:
        if permissions is None:
            permissions = ["url_check"]
        valid_permissions = {"url_check", "report_create", "report_read", "admin"}
        invalid = set(permissions) - valid_permissions
        if invalid:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid permissions: {', '.join(invalid)}")

        try:
            async with self.get_db_session() as session:
                stmt = select(APIKey).where(and_(APIKey.user_id == user.id, APIKey.is_active == True))
                result = await session.execute(stmt)
                keys = result.scalars().all()
                if len(keys) >= (10 if getattr(user, "subscription_tier", "free") == "premium" else 3):
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="API key limit reached")

                raw_key = secrets.token_urlsafe(32)
                key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
                api_key = APIKey(
                    id=uuid.uuid4(),
                    user_id=user.id,
                    name=name,
                    key_hash=key_hash,
                    key_prefix=raw_key[:8],
                    is_active=True,
                    rate_limit=100,
                    usage_count=0,
                    last_used_at=None,
                    created_at=datetime.now(timezone.utc),
                    expires_at=expires_at,
                    description=description if hasattr(APIKey, "description") else None,
                    permissions=permissions,
                )
                session.add(api_key)
                await session.commit()
                await session.refresh(api_key)

            self.log_operation("API key created", user_id=user.id, details={"key_id": str(api_key.id)})
            return api_key, raw_key
        except Exception as e:
            raise self.handle_database_error(e, "API key creation")

    async def _delete_api_key_impl(self, *, user: User, key_id: uuid.UUID) -> None:
        try:
            async with self.get_db_session() as session:
                stmt = select(APIKey).where(and_(APIKey.id == key_id, APIKey.user_id == user.id, APIKey.is_active == True))
                result = await session.execute(stmt)
                key = result.scalar_one_or_none()
                if not key:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")
                key.is_active = False
                key.deleted_at = datetime.now(timezone.utc)
                session.add(key)
                await session.commit()
            self.log_operation("API key deleted", user_id=user.id, details={"key_id": str(key_id)})
        except HTTPException:
            raise
        except Exception as e:
            raise self.handle_database_error(e, "API key deletion")

    async def list_api_keys(self, *, user: User) -> List[APIKey]:
        try:
            async with self.get_db_session() as session:
                stmt = select(APIKey).where(and_(APIKey.user_id == user.id, APIKey.is_active == True))
                result = await session.execute(stmt)
                keys = result.scalars().all()
            return keys
        except Exception as e:
            raise self.handle_database_error(e, "API key listing")

    async def list_user_sessions(self, *, user: User) -> List[UserSession]:
        try:
            async with self.get_db_session() as session:
                stmt = select(UserSession).where(
                    and_(
                        UserSession.user_id == user.id,
                        UserSession.is_active == True,
                        UserSession.expires_at > datetime.now(timezone.utc),
                    )
                )
                result = await session.execute(stmt)
                sessions = result.scalars().all()
            self.log_operation("User sessions listed", user_id=user.id, details={"count": len(sessions)})
            return sessions
        except Exception as e:
            raise self.handle_database_error(e, "user sessions listing")

    async def terminate_session(self, *, user: User, session_id: uuid.UUID) -> None:
        try:
            async with self.get_db_session() as session:
                stmt = select(UserSession).where(
                    and_(
                        UserSession.id == session_id,
                        UserSession.user_id == user.id,
                        UserSession.is_active == True,
                    )
                )
                result = await session.execute(stmt)
                ses = result.scalar_one_or_none()
                if not ses:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
                ses.is_active = False
                ses.ended_at = datetime.now(timezone.utc)
                session.add(ses)
                await session.commit()
            self.log_operation("Session terminated", user_id=user.id, details={"session_id": str(session_id)})
        except HTTPException:
            raise
        except Exception as e:
            raise self.handle_database_error(e, "session termination")

    async def terminate_all_sessions_impl(self, *, user: User) -> int:
        try:
            async with self.get_db_session() as session:
                stmt = select(UserSession).where(
                    and_(
                        UserSession.user_id == user.id,
                        UserSession.is_active == True,
                    )
                )
                result = await session.execute(stmt)
                sessions = result.scalars().all()
                count = len(sessions)
                if count:
                    stmt2 = (
                        update(UserSession)
                        .where(
                            and_(
                                UserSession.user_id == user.id,
                                UserSession.is_active == True,
                            )
                        )
                        .values({"is_active": False, "ended_at": datetime.now(timezone.utc)})
                    )
                    await session.execute(stmt2)
                    await session.commit()
            self.log_operation("All sessions terminated", user_id=user.id, details={"sessions_terminated": count})
            return count
        except Exception as e:
            raise self.handle_database_error(e, "session termination")

    async def _verify_email_impl(self, *, token: str) -> User:
        try:
            async with self.get_db_session() as session:
                stmt = select(EmailVerificationToken).where(
                    and_(
                        EmailVerificationToken.token_hash == token,
                        EmailVerificationToken.is_used == False,
                        EmailVerificationToken.expires_at > datetime.now(timezone.utc),
                    )
                )
                result = await session.execute(stmt)
                verification_token = result.scalar_one_or_none()
                if not verification_token:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired verification token")

                stmt = select(User).where(User.id == verification_token.user_id)
                result = await session.execute(stmt)
                user = result.scalar_one_or_none()
                if not user:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid verification token")

                user.is_verified = True
                user.email_verified_at = datetime.now(timezone.utc)
                user.updated_at = datetime.now(timezone.utc)

                verification_token.is_used = True
                verification_token.used_at = datetime.now(timezone.utc)

                session.add(user)
                session.add(verification_token)
                await session.commit()
                await session.refresh(user)

            self.log_operation("Email verified", user_id=user.id)
            return user
        except HTTPException:
            raise
        except Exception as e:
            raise self.handle_database_error(e, "email verification")

    async def _create_user_session(
        self,
        *,
        user: User,
        duration: timedelta,
        device_info: Optional[str] = None,
        request: Optional[Request] = None,
    ) -> UserSession:
        async with self.get_db_session() as session:
            us = UserSession(
                id=uuid.uuid4(),
                user_id=user.id,
                device_info=device_info,
                ip_address=(request.client.host if request else None),
                user_agent=(request.headers.get("user-agent") if request else None),
                is_active=True,
                expires_at=utc_datetime() + duration,
                last_accessed_at=utc_datetime(),
                created_at=utc_datetime(),
            )
            session.add(us)
            await session.commit()
            await session.refresh(us)
            return us

    async def _create_email_verification_token(self, *, user: User) -> EmailVerificationToken:
        async with self.get_db_session() as session:
            await session.execute(
                update(EmailVerificationToken)
                .where(
                    and_(
                        EmailVerificationToken.user_id == user.id,
                        EmailVerificationToken.is_used == False,
                    )
                )
                .values({"is_used": True, "used_at": datetime.now(timezone.utc)})
            )
            token = EmailVerificationToken(
                id=uuid.uuid4(),
                user_id=user.id,
                token_hash=secrets.token_urlsafe(32),
                email=user.email,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
                is_used=False,
                created_at=datetime.now(timezone.utc),
            )
            session.add(token)
            await session.commit()
            await session.refresh(token)
            return token

    async def _create_password_reset_token(self, *, user: User) -> PasswordResetToken:
        async with self.get_db_session() as session:
            await session.execute(
                update(PasswordResetToken)
                .where(
                    and_(
                        PasswordResetToken.user_id == user.id,
                        PasswordResetToken.is_used == False,
                    )
                )
                .values({"is_used": True, "used_at": datetime.now(timezone.utc)})
            )
            token = PasswordResetToken(
                id=uuid.uuid4(),
                user_id=user.id,
                token_hash=secrets.token_urlsafe(32),
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                is_used=False,
                created_at=datetime.now(timezone.utc),
            )
            session.add(token)
            await session.commit()
            await session.refresh(token)
            return token

    async def _send_verification_email(self, *, user: User, token: str) -> None:
        if self.email_service:
            settings = __import__("src.config.settings", fromlist=["get_settings"]).get_settings()
            verification_url = f"{settings.APP_URL}/verify-email?token={token}"
            user_name = user.first_name or user.username or user.email.split("@")[0]
            email_request = EmailRequest(
                to=user.email,
                subject=f"Verify your {settings.APP_NAME} account",
                email_type=EmailType.VERIFICATION,
                template_variables={
                    "user_name": user_name,
                    "verification_url": verification_url,
                    "expiry_hours": 24,
                    "current_year": datetime.now().year,
                },
            )
            await self.email_service.send_email(email_request, EmailType.VERIFICATION.value)
        else:
            self.logger.info(f"Verification email (mock) for {user.email}: {token}")

    async def _send_password_reset_email(self, *, user: User, token: str) -> None:
        if self.email_service:
            settings = __import__("src.config.settings", fromlist=["get_settings"]).get_settings()
            reset_url = f"{settings.APP_URL}/reset-password?token={token}"
            email_request = EmailRequest(
                to=user.email,
                subject=f"Reset your {settings.APP_NAME} password",
                email_type=EmailType.PASSWORD_RESET,
                template_variables={
                    "user_name": (user.full_name.split()[0] if user.full_name else "User"),
                    "reset_url": reset_url,
                    "expiry_hours": 1,
                    "current_year": datetime.now().year,
                },
            )
            await self.email_service.send_email(email_request, EmailType.PASSWORD_RESET.value)
        else:
            self.logger.info(f"Password reset email (mock) for {user.email}: {token}")

    async def request_password_reset(
        self,
        *,
        email: str,
        request: Optional[Request] = None,
        background_tasks: Optional[BackgroundTasks] = None,
    ) -> None:
        if request:
            ip = getattr(request.client, "host", None)
            if ip and not await self.check_rate_limit(ip, "password_reset", self.password_reset_rate_limit, window_seconds=3600):
                raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Password reset rate limit exceeded")

        try:
            async with self.get_db_session() as session:
                stmt = select(User).where(User.email == email.lower())
                result = await session.execute(stmt)
                user = result.scalar_one_or_none()

            if user and user.is_active:
                reset_token = await self._create_password_reset_token(user=user)
                if background_tasks:
                    background_tasks.add_task(self._send_password_reset_email, user=user, token=reset_token.token_hash)
                else:
                    try:
                        await self._send_password_reset_email(user=user, token=reset_token.token_hash)
                    except Exception:
                        pass

                self.log_operation("Password reset requested", user_id=user.id, details={"email": email})
        except Exception as e:
            self.logger.error(f"Password reset request failed for {email}: {e}")
            return None

    async def _reset_password_impl(self, *, token: str, new_password: str) -> None:
        try:
            if not self.auth_service.check_password_strength(new_password):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New password not strong enough")

            async with self.get_db_session() as session:
                stmt = select(PasswordResetToken).where(
                    and_(
                        PasswordResetToken.token_hash == token,
                        PasswordResetToken.is_used == False,
                        PasswordResetToken.expires_at > datetime.now(timezone.utc),
                    )
                )
                result = await session.execute(stmt)
                reset_token = result.scalar_one_or_none()
                if not reset_token:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired reset token")

                stmt = select(User).where(User.id == reset_token.user_id)
                result = await session.execute(stmt)
                user = result.scalar_one_or_none()
                if not user or not user.is_active:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid reset token")

                user.password_hash = self.auth_service.hash_password(new_password)
                user.password_changed_at = datetime.now(timezone.utc)
                user.updated_at = datetime.now(timezone.utc)

                stmt = (
                    update(UserSession)
                    .where(
                        and_(
                            UserSession.user_id == user.id,
                            UserSession.is_active == True,
                        )
                    )
                    .values({"is_active": False, "ended_at": datetime.now(timezone.utc)})
                )
                await session.execute(stmt)

                session.add(user)
                reset_token.is_used = True
                reset_token.used_at = datetime.now(timezone.utc)
                session.add(reset_token)
                await session.commit()

            self.log_operation("Password reset completed", user_id=user.id)
        except HTTPException:
            raise
        except Exception as e:
            raise self.handle_database_error(e, "password reset")

    def _is_account_locked(self, *, user: User) -> bool:
        try:
            failed = getattr(user, "failed_login_attempts", 0) or 0
            locked_until = getattr(user, "locked_until", None)
            return self.auth_service.is_account_locked(failed_attempts=failed, locked_until=locked_until)
        except Exception:
            return False

    async def _record_failed_login(self, *, user: User) -> None:
        try:
            async with self.get_db_session() as session:
                stmt = select(User).where(User.id == user.id)
                result = await session.execute(stmt)
                db_user = result.scalar_one_or_none()
                if not db_user:
                    return

                db_user.failed_login_attempts = (getattr(db_user, "failed_login_attempts", 0) or 0) + 1
                if db_user.failed_login_attempts >= getattr(self.auth_service, "max_login_attempts", 5):
                    db_user.locked_until = datetime.now(timezone.utc) + getattr(
                        self.auth_service, "lockout_duration", timedelta(minutes=15)
                    )

                session.add(db_user)
                await session.commit()
        except Exception as e:
            self.logger.error(f"Failed to record failed login for user {getattr(user, 'id', None)}: {e}")
            return