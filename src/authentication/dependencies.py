#!/usr/bin/env python3
"""
LinkShield Backend Authentication Dependencies

FastAPI dependency functions for authentication and authorization.
Provides user authentication, session validation, and permission checks.
"""

from typing import Optional
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.database import get_db_session
from src.models.user import User
from src.authentication.auth_service import AuthService, AuthenticationError
from src.services.security_service import SecurityService
from src.services.session_manager import SessionManager
from src.auth.bot_auth import verify_webhook_signature, verify_api_key

# Security scheme for JWT tokens
security = HTTPBearer(auto_error=False)


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: AsyncSession = Depends(get_db_session)) -> User:
    """
    Get current authenticated user with JWT blacklist validation and session management.
    """
    try:
        if not credentials:
            raise HTTPException(status_code=401, detail="No credentials provided")
        
        # Initialize authentication service
        auth_service = AuthService()
        
        # Verify JWT token (includes blacklist check)
        token_data = await auth_service.verify_jwt_token(credentials.credentials)
        if not token_data:
            raise HTTPException(status_code=401, detail="Invalid or revoked token")
        
        user_id = token_data.get("user_id")
        session_id = token_data.get("session_id")
        
        if not user_id or not session_id:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        
        # Validate session using database operations directly
        is_valid, session = await _validate_user_session_in_db(db, session_id, user_id)
        if not is_valid:
            raise HTTPException(status_code=401, detail="Session expired")
        
        # Get user from database
        user = await _get_user_by_id(db, user_id)
        if not user or not user.is_active:
            raise HTTPException(status_code=401, detail="User not found or inactive")
        
        # Update session activity for concurrent session tracking
    session_manager = SessionManager()
    
    # Extract device fingerprint and IP for enhanced validation
    fingerprint_data = None
    ip_address = request.client.host if hasattr(request, 'client') and request.client else None
    
    # Try to extract device fingerprint from headers
    if hasattr(request, 'headers'):
        user_agent = request.headers.get('user-agent')
        accept_language = request.headers.get('accept-language')
        
        if user_agent:
            fingerprint_data = {
                'user_agent': user_agent,
                'language': accept_language,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    # Update session activity with enhanced validation
    await session_manager.update_session_activity(
        session_id=session_id,
        fingerprint_data=fingerprint_data,
        ip_address=ip_address
    )
        
        return user
    
    except HTTPException:
        raise
    except Exception as e:
        # Log the error in production for debugging
        raise HTTPException(status_code=401, detail="Authentication failed")

async def get_current_user_optional(request: Request) -> Optional[User]:
    """
    Get current user from request without raising exceptions.
    Used by middleware that needs optional user information.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Optional[User]: Authenticated user or None
    """
    try:
        # Extract authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return None
        
        token = auth_header.split(" ")[1]
        
        # Get database session (this is a simplified approach)
        # In practice, you might need to handle this differently
        from src.config.database import get_db_session
        
        # Create a mock credentials object
        class MockCredentials:
            def __init__(self, token: str):
                self.credentials = token
        
        credentials = MockCredentials(token)
        
        # Use existing get_optional_user logic
        db_gen = get_db_session()
        db = await db_gen.__anext__()
        
        try:
            user = await get_optional_user(credentials, db)
            return user
        finally:
            await db_gen.aclose()
    
    except Exception:
        return None

async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db_session)
) -> Optional[User]:
    """
    Get current user if authenticated, otherwise None.
    
    Args:
        credentials: Optional JWT token from Authorization header
        db: Database session
        
    Returns:
        Optional[User]: Authenticated user or None
    """
    if not credentials:
        return None
    
    try:
        return await get_current_user(credentials, db)
    except HTTPException:
        return None


async def get_admin_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Get current user and verify admin permissions.    
    Args:
        current_user: Current authenticated user        
    Returns:
        User: Admin user        
    Raises:
        HTTPException: If user is not an admin
    """
    from src.models.user import UserRole
    
    if current_user.role not in [UserRole.ADMIN, UserRole.SUPER_ADMIN]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    return current_user


async def _get_user_by_id(db: AsyncSession, user_id: str) -> Optional[User]:
    """
    Get user from database by ID.
    
    Args:
        db: Database session
        user_id: User ID to lookup
        
    Returns:
        Optional[User]: User if found, None otherwise
    """
    from sqlalchemy import select
    result = await db.execute(select(User).filter(User.id == user_id))
    return result.scalar_one_or_none()


async def _validate_user_session_in_db(db: AsyncSession, session_id: str, user_id: str) -> tuple[bool, Optional]:
    """
    Validate user session in database.
    
    Args:
        db: Database session
        session_id: Session ID to validate
        user_id: User ID for session
        
    Returns:
        Tuple[bool, Optional]: (is_valid, session_object)
    """
    from sqlalchemy import select
    from src.models.user import UserSession
    from datetime import datetime, timezone, timezone
    
    # Get session from database
    result = await db.execute(
        select(UserSession).filter(
            UserSession.id == session_id,
            UserSession.user_id == user_id,
            UserSession.is_active == True
        )
    )
    session = result.scalar_one_or_none()
    
    if not session:
        return False, None
    
    # Check if session is expired
    if session.expires_at < datetime.now(timezone.utc):
        # Mark session as inactive
        session.is_active = False
        await db.commit()
        return False, None
    
    # Update last activity
    session.last_activity = datetime.now(timezone.utc)
    await db.commit()
    
    return True, session

async def check_admin_permissions(user: User) -> None:
    """
    Check if user has admin permissions.
    """
    if user.role not in [UserRole.ADMIN, UserRole.MODERATOR]:
        raise HTTPException(status_code=403, detail="Admin permissions required")


async def get_super_admin_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Get current user and verify super admin permissions.    
    Args:
        current_user: Current authenticated user        
    Returns:
        User: Super admin user        
    Raises:
        HTTPException: If user is not a super admin
    """
    from src.models.user import UserRole
    
    if current_user.role != UserRole.SUPER_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Super admin access required"
        )
    
    return current_user

async def verify_bot_webhook(request: Request, platform: str):
    """
    Verify bot webhook signature for the specified platform.
    
    Args:
        request: FastAPI request object
        platform: Platform name (twitter, telegram, discord)
        
    Returns:
        Authentication context for the webhook
        
    Raises:
        HTTPException: If webhook verification fails
    """
    return await verify_webhook_signature(request, platform)

async def verify_bot_api_key(api_key: str, platform: str):
    """
    Verify bot API key for the specified platform.
    
    Args:
        api_key: API key to verify
        platform: Platform name (twitter, telegram, discord)
        
    Returns:
        Authentication context for the API key
        
    Raises:
        HTTPException: If API key verification fails
    """
    return await verify_api_key(api_key, platform)