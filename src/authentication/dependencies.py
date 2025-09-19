#!/usr/bin/env python3
"""
LinkShield Backend Authentication Dependencies

FastAPI dependency functions for authentication and authorization.
Provides user authentication, session validation, and permission checks.
"""

from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.database import get_db
from src.models.user import User
from src.authentication.auth_service import AuthService, AuthenticationError
from src.services.security_service import SecurityService

# Security scheme for JWT tokens
security = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    Get current authenticated user.
    
    Args:
        credentials: JWT token from Authorization header
        db: Database session
        
    Returns:
        User: Authenticated user
        
    Raises:
        HTTPException: If authentication fails
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    try:
        auth_service = AuthService(db)
        security_service = SecurityService(db)
        
        # Verify JWT token
        token_data = security_service.verify_jwt_token(credentials.credentials)
        user_id = token_data.get("user_id")
        session_id = token_data.get("session_id")
        
        if not user_id or not session_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
        # Validate session
        is_valid, session = security_service.validate_session(session_id, user_id)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired"
            )
        
        # Get user
        user = await db.get(User, user_id)
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )
        
        return user
    
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication failed"
        )


async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db)
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