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


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: AsyncSession = Depends(get_db_session)) -> User:
    """
    Get current authenticated user.
    """
    try:
        auth_service = AuthService(db_session=db)
        security_service = SecurityService(dbdb)
        
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
    
    except Exception as e:
        raise HTTPException(status_code=401, detail="Authentication failed")

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