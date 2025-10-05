#!/usr/bin/env python3
"""
Authentication API Routes

Provides endpoints for user authentication, logout, and token management.
Includes JWT blacklist integration for secure token revocation.
"""

from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.database import get_db_session
from src.models.user import User
from src.authentication.auth_service import AuthService
from src.authentication.dependencies import get_current_user, get_admin_user
from src.security.jwt_blacklist import get_jwt_blacklist_service

router = APIRouter(prefix="/auth", tags=["authentication"])
security = HTTPBearer()


@router.post("/logout")
async def logout(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)
) -> Dict[str, str]:
    """
    Logout user by blacklisting their JWT token.
    
    Args:
        request: FastAPI request object
        credentials: JWT token from Authorization header
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        Success message
        
    Raises:
        HTTPException: If logout fails
    """
    try:
        auth_service = AuthService()
        
        # Get client information for audit trail
        client_ip = request.client.host
        user_agent = request.headers.get("user-agent", "")
        
        # Logout user (blacklist token)
        success = await auth_service.logout_user(
            token=credentials.credentials,
            reason="user_logout",
            ip_address=client_ip,
            user_agent=user_agent
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Logout failed"
            )
        
        return {"message": "Successfully logged out"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed"
        )


@router.post("/admin/revoke-user-tokens/{user_id}")
async def revoke_user_tokens(
    user_id: str,
    request: Request,
    admin_user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db_session)
) -> Dict[str, Any]:
    """
    Admin endpoint to revoke all tokens for a specific user.
    
    Args:
        user_id: ID of user whose tokens to revoke
        request: FastAPI request object
        admin_user: Current admin user
        db: Database session
        
    Returns:
        Number of tokens revoked
        
    Raises:
        HTTPException: If revocation fails
    """
    try:
        auth_service = AuthService()
        
        # Revoke all user tokens
        revoked_count = await auth_service.revoke_user_tokens(
            user_id=user_id,
            reason="admin_revocation",
            admin_id=str(admin_user.id)
        )
        
        return {
            "message": f"Revoked {revoked_count} tokens for user {user_id}",
            "revoked_count": revoked_count,
            "user_id": user_id,
            "admin_id": str(admin_user.id)
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token revocation failed"
        )


@router.get("/admin/blacklist-stats")
async def get_blacklist_stats(
    admin_user: User = Depends(get_admin_user)
) -> Dict[str, Any]:
    """
    Admin endpoint to get JWT blacklist statistics.
    
    Args:
        admin_user: Current admin user
        
    Returns:
        Blacklist statistics
    """
    try:
        blacklist_service = get_jwt_blacklist_service()
        stats = await blacklist_service.get_blacklist_stats()
        
        return {
            "stats": stats,
            "timestamp": "2024-01-01T00:00:00Z"  # Current timestamp in production
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve blacklist statistics"
        )


@router.post("/validate-token")
async def validate_token(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, Any]:
    """
    Validate JWT token (check if not expired and not blacklisted).
    
    Args:
        credentials: JWT token from Authorization header
        
    Returns:
        Token validation result
    """
    try:
        auth_service = AuthService()
        
        # Validate token
        is_valid = await auth_service.is_token_valid(credentials.credentials)
        
        if is_valid:
            # Get token payload for additional info
            payload = await auth_service.verify_jwt_token(credentials.credentials)
            return {
                "valid": True,
                "user_id": payload.get("user_id"),
                "session_id": payload.get("session_id"),
                "expires_at": payload.get("exp")
            }
        else:
            return {
                "valid": False,
                "reason": "Token is expired, invalid, or revoked"
            }
            
    except Exception as e:
        return {
            "valid": False,
            "reason": "Token validation failed"
        }