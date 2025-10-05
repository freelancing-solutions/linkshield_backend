#!/usr/bin/env python3
"""
CSRF Protection API Routes

Provides endpoints for CSRF token management and validation.
"""

from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from linkshield.security.csrf_protection import get_csrf_service, CSRFProtectionService
from linkshield.authentication.dependencies import get_current_user, get_admin_user, get_optional_user
from linkshield.models.user import User

router = APIRouter(prefix="/api/csrf", tags=["CSRF Protection"])


@router.get("/token")
async def get_csrf_token(
    request: Request,
    response: Response,
    current_user: User = Depends(get_optional_user),
    csrf_service: CSRFProtectionService = Depends(get_csrf_service)
) -> Dict[str, Any]:
    """
    Generate CSRF token for the current session.
    
    Returns:
        Dictionary containing CSRF token information
    """
    try:
        # Get user and session information
        user_id = str(current_user.id) if current_user else None
        session_id = None  # Would extract from JWT in real implementation
        
        # Generate CSRF token
        token_data = await csrf_service.generate_csrf_token(
            user_id=user_id,
            session_id=session_id
        )
        
        # Set CSRF cookie
        csrf_service.set_csrf_cookie(
            response,
            token_data["cookie_token"]
        )
        
        return {
            "csrf_token": token_data["validation_token"],
            "expires_in": csrf_service.config.token_ttl,
            "cookie_name": csrf_service.config.cookie_name,
            "header_name": csrf_service.config.header_name
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="Failed to generate CSRF token"
        )


@router.post("/validate")
async def validate_csrf_token(
    request: Request,
    current_user: User = Depends(get_optional_user),
    csrf_service: CSRFProtectionService = Depends(get_csrf_service)
) -> Dict[str, Any]:
    """
    Validate CSRF token from request.
    
    Returns:
        Dictionary with validation result
    """
    try:
        # Get cookie token
        cookie_token = csrf_service.get_csrf_cookie_from_request(request)
        if not cookie_token:
            return {
                "valid": False,
                "error": "CSRF cookie token missing"
            }
        
        # Get submitted token
        submitted_token = csrf_service.extract_csrf_token_from_request(request)
        if not submitted_token:
            return {
                "valid": False,
                "error": "CSRF token missing from request"
            }
        
        # Get user information
        user_id = str(current_user.id) if current_user else None
        session_id = None  # Would extract from JWT in real implementation
        
        # Validate token (don't consume it for validation endpoint)
        is_valid = await csrf_service.validate_csrf_token(
            cookie_token=cookie_token,
            submitted_token=submitted_token,
            user_id=user_id,
            session_id=session_id,
            consume_token=False  # Don't consume for validation check
        )
        
        return {
            "valid": is_valid,
            "user_bound": user_id is not None
        }
        
    except Exception as e:
        return {
            "valid": False,
            "error": "Validation failed"
        }


@router.delete("/revoke")
async def revoke_csrf_tokens(
    current_user: User = Depends(get_current_user),
    csrf_service: CSRFProtectionService = Depends(get_csrf_service)
) -> Dict[str, Any]:
    """
    Revoke all CSRF tokens for the current user.
    
    Returns:
        Dictionary with revocation result
    """
    try:
        user_id = str(current_user.id)
        
        # Revoke all CSRF tokens for the user
        revoked_count = await csrf_service.revoke_user_csrf_tokens(user_id)
        
        return {
            "success": True,
            "revoked_tokens": revoked_count,
            "message": f"Revoked {revoked_count} CSRF tokens"
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="Failed to revoke CSRF tokens"
        )


@router.get("/stats")
async def get_csrf_stats(
    admin_user: User = Depends(get_admin_user),
    csrf_service: CSRFProtectionService = Depends(get_csrf_service)
) -> Dict[str, Any]:
    """
    Get CSRF protection statistics (admin only).
    
    Returns:
        Dictionary with CSRF statistics
    """
    try:
        stats = await csrf_service.get_csrf_stats()
        
        return {
            "csrf_stats": stats,
            "config": {
                "token_ttl": csrf_service.config.token_ttl,
                "cookie_name": csrf_service.config.cookie_name,
                "header_name": csrf_service.config.header_name,
                "secure_cookie": csrf_service.config.secure_cookie,
                "samesite": csrf_service.config.samesite
            }
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve CSRF statistics"
        )


@router.post("/admin/revoke-user/{user_id}")
async def admin_revoke_user_csrf_tokens(
    user_id: int,
    admin_user: User = Depends(get_admin_user),
    csrf_service: CSRFProtectionService = Depends(get_csrf_service)
) -> Dict[str, Any]:
    """
    Revoke all CSRF tokens for a specific user (admin only).
    
    Args:
        user_id: ID of user whose tokens to revoke
        
    Returns:
        Dictionary with revocation result
    """
    try:
        # Revoke all CSRF tokens for the specified user
        revoked_count = await csrf_service.revoke_user_csrf_tokens(str(user_id))
        
        return {
            "success": True,
            "user_id": user_id,
            "revoked_tokens": revoked_count,
            "message": f"Revoked {revoked_count} CSRF tokens for user {user_id}"
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="Failed to revoke user CSRF tokens"
        )


@router.post("/admin/cleanup")
async def cleanup_expired_csrf_tokens(
    admin_user: User = Depends(get_admin_user),
    csrf_service: CSRFProtectionService = Depends(get_csrf_service)
) -> Dict[str, Any]:
    """
    Clean up expired CSRF tokens (admin only).
    
    Returns:
        Dictionary with cleanup result
    """
    try:
        cleaned_count = await csrf_service.cleanup_expired_tokens()
        
        return {
            "success": True,
            "cleaned_tokens": cleaned_count,
            "message": f"Cleaned up {cleaned_count} expired CSRF tokens"
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="Failed to clean up expired CSRF tokens"
        )