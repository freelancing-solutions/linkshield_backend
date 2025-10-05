#!/usr/bin/env python3
"""
JWT Key Management API Routes

Provides administrative endpoints for JWT key rotation, monitoring, and management.
These endpoints are restricted to admin users for security purposes.
"""

from datetime import datetime, timezone
from typing import Dict, Any

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from linkshield.security.jwt_key_manager import get_jwt_key_manager, JWTKeyManagerError
from linkshield.authentication.auth_service import AuthService
from linkshield.services.security_service import SecurityService


router = APIRouter(prefix="/api/v1/jwt", tags=["JWT Management"])
security = HTTPBearer()


async def verify_admin_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """
    Verify that the request is from an authenticated admin user.
    
    Args:
        credentials: JWT token from Authorization header
        
    Returns:
        Token payload if valid admin token
        
    Raises:
        HTTPException: If token is invalid or user is not admin
    """
    try:
        security_service = SecurityService()
        payload = security_service.verify_jwt_token(credentials.credentials)
        
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token"
            )
        
        # Check if user has admin role (this would typically check against user database)
        # For now, we'll check if the token has admin claims
        user_role = payload.get("role", "user")
        if user_role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required"
            )
        
        return payload
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed"
        )


@router.get("/status")
async def get_jwt_key_status(
    admin_payload: Dict[str, Any] = Depends(verify_admin_token)
) -> Dict[str, Any]:
    """
    Get current JWT key management status and statistics.
    
    Returns:
        Key management statistics and status information
    """
    try:
        key_manager = get_jwt_key_manager()
        statistics = await key_manager.get_key_statistics()
        
        return {
            "success": True,
            "data": statistics,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except JWTKeyManagerError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Key management error: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get key status"
        )


@router.post("/rotate")
async def rotate_jwt_keys(
    admin_payload: Dict[str, Any] = Depends(verify_admin_token)
) -> Dict[str, Any]:
    """
    Manually trigger JWT key rotation.
    
    Returns:
        Rotation result information
    """
    try:
        key_manager = get_jwt_key_manager()
        new_key, deprecated_keys = await key_manager.rotate_keys()
        
        return {
            "success": True,
            "data": {
                "new_key_id": new_key.key_id,
                "new_key_created": new_key.created_at.isoformat(),
                "new_key_expires": new_key.expires_at.isoformat(),
                "deprecated_keys": deprecated_keys,
                "rotation_time": datetime.now(timezone.utc).isoformat()
            },
            "message": f"Key rotation completed. New key: {new_key.key_id}"
        }
        
    except JWTKeyManagerError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Key rotation failed: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Key rotation failed"
        )


@router.post("/cleanup")
async def cleanup_expired_keys(
    admin_payload: Dict[str, Any] = Depends(verify_admin_token)
) -> Dict[str, Any]:
    """
    Clean up expired JWT keys from storage.
    
    Returns:
        Cleanup result information
    """
    try:
        key_manager = get_jwt_key_manager()
        cleaned_count = await key_manager.cleanup_expired_keys()
        
        return {
            "success": True,
            "data": {
                "cleaned_keys": cleaned_count,
                "cleanup_time": datetime.now(timezone.utc).isoformat()
            },
            "message": f"Cleaned up {cleaned_count} expired keys"
        }
        
    except JWTKeyManagerError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Key cleanup failed: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Key cleanup failed"
        )


@router.get("/keys")
async def list_jwt_keys(
    admin_payload: Dict[str, Any] = Depends(verify_admin_token)
) -> Dict[str, Any]:
    """
    List all JWT keys with their status and metadata.
    
    Returns:
        List of JWT keys with metadata (excluding key values for security)
    """
    try:
        key_manager = get_jwt_key_manager()
        
        # Get active and verification keys
        active_keys = await key_manager.get_active_keys()
        verification_keys = await key_manager.get_verification_keys()
        
        # Format key information (exclude actual key values for security)
        active_key_info = [
            {
                "key_id": key.key_id,
                "status": key.status.value,
                "created_at": key.created_at.isoformat(),
                "expires_at": key.expires_at.isoformat(),
                "algorithm": key.algorithm,
                "usage_count": key.usage_count,
                "last_used": key.last_used.isoformat() if key.last_used else None
            }
            for key in active_keys
        ]
        
        verification_key_info = [
            {
                "key_id": key.key_id,
                "status": key.status.value,
                "created_at": key.created_at.isoformat(),
                "expires_at": key.expires_at.isoformat(),
                "algorithm": key.algorithm,
                "usage_count": key.usage_count,
                "last_used": key.last_used.isoformat() if key.last_used else None
            }
            for key in verification_keys
        ]
        
        return {
            "success": True,
            "data": {
                "active_keys": active_key_info,
                "verification_keys": verification_key_info,
                "total_active": len(active_keys),
                "total_verification": len(verification_keys)
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except JWTKeyManagerError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list keys: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list keys"
        )


@router.post("/keys/{key_id}/deprecate")
async def deprecate_jwt_key(
    key_id: str,
    admin_payload: Dict[str, Any] = Depends(verify_admin_token)
) -> Dict[str, Any]:
    """
    Deprecate a specific JWT key.
    
    Args:
        key_id: Key identifier to deprecate
        
    Returns:
        Deprecation result
    """
    try:
        key_manager = get_jwt_key_manager()
        success = await key_manager.deprecate_key(key_id)
        
        if success:
            return {
                "success": True,
                "data": {
                    "key_id": key_id,
                    "deprecated_at": datetime.now(timezone.utc).isoformat()
                },
                "message": f"Key {key_id} has been deprecated"
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Key {key_id} not found"
            )
        
    except JWTKeyManagerError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to deprecate key: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to deprecate key"
        )


@router.delete("/keys/{key_id}")
async def revoke_jwt_key(
    key_id: str,
    admin_payload: Dict[str, Any] = Depends(verify_admin_token)
) -> Dict[str, Any]:
    """
    Revoke (permanently delete) a specific JWT key.
    
    Args:
        key_id: Key identifier to revoke
        
    Returns:
        Revocation result
    """
    try:
        key_manager = get_jwt_key_manager()
        success = await key_manager.revoke_key(key_id)
        
        if success:
            return {
                "success": True,
                "data": {
                    "key_id": key_id,
                    "revoked_at": datetime.now(timezone.utc).isoformat()
                },
                "message": f"Key {key_id} has been revoked"
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Key {key_id} not found"
            )
        
    except JWTKeyManagerError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to revoke key: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke key"
        )


@router.get("/health")
async def jwt_key_health_check(
    admin_payload: Dict[str, Any] = Depends(verify_admin_token)
) -> Dict[str, Any]:
    """
    Health check for JWT key management system.
    
    Returns:
        Health status and recommendations
    """
    try:
        key_manager = get_jwt_key_manager()
        
        # Check if rotation is needed
        rotation_needed = await key_manager.check_rotation_needed()
        
        # Get current statistics
        stats = await key_manager.get_key_statistics()
        
        # Determine health status
        health_status = "healthy"
        recommendations = []
        
        if rotation_needed:
            health_status = "warning"
            recommendations.append("Key rotation is recommended")
        
        if stats.get("active_keys_count", 0) == 0:
            health_status = "critical"
            recommendations.append("No active keys found - system may be using fallback")
        
        if stats.get("verification_keys_count", 0) > 10:
            health_status = "warning"
            recommendations.append("Too many verification keys - consider cleanup")
        
        return {
            "success": True,
            "data": {
                "health_status": health_status,
                "rotation_needed": rotation_needed,
                "recommendations": recommendations,
                "statistics": stats
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except JWTKeyManagerError as e:
        return {
            "success": False,
            "data": {
                "health_status": "critical",
                "error": str(e),
                "recommendations": ["Check Redis connection and key manager configuration"]
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        return {
            "success": False,
            "data": {
                "health_status": "critical",
                "error": "Health check failed",
                "recommendations": ["Check system logs and key manager status"]
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        }