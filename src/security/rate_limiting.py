#!/usr/bin/env python3
"""
LinkShield Backend Rate Limiting

Rate limiting utilities using slowapi for API endpoint protection.
Provides configurable rate limits for different endpoint types.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address
from fastapi import Request
from typing import Callable

# Initialize the global limiter instance
limiter = Limiter(key_func=get_remote_address)

# Rate limit configurations for different endpoint types
RATE_LIMITS = {
    "ai_analysis": "10/minute",
    "url_check": "30/minute", 
    "user_auth": "5/minute",
    "report_generation": "20/minute",
    "general_api": "100/minute"
}


def get_client_identifier(request: Request) -> str:
    """
    Get client identifier for rate limiting.
    
    Args:
        request: FastAPI request object
        
    Returns:
        str: Client identifier (IP address)
    """
    return get_remote_address(request)


def create_rate_limit_key_func(prefix: str = "") -> Callable[[Request], str]:
    """
    Create a custom key function for rate limiting with optional prefix.
    
    Args:
        prefix: Optional prefix for the rate limit key
        
    Returns:
        Callable: Key function for rate limiting
    """
    def key_func(request: Request) -> str:
        client_id = get_remote_address(request)
        return f"{prefix}:{client_id}" if prefix else client_id
    
    return key_func


# Specialized key functions for different endpoint types
ai_analysis_key_func = create_rate_limit_key_func("ai_analysis")
url_check_key_func = create_rate_limit_key_func("url_check")
user_auth_key_func = create_rate_limit_key_func("user_auth")
report_key_func = create_rate_limit_key_func("report")