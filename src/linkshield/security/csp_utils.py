#!/usr/bin/env python3
"""
Content Security Policy Utilities

Utilities for working with CSP nonces and security headers in templates and responses.
"""

from typing import Optional
from fastapi import Request


def get_csp_nonce(request: Request) -> Optional[str]:
    """
    Get the CSP nonce from the request state.
    
    Args:
        request: FastAPI request object
        
    Returns:
        CSP nonce string if available, None otherwise
    """
    return getattr(request.state, 'csp_nonce', None)


def create_nonce_script_tag(request: Request, script_content: str) -> str:
    """
    Create a script tag with the appropriate nonce for CSP compliance.
    
    Args:
        request: FastAPI request object
        script_content: JavaScript content to include
        
    Returns:
        HTML script tag with nonce attribute
    """
    nonce = get_csp_nonce(request)
    if nonce:
        return f'<script nonce="{nonce}">{script_content}</script>'
    else:
        # Fallback for cases where nonce is not available
        return f'<script>{script_content}</script>'


def create_nonce_style_tag(request: Request, style_content: str) -> str:
    """
    Create a style tag with the appropriate nonce for CSP compliance.
    
    Args:
        request: FastAPI request object
        style_content: CSS content to include
        
    Returns:
        HTML style tag with nonce attribute
    """
    nonce = get_csp_nonce(request)
    if nonce:
        return f'<style nonce="{nonce}">{style_content}</style>'
    else:
        # Fallback for cases where nonce is not available
        return f'<style>{style_content}</style>'


def get_inline_script_attrs(request: Request) -> str:
    """
    Get the nonce attribute string for inline scripts.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Nonce attribute string for use in HTML templates
    """
    nonce = get_csp_nonce(request)
    if nonce:
        return f'nonce="{nonce}"'
    else:
        return ''


def get_inline_style_attrs(request: Request) -> str:
    """
    Get the nonce attribute string for inline styles.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Nonce attribute string for use in HTML templates
    """
    nonce = get_csp_nonce(request)
    if nonce:
        return f'nonce="{nonce}"'
    else:
        return ''


class CSPNonceContext:
    """
    Context manager for CSP nonce handling in templates.
    
    Usage:
        with CSPNonceContext(request) as csp:
            script_tag = csp.script('console.log("Hello");')
            style_tag = csp.style('body { margin: 0; }')
    """
    
    def __init__(self, request: Request):
        self.request = request
        self.nonce = get_csp_nonce(request)
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass
    
    def script(self, content: str) -> str:
        """Create a nonce-compliant script tag."""
        return create_nonce_script_tag(self.request, content)
    
    def style(self, content: str) -> str:
        """Create a nonce-compliant style tag."""
        return create_nonce_style_tag(self.request, content)
    
    def attrs(self) -> str:
        """Get nonce attributes for manual tag creation."""
        return get_inline_script_attrs(self.request)