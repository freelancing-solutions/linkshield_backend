#!/usr/bin/env python3
"""
Security API Routes

Provides endpoints for security-related functionality including CSP violation reporting.
"""

import logging
from typing import Dict, Any, Optional
from datetime import datetime
from fastapi import APIRouter, Request, HTTPException, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from src.authentication.dependencies import get_admin_user
from src.models.user import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/security", tags=["Security"])


class CSPViolationReport(BaseModel):
    """CSP violation report structure as sent by browsers."""
    
    document_uri: str = Field(..., alias="document-uri")
    referrer: Optional[str] = None
    violated_directive: str = Field(..., alias="violated-directive")
    effective_directive: str = Field(..., alias="effective-directive")
    original_policy: str = Field(..., alias="original-policy")
    disposition: str = "enforce"  # "enforce" or "report"
    blocked_uri: Optional[str] = Field(None, alias="blocked-uri")
    line_number: Optional[int] = Field(None, alias="line-number")
    column_number: Optional[int] = Field(None, alias="column-number")
    source_file: Optional[str] = Field(None, alias="source-file")
    status_code: Optional[int] = Field(None, alias="status-code")
    script_sample: Optional[str] = Field(None, alias="script-sample")


class CSPViolationWrapper(BaseModel):
    """Wrapper for CSP violation report as sent by browsers."""
    
    csp_report: CSPViolationReport = Field(..., alias="csp-report")


@router.post("/csp-report")
async def csp_violation_report(request: Request):
    """
    Receive and log CSP violation reports from browsers.
    
    This endpoint receives CSP violation reports sent by browsers when
    Content Security Policy violations occur. Reports are logged for
    security monitoring and policy refinement.
    
    Args:
        request: FastAPI request containing the violation report
        
    Returns:
        Empty response with 204 status code
    """
    try:
        # Get client IP for logging
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "unknown")
        
        # Parse the violation report
        report_data = await request.json()
        
        # Validate the report structure
        try:
            violation_wrapper = CSPViolationWrapper(**report_data)
            violation = violation_wrapper.csp_report
        except Exception as e:
            logger.warning(f"Invalid CSP report structure from {client_ip}: {e}")
            # Still log the raw data for analysis
            violation = None
        
        # Log the violation with context
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "client_ip": client_ip,
            "user_agent": user_agent,
            "raw_report": report_data
        }
        
        if violation:
            # Structured logging for valid reports
            logger.warning(
                f"CSP Violation - Document: {violation.document_uri}, "
                f"Directive: {violation.violated_directive}, "
                f"Blocked: {violation.blocked_uri or 'inline'}, "
                f"Client: {client_ip}"
            )
            
            # Additional context logging
            logger.info(f"CSP Violation Details: {log_data}")
            
            # Check for common violation patterns that might indicate attacks
            if violation.violated_directive in ["script-src", "object-src"]:
                if violation.blocked_uri and any(
                    suspicious in violation.blocked_uri.lower() 
                    for suspicious in ["javascript:", "data:", "blob:", "eval"]
                ):
                    logger.error(
                        f"Suspicious CSP violation detected - "
                        f"Potential XSS attempt from {client_ip}: {violation.blocked_uri}"
                    )
            
        else:
            # Log malformed reports
            logger.warning(f"Malformed CSP report from {client_ip}: {log_data}")
        
        # Return 204 No Content as per CSP specification
        return JSONResponse(content=None, status_code=204)
        
    except Exception as e:
        logger.error(f"Error processing CSP violation report: {e}")
        # Still return 204 to not break browser reporting
        return JSONResponse(content=None, status_code=204)


@router.get("/csp-violations/stats")
async def get_csp_violation_stats(
    admin_user: User = Depends(get_admin_user)
) -> Dict[str, Any]:
    """
    Get CSP violation statistics (admin only).
    
    This endpoint provides administrators with statistics about CSP violations
    to help monitor security and refine CSP policies.
    
    Args:
        admin_user: Authenticated admin user
        
    Returns:
        Dictionary containing violation statistics
    """
    # Note: This is a placeholder implementation
    # In a production system, you would query a database or log aggregation system
    # to provide real violation statistics
    
    return {
        "message": "CSP violation statistics endpoint",
        "note": "This endpoint would provide real violation statistics in production",
        "implementation_needed": [
            "Database storage for violation reports",
            "Aggregation queries for statistics",
            "Time-based filtering and grouping",
            "Violation pattern analysis"
        ],
        "suggested_metrics": [
            "Total violations by time period",
            "Most common violated directives",
            "Top blocked URIs",
            "Client IP patterns",
            "User agent analysis"
        ]
    }


@router.post("/csp-violations/analyze")
async def analyze_csp_violations(
    admin_user: User = Depends(get_admin_user)
) -> Dict[str, Any]:
    """
    Analyze CSP violations for security threats (admin only).
    
    This endpoint analyzes stored CSP violations to identify potential
    security threats and attack patterns.
    
    Args:
        admin_user: Authenticated admin user
        
    Returns:
        Dictionary containing security analysis results
    """
    # Note: This is a placeholder implementation
    # In a production system, you would implement threat analysis logic
    
    return {
        "message": "CSP violation analysis endpoint",
        "note": "This endpoint would provide real threat analysis in production",
        "implementation_needed": [
            "Threat pattern detection algorithms",
            "IP reputation checking",
            "Anomaly detection for violation patterns",
            "Integration with security monitoring systems"
        ],
        "analysis_types": [
            "XSS attempt detection",
            "Malicious script injection patterns",
            "Suspicious client behavior",
            "Policy bypass attempts"
        ]
    }