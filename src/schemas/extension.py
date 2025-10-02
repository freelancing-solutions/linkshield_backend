#!/usr/bin/env python3
"""
LinkShield Backend - Extension Schemas

Pydantic models for browser extension endpoints (quick URL checks, bulk checks,
and real-time content analysis). These schemas provide a light-weight response
shape tailored for the browser extension's needs.
"""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, HttpUrl

from src.models.url_check import ThreatLevel


class QuickURLCheckRequest(BaseModel):
    """Request model for quick URL safety check from the browser extension."""
    url: HttpUrl = Field(..., description="URL to check")
    referrer: Optional[str] = Field(None, description="Referrer if applicable")
    headers: Optional[Dict[str, str]] = Field(None, description="Optional HTTP headers context")
    mode: str = Field("real_time", description="Analysis mode: real_time or background")


class QuickURLCheckResponse(BaseModel):
    """Simplified response model tailored for the extension UI."""
    normalized_url: str
    domain: str
    threat_level: ThreatLevel
    confidence_score: float = Field(0.0, ge=0.0, le=100.0)
    is_safe: bool
    reasons: List[str] = Field(default_factory=list)
    scan_types: List[str] = Field(default_factory=list)


class BulkURLCheckItem(BaseModel):
    """Represents an individual URL check item in a bulk request."""
    url: HttpUrl
    referrer: Optional[str] = None


class BulkURLCheckRequest(BaseModel):
    """Request to perform multiple quick URL checks at once."""
    items: List[BulkURLCheckItem] = Field(..., min_items=1, description="List of URLs to check")


class BulkURLCheckResult(BaseModel):
    """Result item for a bulk URL check."""
    url: str
    result: QuickURLCheckResponse


class BulkURLCheckResponse(BaseModel):
    """Aggregated response for bulk URL checks."""
    total: int
    results: List[BulkURLCheckResult] = Field(default_factory=list)


class ContentAnalyzeRequest(BaseModel):
    """Minimal content analysis request for real-time assessment from extension."""
    request_id: str = Field(..., description="Client-generated request identifier")
    platform: str = Field(..., description="Platform identifier (e.g., twitter, facebook)")
    content_type: str = Field(..., description="Type of content (e.g., text, url, media)")
    content: str = Field(..., description="Raw content for analysis")
    url: Optional[str] = Field(None, description="Associated URL if present")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional context data")


class ContentAnalyzeResponse(BaseModel):
    """Simplified content analysis response for the extension UI."""
    request_id: str
    risk_level: str
    confidence_score: float
    risk_factors: List[str] = Field(default_factory=list)
    processing_time_ms: int = 0
    success: bool = True
    error_message: Optional[str] = None