#!/usr/bin/env python3
"""
Pydantic models for URL analysis results with strict typing.
These models work alongside existing SQLAlchemy models to provide type safety.
"""
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field

from src.utils import utc_datetime


# Lazy imports to avoid circular dependencies
def get_url_check_models():
    from .url_check import ThreatLevel, ScanType, ScanResult, URLCheck
    return ThreatLevel, ScanType, ScanResult, URLCheck


class ThreatType(str, Enum):
    MALWARE = "malware"
    PHISHING = "phishing"
    SOCIAL_ENGINEERING = "social_engineering"
    UNWANTED_SOFTWARE = "unwanted_software"
    SPAM = "spam"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class BrokenLinkStatus(str, Enum):
    """Status of a broken link check."""
    WORKING = "working"
    BROKEN = "broken"
    TIMEOUT = "timeout"
    REDIRECT = "redirect"
    UNKNOWN = "unknown"


class BrokenLinkDetail(BaseModel):
    """Details about a specific broken link found during scanning."""
    url: str = Field(..., description="The URL that was checked")
    status_code: Optional[int] = Field(None, description="HTTP status code returned")
    status: BrokenLinkStatus = Field(..., description="Status of the link check")
    error_message: Optional[str] = Field(None, description="Error message if link is broken")
    response_time: Optional[float] = Field(None, description="Response time in seconds")
    redirect_url: Optional[str] = Field(None, description="Final URL after redirects")
    depth_level: int = Field(..., description="Depth level where this link was found")
    
    class Config:
        extra = "forbid"


class BrokenLinkScanResult(BaseModel):
    """Results from a broken link scan."""
    total_links_found: int = Field(0, description="Total number of links discovered")
    total_links_checked: int = Field(0, description="Total number of links actually checked")
    broken_links_count: int = Field(0, description="Number of broken links found")
    working_links_count: int = Field(0, description="Number of working links found")
    scan_depth_used: int = Field(1, description="Actual scan depth used")
    max_links_used: int = Field(100, description="Maximum links limit used")
    broken_links: List[BrokenLinkDetail] = Field(default_factory=list, description="Details of broken links")
    scan_duration: Optional[float] = Field(None, description="Total scan duration in seconds")
    
    class Config:
        extra = "forbid"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "total_links_found": self.total_links_found,
            "total_links_checked": self.total_links_checked,
            "broken_links_count": self.broken_links_count,
            "working_links_count": self.working_links_count,
            "scan_depth_used": self.scan_depth_used,
            "max_links_used": self.max_links_used,
            "broken_links": [link.dict() for link in self.broken_links],
            "scan_duration": self.scan_duration
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BrokenLinkScanResult':
        """Create from dictionary."""
        broken_links = [BrokenLinkDetail(**link) for link in data.get("broken_links", [])]
        return cls(
            total_links_found=data.get("total_links_found", 0),
            total_links_checked=data.get("total_links_checked", 0),
            broken_links_count=data.get("broken_links_count", 0),
            working_links_count=data.get("working_links_count", 0),
            scan_depth_used=data.get("scan_depth_used", 1),
            max_links_used=data.get("max_links_used", 100),
            broken_links=broken_links,
            scan_duration=data.get("scan_duration")
        )


# ------------------------------------------------------------------
# Pydantic equivalents of former @dataclasses
# ------------------------------------------------------------------
class ProviderMetadata(BaseModel):
    positives: Optional[int] = None
    total: Optional[int] = None
    scan_date: Optional[str] = None
    matches_count: Optional[int] = None
    additional_data: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        extra = "forbid"  # mimic dataclass strictness


class ProviderScanResult(BaseModel):
    provider: str
    threat_detected: bool
    threat_types: List[str] = Field(default_factory=list)
    confidence_score: float = 0.0
    raw_response: Optional[Dict[str, Any]] = None
    metadata: Optional[ProviderMetadata] = None
    error: Optional[str] = None

    # --- backward-compat helpers ---
    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ProviderScanResult':
        return cls(**data)


class AnalysisResults(BaseModel):
    normalized_url: str
    domain: str
    threat_level: Optional[str] = None
    confidence_score: float = 0.0
    scan_results: List[ProviderScanResult] = Field(default_factory=list)
    scan_types: List[str] = Field(default_factory=list)
    analysis_timestamp: datetime = Field(default_factory=utc_datetime)
    # Broken link scan results
    broken_link_scan: Optional[BrokenLinkScanResult] = Field(None, description="Broken link scan results")

    # --- backward-compat helpers ---
    def to_dict(self) -> Dict[str, Any]:
        data = self.model_dump()
        # Handle broken link scan serialization
        if self.broken_link_scan:
            data["broken_link_scan"] = self.broken_link_scan.to_dict()
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AnalysisResults':
        # Handle nested Pydantic models explicitly
        broken_link_scan = None
        if data.get("broken_link_scan"):
            broken_link_scan = BrokenLinkScanResult.from_dict(data["broken_link_scan"])
        
        return cls(
            normalized_url=data.get("normalized_url", ""),
            domain=data.get("domain", ""),
            threat_level=data.get("threat_level"),
            confidence_score=data.get("confidence_score", 0.0),
            scan_results=[ProviderScanResult.from_dict(sr) for sr in data.get("scan_results", [])],
            scan_types=data.get("scan_types", []),
            analysis_timestamp=data.get("analysis_timestamp") or utc_datetime(),
            broken_link_scan=broken_link_scan,
        )

    # --- business helpers ---
    def get_provider_result(self, provider_name: str) -> Optional[ProviderScanResult]:
        return next((r for r in self.scan_results if r.provider == provider_name), None)

    def get_threat_types(self) -> List[str]:
        return list({tt for r in self.scan_results for tt in r.threat_types})

    def has_threat_detected(self) -> bool:
        return any(r.threat_detected for r in self.scan_results)
    
    def has_broken_links(self) -> bool:
        """Check if broken links were found."""
        return self.broken_link_scan is not None and self.broken_link_scan.broken_links_count > 0
    
    def get_broken_links_count(self) -> int:
        """Get the number of broken links found."""
        return self.broken_link_scan.broken_links_count if self.broken_link_scan else 0


class ReputationUpdate(BaseModel):
    domain: str
    reputation_score: int
    total_scans: int
    malicious_count: int
    last_scan_date: datetime = Field(default_factory=utc_datetime)

    # --- backward-compat helpers ---
    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ReputationUpdate':
        return cls(**data)


# ------------------------------------------------------------------
# Utility functions (unchanged signatures, but use Pydantic models)
# ------------------------------------------------------------------
def convert_legacy_analysis_results(legacy_data: Dict[str, Any]) -> AnalysisResults:
    """
    Convert legacy dictionary-based analysis results to typed AnalysisResults.
    Handles old nested formats like {"virustotal": {...}}.
    """
    scan_results = []
    raw_scan = legacy_data.get("analysis_results", {})

    if isinstance(raw_scan, dict):
        for provider_name, provider_data in raw_scan.items():
            if isinstance(provider_data, dict):
                provider_data.setdefault("provider", provider_name)
                scan_results.append(ProviderScanResult.from_dict(provider_data))

    direct_list = legacy_data.get("scan_results", [])
    for item in direct_list:
        if isinstance(item, dict):
            scan_results.append(ProviderScanResult.from_dict(item))

    return AnalysisResults(
        normalized_url=legacy_data.get("normalized_url", ""),
        domain=legacy_data.get("domain", ""),
        threat_level=legacy_data.get("threat_level"),
        confidence_score=legacy_data.get("confidence_score", 0.0),
        scan_results=scan_results,
        scan_types=legacy_data.get("scan_types", []),
        analysis_timestamp=legacy_data.get("analysis_timestamp") or utc_datetime()
    )


def create_scan_result_model(analysis_results: AnalysisResults, url_check_id: str) -> List[Dict[str, Any]]:
    """Return plain dicts ready for DB insertion."""
    return [
        {
            "url_check_id": url_check_id,
            "scan_type": result.provider,
            "threat_types": result.threat_types,
            "confidence_score": result.confidence_score,
            "created_at": analysis_results.analysis_timestamp,
        }
        for result in analysis_results.scan_results
    ]


def convert_analysis_results_to_scan_results(analysis_results: AnalysisResults, url_check_id: UUID):
    """Convert AnalysisResults to a list of ScanResult **ORM instances**."""
    _, _, ScanResult, _ = get_url_check_models()
    return [
        ScanResult(
            id=UUID(int=i),
            url_check_id=url_check_id,
            scan_type=result.provider,
            threat_types=result.threat_types,
            confidence_score=result.confidence_score,
            created_at=utc_datetime(),
        )
        for i, result in enumerate(analysis_results.scan_results)
    ]


def convert_analysis_results_to_dict_for_storage(analysis_results: AnalysisResults) -> Dict[str, Any]:
    """Return a dict safe for JSONB storage in PostgreSQL."""
    return {
        "threat_level": analysis_results.threat_level,
        "confidence_score": analysis_results.confidence_score,
        "scan_results": [r.model_dump() for r in analysis_results.scan_results],
        "reputation_data": analysis_results.reputation_data.model_dump() if hasattr(analysis_results, "reputation_data") and analysis_results.reputation_data else None,
    }


def create_analysis_results_from_url_check(url_check) -> Optional[AnalysisResults]:
    """Hydrate AnalysisResults from a URLCheck ORM instance."""
    if not url_check.analysis_results:
        return None
    if isinstance(url_check.analysis_results, dict):
        return convert_legacy_analysis_results(url_check.analysis_results)
    return None