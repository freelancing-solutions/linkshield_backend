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

    # --- backward-compat helpers ---
    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AnalysisResults':
        # Handle nested Pydantic models explicitly
        return cls(
            normalized_url=data.get("normalized_url", ""),
            domain=data.get("domain", ""),
            threat_level=data.get("threat_level"),
            confidence_score=data.get("confidence_score", 0.0),
            scan_results=[ProviderScanResult.from_dict(sr) for sr in data.get("scan_results", [])],
            scan_types=data.get("scan_types", []),
            analysis_timestamp=data.get("analysis_timestamp") or utc_datetime(),
        )

    # --- business helpers ---
    def get_provider_result(self, provider_name: str) -> Optional[ProviderScanResult]:
        return next((r for r in self.scan_results if r.provider == provider_name), None)

    def get_threat_types(self) -> List[str]:
        return list({tt for r in self.scan_results for tt in r.threat_types})

    def has_threat_detected(self) -> bool:
        return any(r.threat_detected for r in self.scan_results)


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