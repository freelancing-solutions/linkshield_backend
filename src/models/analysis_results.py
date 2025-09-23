"""
Data classes for URL analysis results with strict typing.
These classes work alongside existing models to provide type safety.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union
from datetime import datetime
from enum import Enum
import uuid

# Import existing models for conversion - use local imports to avoid circular dependencies
def get_url_check_models():
    """Lazy import to avoid circular dependencies."""
    from .url_check import ThreatLevel, ScanType, ScanResult, URLCheck
    return ThreatLevel, ScanType, ScanResult, URLCheck


class ThreatType(str, Enum):
    """Standardized threat types across providers."""
    MALWARE = "malware"
    PHISHING = "phishing"
    SOCIAL_ENGINEERING = "social_engineering"
    UNWANTED_SOFTWARE = "unwanted_software"
    SPAM = "spam"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


@dataclass
class ProviderMetadata:
    """Metadata for provider scan results."""
    positives: Optional[int] = None
    total: Optional[int] = None
    scan_date: Optional[str] = None
    matches_count: Optional[int] = None
    additional_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProviderScanResult:
    """Individual scan result from a specific provider."""
    provider: str
    threat_detected: bool
    threat_types: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    raw_response: Optional[Dict[str, Any]] = None
    metadata: Optional[ProviderMetadata] = None
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for backward compatibility."""
        return {
            "provider": self.provider,
            "threat_detected": self.threat_detected,
            "threat_types": self.threat_types,
            "confidence_score": self.confidence_score,
            "raw_response": self.raw_response,
            "metadata": self.metadata.__dict__ if self.metadata else None,
            "error": self.error
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProviderScanResult":
        """Create from dictionary for backward compatibility."""
        metadata = None
        if data.get("metadata"):
            metadata = ProviderMetadata(**data["metadata"])
        
        return cls(
            provider=data.get("provider", ""),
            threat_detected=data.get("threat_detected", False),
            threat_types=data.get("threat_types", []),
            confidence_score=data.get("confidence_score", 0.0),
            raw_response=data.get("raw_response"),
            metadata=metadata,
            error=data.get("error")
        )


@dataclass
class AnalysisResults:
    """Aggregated analysis results from all providers."""
    normalized_url: str
    domain: str
    threat_level: Optional[str] = None
    confidence_score: float = 0.0
    scan_results: List[ProviderScanResult] = field(default_factory=list)
    scan_types: List[str] = field(default_factory=list)
    analysis_timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for backward compatibility."""
        return {
            "normalized_url": self.normalized_url,
            "domain": self.domain,
            "threat_level": self.threat_level,
            "confidence_score": self.confidence_score,
            "scan_results": [result.to_dict() for result in self.scan_results],
            "scan_types": self.scan_types,
            "analysis_timestamp": self.analysis_timestamp.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AnalysisResults":
        """Create from dictionary for backward compatibility."""
        scan_results = []
        for scan_data in data.get("scan_results", []):
            if isinstance(scan_data, dict):
                # Handle both old format (nested dict) and new format
                if "provider" in scan_data:
                    scan_results.append(ProviderScanResult.from_dict(scan_data))
                else:
                    # Handle old nested format like {"virustotal": {...}}
                    for provider_name, provider_data in scan_data.items():
                        if isinstance(provider_data, dict):
                            provider_data["provider"] = provider_name
                            scan_results.append(ProviderScanResult.from_dict(provider_data))
        
        return cls(
            normalized_url=data.get("normalized_url", ""),
            domain=data.get("domain", ""),
            threat_level=data.get("threat_level"),
            confidence_score=data.get("confidence_score", 0.0),
            scan_results=scan_results,
            scan_types=data.get("scan_types", []),
            analysis_timestamp=datetime.fromisoformat(data["analysis_timestamp"]) if data.get("analysis_timestamp") else datetime.utcnow()
        )
    
    def get_provider_result(self, provider_name: str) -> Optional[ProviderScanResult]:
        """Get result for a specific provider."""
        for result in self.scan_results:
            if result.provider == provider_name:
                return result
        return None
    
    def get_threat_types(self) -> List[str]:
        """Get all unique threat types detected."""
        threat_types = set()
        for result in self.scan_results:
            threat_types.update(result.threat_types)
        return list(threat_types)
    
    def has_threat_detected(self) -> bool:
        """Check if any provider detected a threat."""
        return any(result.threat_detected for result in self.scan_results)


@dataclass
class ReputationUpdate:
    """Data class for domain reputation updates."""
    domain: str
    reputation_score: int
    total_scans: int
    malicious_count: int
    last_scan_date: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for backward compatibility."""
        return {
            "domain": self.domain,
            "reputation_score": self.reputation_score,
            "total_scans": self.total_scans,
            "malicious_count": self.malicious_count,
            "last_scan_date": self.last_scan_date.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReputationUpdate":
        """Create from dictionary for backward compatibility."""
        return cls(
            domain=data.get("domain", ""),
            reputation_score=data.get("reputation_score", 50),
            total_scans=data.get("total_scans", 0),
            malicious_count=data.get("malicious_count", 0),
            last_scan_date=datetime.fromisoformat(data["last_scan_date"]) if data.get("last_scan_date") else datetime.utcnow()
        )


# Utility functions for conversion between old and new formats
def convert_legacy_analysis_results(legacy_data: Dict[str, Any]) -> AnalysisResults:
    """
    Convert legacy dictionary-based analysis results to typed AnalysisResults.
    This handles the old format where scan results were nested dictionaries.
    """
    # Extract basic information
    normalized_url = legacy_data.get("normalized_url", "")
    domain = legacy_data.get("domain", "")
    threat_level = legacy_data.get("threat_level")
    confidence_score = legacy_data.get("confidence_score", 0.0)
    scan_types = legacy_data.get("scan_types", [])
    
    # Convert scan results from old format to new format
    scan_results = []
    analysis_results = legacy_data.get("analysis_results", {})
    
    # Handle different possible formats of scan results
    if isinstance(analysis_results, dict):
        for provider_name, provider_data in analysis_results.items():
            if isinstance(provider_data, dict) and "provider" in provider_data:
                # New format already
                scan_results.append(ProviderScanResult.from_dict(provider_data))
            elif isinstance(provider_data, dict):
                # Old nested format
                provider_data["provider"] = provider_name
                scan_results.append(ProviderScanResult.from_dict(provider_data))
    
    # Also check for scan_results key directly
    direct_scan_results = legacy_data.get("scan_results", [])
    for scan_data in direct_scan_results:
        if isinstance(scan_data, dict):
            scan_results.append(ProviderScanResult.from_dict(scan_data))
    
    return AnalysisResults(
        normalized_url=normalized_url,
        domain=domain,
        threat_level=threat_level,
        confidence_score=confidence_score,
        scan_results=scan_results,
        scan_types=scan_types
    )


def create_scan_result_model(analysis_results: AnalysisResults, url_check_id: str) -> List[Dict[str, Any]]:
    """
    Create ScanResult model instances from AnalysisResults.
    This is used to populate the database with scan results.
    """
    scan_result_data = []
    
    for provider_result in analysis_results.scan_results:
        data = {
            "url_check_id": url_check_id,
            "scan_type": provider_result.provider,  # Map provider to scan_type
            "threat_types": provider_result.threat_types,
            "confidence_score": provider_result.confidence_score,
            "created_at": analysis_results.analysis_timestamp
        }
        scan_result_data.append(data)
    
    return scan_result_data


def convert_analysis_results_to_scan_results(analysis_results: AnalysisResults, url_check_id: uuid.UUID):
    """Convert AnalysisResults to a list of ScanResult database models.
    
    Args:
        analysis_results: AnalysisResults object to convert
        url_check_id: ID of the URLCheck to associate with scan results
        
    Returns:
        List of ScanResult database models
    """
    _, _, ScanResult, _ = get_url_check_models()
    
    scan_results = []
    
    for provider_result in analysis_results.scan_results:
        scan_result = ScanResult(
            id=uuid.uuid4(),
            url_check_id=url_check_id,
            scan_type=provider_result.provider,
            threat_types=provider_result.threat_types,
            confidence_score=provider_result.confidence_score,
            created_at=datetime.utcnow()
        )
        scan_results.append(scan_result)
    
    return scan_results


def convert_analysis_results_to_dict_for_storage(analysis_results: AnalysisResults) -> Dict[str, Any]:
    """Convert AnalysisResults to a dictionary suitable for database storage.
    
    Args:
        analysis_results: AnalysisResults object to convert
        
    Returns:
        Dictionary containing analysis results data for storage
    """
    return {
        'threat_level': analysis_results.threat_level.value if analysis_results.threat_level else None,
        'confidence_score': analysis_results.confidence_score,
        'scan_results': [
            {
                'scan_type': result.provider,
                'provider': result.provider,
                'threat_detected': result.threat_detected,
                'threat_types': result.threat_types,
                'confidence_score': result.confidence_score,
                'metadata': result.metadata.to_dict() if result.metadata else None
            }
            for result in analysis_results.scan_results
        ],
        'reputation_data': analysis_results.reputation_data.to_dict() if hasattr(analysis_results, 'reputation_data') and analysis_results.reputation_data else None
    }


def create_analysis_results_from_url_check(url_check) -> Optional[AnalysisResults]:
    """Create AnalysisResults from a URLCheck database model.
    
    Args:
        url_check: URLCheck database model to convert
        
    Returns:
        AnalysisResults object or None if analysis_results is empty
    """
    if not url_check.analysis_results:
        return None
    
    # If analysis_results is already a dict, convert it to AnalysisResults
    if isinstance(url_check.analysis_results, dict):
        return convert_legacy_analysis_results(url_check.analysis_results)
    
    return None