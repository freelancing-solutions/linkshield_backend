#!/usr/bin/env python3
"""
LinkShield Backend - Extension Routes

FastAPI routes for browser extension integration:
- Quick URL safety check
- Bulk URL safety check
- Real-time content analysis
"""
import asyncio
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status, Request

from src.schemas.extension import (
    QuickURLCheckRequest,
    QuickURLCheckResponse,
    BulkURLCheckRequest,
    BulkURLCheckResult,
    BulkURLCheckResponse,
    ContentAnalyzeRequest,
    ContentAnalyzeResponse,
)
from src.models.url_check import ThreatLevel
from src.services.url_analysis_service import (
    URLAnalysisService,
    InvalidURLError,
    ScanTimeoutError,
)
from src.services.depends import (
    get_url_analysis_service,
    get_extension_data_processor,
)
from src.social_protection.services.extension_data_processor import ExtensionDataProcessor
from src.authentication.dependencies import get_current_user, get_optional_user
from src.services.advanced_rate_limiter import rate_limit
from src.models.user import User


router = APIRouter(
    prefix="/api/v1/extension",
    tags=["Extension"],
    responses={
        400: {"description": "Invalid request"},
        429: {"description": "Rate limit exceeded"},
        500: {"description": "Internal server error"},
    },
)


@router.post(
    "/url/check",
    response_model=QuickURLCheckResponse,
    status_code=status.HTTP_200_OK,
)
async def quick_url_check(
    request: QuickURLCheckRequest,
    http_request: Request,
    current_user: Optional[User] = Depends(get_optional_user),
    url_analysis_service: URLAnalysisService = Depends(get_url_analysis_service),
):
    """Perform a quick URL safety check optimized for the extension UI."""
    try:
        analysis = await url_analysis_service.quick_security_analysis_by_url(str(request.url))

        # Map to simplified response
        threat_level = ThreatLevel(analysis.threat_level or ThreatLevel.SAFE.value)
        is_safe = (analysis.threat_level == ThreatLevel.SAFE.value) and not analysis.has_threat_detected()

        return QuickURLCheckResponse(
            normalized_url=analysis.normalized_url,
            domain=analysis.domain,
            threat_level=threat_level,
            confidence_score=analysis.confidence_score,
            is_safe=is_safe,
            reasons=analysis.get_threat_types(),
            scan_types=analysis.scan_types,
        )
    except InvalidURLError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except ScanTimeoutError as e:
        raise HTTPException(status_code=status.HTTP_408_REQUEST_TIMEOUT, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"URL check failed: {str(e)}")


@router.post(
    "/url/bulk-check",
    response_model=BulkURLCheckResponse,
    status_code=status.HTTP_200_OK,
)
async def bulk_url_check(
    request: BulkURLCheckRequest,
    http_request: Request,
    current_user: User = Depends(get_current_user),
    url_analysis_service: URLAnalysisService = Depends(get_url_analysis_service),
):
    """Perform quick URL checks for multiple URLs concurrently."""

    async def _check_one(item) -> BulkURLCheckResult:
        analysis = await url_analysis_service.quick_security_analysis_by_url(str(item.url))
        threat_level = ThreatLevel(analysis.threat_level or ThreatLevel.SAFE.value)
        is_safe = (analysis.threat_level == ThreatLevel.SAFE.value) and not analysis.has_threat_detected()
        resp = QuickURLCheckResponse(
            normalized_url=analysis.normalized_url,
            domain=analysis.domain,
            threat_level=threat_level,
            confidence_score=analysis.confidence_score,
            is_safe=is_safe,
            reasons=analysis.get_threat_types(),
            scan_types=analysis.scan_types,
        )
        return BulkURLCheckResult(url=str(item.url), result=resp)

    try:
        tasks: List[asyncio.Task] = [asyncio.create_task(_check_one(item)) for item in request.items]
        results = await asyncio.gather(*tasks, return_exceptions=False)
        return BulkURLCheckResponse(total=len(results), results=results)
    except InvalidURLError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except ScanTimeoutError as e:
        raise HTTPException(status_code=status.HTTP_408_REQUEST_TIMEOUT, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Bulk URL check failed: {str(e)}")


@router.post(
    "/content/analyze",
    response_model=ContentAnalyzeResponse,
    status_code=status.HTTP_200_OK,
)
async def content_analyze(
    request: ContentAnalyzeRequest,
    http_request: Request,
    current_user: User = Depends(get_current_user),
    processor: ExtensionDataProcessor = Depends(get_extension_data_processor),
):
    """Perform real-time content analysis for the browser extension."""
    try:
        response = await processor.process_extension_request(request.model_dump())
        assessment = response.assessment

        # Map to simplified response model
        return ContentAnalyzeResponse(
            request_id=request.request_id,
            risk_level=(assessment.risk_level if assessment else "low"),
            confidence_score=(assessment.confidence if assessment else 0.0),
            risk_factors=(assessment.risk_factors if assessment else []),
            processing_time_ms=(assessment.processing_time_ms if assessment else response.processing_time_ms),
            success=response.status == "success",
            error_message=response.error_message,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Content analysis failed: {str(e)}")

# Apply rate limiting decorators after function definitions to ensure FastAPI recognizes wrappers properly
quick_url_check = rate_limit("extension_url_check")(quick_url_check)
bulk_url_check = rate_limit("extension_bulk_url_check")(bulk_url_check)
content_analyze = rate_limit("extension_content_analyze")(content_analyze)