#!/usr/bin/env python3
"""
LinkShield Backend AI Analysis Routes

API endpoints for AI-powered content analysis including quality scoring,
topic classification, sentiment analysis, and intelligent insights.
"""

import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional

from fastapi import APIRouter, Depends, status, Request, Query, Path
from pydantic import BaseModel, field_validator, Field

from src.authentication.dependencies import get_current_user, get_optional_user
from src.security.rate_limiting import limiter, ai_analysis_key_func

from src.controllers.depends import get_ai_analysis_controller
from src.controllers import AIAnalysisController
from src.models.ai_analysis import AnalysisType
from src.models.user import User

# Initialize router
router = APIRouter(prefix="/ai-analysis", tags=["AI Analysis"])



# Request/Response Models
class AIAnalysisRequest(BaseModel):
    """
    Request model for AI content analysis.
    """
    url: str = Field(..., description="URL to analyze")
    content: str = Field(..., min_length=10, max_length=50000, description="Content to analyze")
    analysis_types: Optional[List[AnalysisType]] = Field(
        default=None,
        description="Specific analysis types to perform"
    )
    
    @field_validator('url')
    def validate_url(cls, v):
        if not v.startswith(('http://', 'https://')):
            raise ValueError('URL must start with http:// or https://')
        return v


class AIAnalysisResponse(BaseModel):
    """
    Response model for AI analysis results.
    """
    id: str
    url: str
    domain: str
    content_summary: Optional[str]
    quality_metrics: Optional[Dict[str, Any]]
    topic_categories: Optional[Dict[str, Any]]
    sentiment_analysis: Optional[Dict[str, Any]]
    seo_metrics: Optional[Dict[str, Any]]
    content_length: Optional[int]
    language: Optional[str]
    reading_level: Optional[str]
    overall_quality_score: Optional[int]
    readability_score: Optional[int]
    trustworthiness_score: Optional[int]
    professionalism_score: Optional[int]
    processing_status: str
    processing_time_ms: Optional[int]
    created_at: datetime
    processed_at: Optional[datetime]
    
    class Config:
        from_attributes = True


class SimilarContentResponse(BaseModel):
    """
    Response model for similar content results.
    """
    id: str
    target_analysis: AIAnalysisResponse
    similarity_score: float
    similarity_type: str
    confidence_score: int
    matching_elements: Optional[Dict[str, Any]]
    
    class Config:
        from_attributes = True


class DomainStatsResponse(BaseModel):
    """
    Response model for domain analysis statistics.
    """
    domain: str
    total_analyses: int
    avg_quality_score: float
    avg_trustworthiness_score: float
    completed_analyses: int
    success_rate: float


class AnalysisHistoryResponse(BaseModel):
    """
    Response model for analysis history.
    """
    analyses: List[AIAnalysisResponse]
    total_count: int
    page: int
    page_size: int
    has_next: bool


# API Endpoints
@router.post(
    "/analyze",
    response_model=AIAnalysisResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Analyze Content with AI",
    description="Perform comprehensive AI analysis on web content including quality scoring, topic classification, and sentiment analysis."
)
@limiter.limit("10/minute", key_func=ai_analysis_key_func)
async def analyze_content(
    request: Request,
    analysis_request: AIAnalysisRequest,
    controller: AIAnalysisController = Depends(get_ai_analysis_controller),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """
    Analyze web content using AI-powered analysis.
    
    This endpoint performs comprehensive content analysis including:
    - Content quality scoring
    - Topic classification
    - Sentiment analysis
    - SEO analysis
    - Language detection
    - Readability assessment
    """
    return await controller.analyze_content(
        request=request,
        url=analysis_request.url,
        content=analysis_request.content,
        analysis_types=analysis_request.analysis_types,
        current_user=current_user
    )


@router.get(
    "/analysis/{analysis_id}",
    response_model=AIAnalysisResponse,
    summary="Get Analysis Results",
    description="Retrieve AI analysis results by analysis ID."
)
@limiter.limit("20/minute", key_func=ai_analysis_key_func)
async def get_analysis(
    analysis_id: str,
    controller: AIAnalysisController = Depends(get_ai_analysis_controller),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """
    Get AI analysis results by ID.
    """
    return await controller.get_analysis(
        analysis_id=analysis_id,
        current_user=current_user
    )


@router.get("/analysis/{analysis_id}/similar", response_model=List[SimilarContentResponse], summary="Find Similar Content", description="Find content similar to the analyzed content.")
@limiter.limit("30/minute", key_func=ai_analysis_key_func)
async def find_similar_content(
    analysis_id: str,
    similarity_threshold: float = Query(0.8, ge=0.0, le=1.0, description="Minimum similarity score"),
    limit: int = Query(10, ge=1, le=50, description="Maximum number of results"),
    controller: AIAnalysisController = Depends(get_ai_analysis_controller),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """
    Find content similar to the analyzed content.
    """
    result = await controller.find_similar_content(
        analysis_id=analysis_id,
        similarity_threshold=similarity_threshold,
        limit=limit,
        current_user=current_user
    )
    return result["similar_content"]


@router.get(
    "/history",
    response_model=AnalysisHistoryResponse,
    summary="Get Analysis History",
    description="Get user's AI analysis history."
)
@limiter.limit("20/minute", key_func=ai_analysis_key_func)
async def get_analysis_history(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    controller: AIAnalysisController = Depends(get_ai_analysis_controller),
    current_user: User = Depends(get_current_user)
):
    """
    Get user's AI analysis history with pagination.
    """
    return await controller.get_analysis_history(
        page=page,
        page_size=page_size,
        current_user=current_user
    )


@router.get(
    "/domain/{domain}/stats",
    response_model=DomainStatsResponse,
    summary="Get Domain Analysis Statistics",
    description="Get analysis statistics for a specific domain."
)
@limiter.limit("30/minute", key_func=ai_analysis_key_func)
async def get_domain_stats(
    domain: str,
    controller: AIAnalysisController = Depends(get_ai_analysis_controller),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """
    Get analysis statistics for a domain.
    """
    return await controller.get_domain_stats(
        domain=domain,
        current_user=current_user
    )


@router.post(
    "/analysis/{analysis_id}/retry",
    response_model=AIAnalysisResponse,
    summary="Retry Failed Analysis",
    description="Retry a failed AI analysis.")
@limiter.limit("10/minute", key_func=ai_analysis_key_func)
async def retry_analysis(
    analysis_id: str,
    controller: AIAnalysisController = Depends(get_ai_analysis_controller),
    current_user: User = Depends(get_current_user)
):
    """
    Retry a failed analysis.
    """
    return await controller.retry_analysis(
        analysis_id=analysis_id,
        current_user=current_user
    )


@router.get(
    "/status",
    summary="Get AI Analysis Service Status",
    description="Get the current status of the AI analysis service.")
@limiter.limit("30/minute", key_func=ai_analysis_key_func)
async def get_service_status(controller: AIAnalysisController = Depends(get_ai_analysis_controller)):
    """
    Get AI analysis service status.
    """
    return await controller.get_service_status()