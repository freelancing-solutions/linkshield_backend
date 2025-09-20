#!/usr/bin/env python3
"""
LinkShield Backend AI Analysis Routes

API endpoints for AI-powered content analysis, quality scoring,
and intelligent insights.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, validator
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.database import get_db_session
from src.models.ai_analysis import AIAnalysis, ProcessingStatus, AnalysisType
from src.models.user import User
from src.services.ai_analysis_service import AIAnalysisService
from src.authentication.dependencies import get_current_user, get_optional_user
from src.security.rate_limiting import limiter
from fastapi import Request

# Initialize router
router = APIRouter(prefix="/api/v1/ai-analysis", tags=["AI Analysis"])

# Initialize service
ai_analysis_service = AIAnalysisService()


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
    
    @validator('url')
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
@limiter.limit("10/minute")
async def analyze_content(
    request: Request,
    analysis_request: AIAnalysisRequest,
    db: AsyncSession = Depends(get_db_session),
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
    try:
        # Initialize service if needed
        await ai_analysis_service.initialize()
        
        # Perform analysis
        analysis = await ai_analysis_service.analyze_content(
            db=db,
            url=analysis_request.url,
            content=analysis_request.content,
            user_id=str(current_user.id) if current_user else None,
            analysis_types=analysis_request.analysis_types
        )
        
        return AIAnalysisResponse.from_orm(analysis)
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}"
        )


@router.get(
    "/analysis/{analysis_id}",
    response_model=AIAnalysisResponse,
    summary="Get Analysis Results",
    description="Retrieve AI analysis results by analysis ID."
)
async def get_analysis(
    analysis_id: str,
    db: AsyncSession = Depends(get_db_session),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """
    Get AI analysis results by ID.
    """
    try:
        # Validate UUID format
        uuid.UUID(analysis_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid analysis ID format"
        )
    
    analysis = await db.get(AIAnalysis, analysis_id)
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis not found"
        )
    
    # Check access permissions
    if current_user and analysis.user_id and str(analysis.user_id) != str(current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    return AIAnalysisResponse.from_orm(analysis)


@router.get(
    "/analysis/{analysis_id}/similar",
    response_model=List[SimilarContentResponse],
    summary="Find Similar Content",
    description="Find content similar to the analyzed content."
)
@limiter.limit("20/minute")
async def find_similar_content(
    request: Request,
    analysis_id: str,
    similarity_threshold: float = Query(0.8, ge=0.0, le=1.0, description="Minimum similarity score"),
    limit: int = Query(10, ge=1, le=50, description="Maximum number of results"),
    db: AsyncSession = Depends(get_db_session),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """
    Find content similar to the analyzed content.
    """
    try:
        # Validate UUID format
        uuid.UUID(analysis_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid analysis ID format"
        )
    
    # Check if analysis exists and user has access
    analysis = await db.get(AIAnalysis, analysis_id)
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis not found"
        )
    
    if current_user and analysis.user_id and str(analysis.user_id) != str(current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    try:
        similarities = await ai_analysis_service.find_similar_content(
            db=db,
            analysis_id=analysis_id,
            similarity_threshold=similarity_threshold,
            limit=limit
        )
        
        # Load target analyses
        response = []
        for similarity in similarities:
            target_analysis = await db.get(AIAnalysis, similarity.target_analysis_id)
            if target_analysis:
                response.append(SimilarContentResponse(
                    id=str(similarity.id),
                    target_analysis=AIAnalysisResponse.from_orm(target_analysis),
                    similarity_score=similarity.similarity_score,
                    similarity_type=similarity.similarity_type,
                    confidence_score=similarity.confidence_score,
                    matching_elements=similarity.matching_elements
                ))
        
        return response
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Similarity search failed: {str(e)}"
        )


@router.get(
    "/history",
    response_model=AnalysisHistoryResponse,
    summary="Get Analysis History",
    description="Get user's AI analysis history."
)
async def get_analysis_history(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """
    Get user's AI analysis history with pagination.
    """
    offset = (page - 1) * page_size
    
    try:
        analyses = await ai_analysis_service.get_user_analysis_history(
            db=db,
            user_id=str(current_user.id),
            limit=page_size + 1,  # Get one extra to check if there's a next page
            offset=offset
        )
        
        has_next = len(analyses) > page_size
        if has_next:
            analyses = analyses[:-1]  # Remove the extra item
        
        # Get total count (this could be optimized with a separate count query)
        total_analyses = await ai_analysis_service.get_user_analysis_history(
            db=db,
            user_id=str(current_user.id),
            limit=1000000,  # Large number to get all
            offset=0
        )
        
        return AnalysisHistoryResponse(
            analyses=[AIAnalysisResponse.from_orm(analysis) for analysis in analyses],
            total_count=len(total_analyses),
            page=page,
            page_size=page_size,
            has_next=has_next
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve analysis history: {str(e)}"
        )


@router.get(
    "/domain/{domain}/stats",
    response_model=DomainStatsResponse,
    summary="Get Domain Analysis Statistics",
    description="Get analysis statistics for a specific domain."
)
@limiter.limit("30/minute")
async def get_domain_stats(
    request: Request,
    domain: str,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get analysis statistics for a domain.
    """
    try:
        stats = await ai_analysis_service.get_domain_analysis_stats(
            db=db,
            domain=domain
        )
        
        return DomainStatsResponse(**stats)
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve domain statistics: {str(e)}"
        )


@router.post(
    "/analysis/{analysis_id}/retry",
    response_model=AIAnalysisResponse,
    summary="Retry Failed Analysis",
    description="Retry a failed AI analysis."
)
async def retry_analysis(
    analysis_id: str,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
):
    """
    Retry a failed AI analysis.
    """
    try:
        # Validate UUID format
        uuid.UUID(analysis_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid analysis ID format"
        )
    
    # Check if analysis exists and user has access
    analysis = await db.get(AIAnalysis, analysis_id)
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis not found"
        )
    
    if str(analysis.user_id) != str(current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    try:
        retried_analysis = await ai_analysis_service.retry_failed_analysis(
            db=db,
            analysis_id=analysis_id
        )
        
        return AIAnalysisResponse.from_orm(retried_analysis)
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Retry failed: {str(e)}"
        )


@router.get(
    "/status",
    summary="Get AI Analysis Service Status",
    description="Get the current status of AI analysis models and services."
)
async def get_service_status():
    """
    Get AI analysis service status.
    """
    try:
        await ai_analysis_service.initialize()
        model_status = await ai_analysis_service.ai_service.get_model_status()
        
        return {
            "status": "operational",
            "initialized": ai_analysis_service._initialized,
            "models": model_status,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }