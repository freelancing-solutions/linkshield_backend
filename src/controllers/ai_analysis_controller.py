#!/usr/bin/env python3
"""
LinkShield Backend AI Analysis Controller

Controller for handling AI analysis business logic including content analysis,
quality scoring, similarity detection, and intelligent insights management.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

from fastapi import HTTPException, status, Request
from loguru import logger

from src.controllers.base_controller import BaseController
from src.services.ai_analysis_service import AIAnalysisService
from src.models.ai_analysis import AIAnalysis, ProcessingStatus, AnalysisType
from src.models.user import User


class AIAnalysisController(BaseController):
    """
    Controller for AI analysis operations.
    
    Handles content analysis, quality scoring, similarity detection,
    and analysis history management with comprehensive error handling
    and validation.
    """
    
    def __init__(
        self,
        db_session,
        ai_analysis_service: AIAnalysisService,
        security_service=None,
        auth_service=None
    ):
        """
        Initialize the AI analysis controller.
        
        Args:
            db_session: Database session for data operations
            ai_analysis_service: AI analysis service instance
            security_service: Security service for validation
            auth_service: Authentication service for user operations
        """
        super().__init__(
            get_db_session=db_session,
            security_service=security_service,
            auth_service=auth_service
        )
        self.ai_analysis_service = ai_analysis_service

    async def analyze_content(
        self,
        request: Request,
        url: str,
        content: str,
        analysis_types: Optional[List[AnalysisType]] = None,
        current_user: Optional[User] = None
    ) -> Dict[str, Any]:
        """
        Analyze web content using AI-powered analysis.
        
        Args:
            request: FastAPI request object for rate limiting
            url: URL to analyze
            content: Content to analyze
            analysis_types: Specific analysis types to perform
            current_user: Current authenticated user
            
        Returns:
            Dict containing analysis results
            
        Raises:
            HTTPException: If analysis fails or validation errors occur
        """
        try:
            # Validate URL format
            if not url.startswith(('http://', 'https://')):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="URL must start with http:// or https://"
                )
            
            # Validate content length
            if len(content) < 10:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Content must be at least 10 characters long"
                )
            
            if len(content) > 50000:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Content must not exceed 50,000 characters"
                )
            
            # Initialize service if needed
            await self.ai_analysis_service.initialize()
            
            # Get database session
            db = await self.get_db_session()
            
            # Perform analysis
            analysis = await self.ai_analysis_service.analyze_content(
                db=db,
                url=url,
                content=content,
                user_id=current_user.id if current_user else None,
                analysis_types=analysis_types
            )
            
            # Log successful analysis
            self.log_operation(
                "AI content analysis completed",
                user_id=current_user.id if current_user else None,
                details={
                    "analysis_id": str(analysis.id),
                    "url": url,
                    "content_length": len(content),
                    "analysis_types": [t.value for t in analysis_types] if analysis_types else None
                }
            )
            
            return {
                "id": str(analysis.id),
                "url": analysis.url,
                "domain": analysis.domain,
                "content_summary": analysis.content_summary,
                "quality_metrics": analysis.quality_metrics,
                "topic_categories": analysis.topic_categories,
                "sentiment_analysis": analysis.sentiment_analysis,
                "seo_metrics": analysis.seo_metrics,
                "content_length": analysis.content_length,
                "language": analysis.language,
                "reading_level": analysis.reading_level,
                "overall_quality_score": analysis.overall_quality_score,
                "readability_score": analysis.readability_score,
                "trustworthiness_score": analysis.trustworthiness_score,
                "professionalism_score": analysis.professionalism_score,
                "processing_status": analysis.processing_status.value,
                "processing_time_ms": analysis.processing_time_ms,
                "created_at": analysis.created_at,
                "processed_at": analysis.processed_at
            }
            
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"AI analysis failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Analysis processing failed"
            )

    async def get_analysis(
        self,
        analysis_id: str,
        current_user: Optional[User] = None
    ) -> Dict[str, Any]:
        """
        Get analysis results by ID.
        
        Args:
            analysis_id: UUID of the analysis
            current_user: Current authenticated user
            
        Returns:
            Dict containing analysis results
            
        Raises:
            HTTPException: If analysis not found or access denied
        """
        try:
            # Validate UUID format
            try:
                uuid.UUID(analysis_id)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid analysis ID format"
                )
            
            # Get database session
            db = await self.get_db_session()
            
            # Get analysis
            analysis = await self.ai_analysis_service.get_analysis(
                db=db,
                analysis_id=analysis_id,
                user_id=current_user.id if current_user else None
            )
            
            if not analysis:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Analysis not found"
                )
            
            # Check access permissions
            if current_user and analysis.user_id and analysis.user_id != current_user.id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied to this analysis"
                )
            
            return {
                "id": str(analysis.id),
                "url": analysis.url,
                "domain": analysis.domain,
                "content_summary": analysis.content_summary,
                "quality_metrics": analysis.quality_metrics,
                "topic_categories": analysis.topic_categories,
                "sentiment_analysis": analysis.sentiment_analysis,
                "seo_metrics": analysis.seo_metrics,
                "content_length": analysis.content_length,
                "language": analysis.language,
                "reading_level": analysis.reading_level,
                "overall_quality_score": analysis.overall_quality_score,
                "readability_score": analysis.readability_score,
                "trustworthiness_score": analysis.trustworthiness_score,
                "professionalism_score": analysis.professionalism_score,
                "processing_status": analysis.processing_status.value,
                "processing_time_ms": analysis.processing_time_ms,
                "created_at": analysis.created_at,
                "processed_at": analysis.processed_at
            }
            
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Failed to get analysis {analysis_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve analysis"
            )

    async def find_similar_content(
        self,
        analysis_id: str,
        similarity_threshold: float = 0.7,
        limit: int = 10,
        current_user: Optional[User] = None
    ) -> Dict[str, Any]:
        """
        Find similar content based on analysis.
        
        Args:
            analysis_id: UUID of the target analysis
            similarity_threshold: Minimum similarity score (0.0-1.0)
            limit: Maximum number of results
            current_user: Current authenticated user
            
        Returns:
            Dict containing similar content results
            
        Raises:
            HTTPException: If analysis not found or validation errors
        """
        try:
            # Validate parameters
            try:
                uuid.UUID(analysis_id)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid analysis ID format"
                )
            
            if not 0.0 <= similarity_threshold <= 1.0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Similarity threshold must be between 0.0 and 1.0"
                )
            
            if not 1 <= limit <= 100:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Limit must be between 1 and 100"
                )
            
            # Get database session
            db = await self.get_db_session()
            
            # Find similar content
            similar_content = await self.ai_analysis_service.find_similar_content(
                db=db,
                analysis_id=analysis_id,
                similarity_threshold=similarity_threshold,
                limit=limit,
                user_id=current_user.id if current_user else None
            )
            
            # Format response
            results = []
            for similarity in similar_content:
                target_analysis = similarity.target_analysis
                results.append({
                    "id": str(similarity.id),
                    "target_analysis": {
                        "id": str(target_analysis.id),
                        "url": target_analysis.url,
                        "domain": target_analysis.domain,
                        "content_summary": target_analysis.content_summary,
                        "quality_metrics": target_analysis.quality_metrics,
                        "topic_categories": target_analysis.topic_categories,
                        "sentiment_analysis": target_analysis.sentiment_analysis,
                        "seo_metrics": target_analysis.seo_metrics,
                        "content_length": target_analysis.content_length,
                        "language": target_analysis.language,
                        "reading_level": target_analysis.reading_level,
                        "overall_quality_score": target_analysis.overall_quality_score,
                        "readability_score": target_analysis.readability_score,
                        "trustworthiness_score": target_analysis.trustworthiness_score,
                        "professionalism_score": target_analysis.professionalism_score,
                        "processing_status": target_analysis.processing_status.value,
                        "processing_time_ms": target_analysis.processing_time_ms,
                        "created_at": target_analysis.created_at,
                        "processed_at": target_analysis.processed_at
                    },
                    "similarity_score": similarity.similarity_score,
                    "similarity_type": similarity.similarity_type,
                    "confidence_score": similarity.confidence_score,
                    "matching_elements": similarity.matching_elements
                })
            
            return {"similar_content": results}
            
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Failed to find similar content for {analysis_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to find similar content"
            )

    async def get_analysis_history(
        self,
        page: int = 1,
        page_size: int = 20,
        current_user: Optional[User] = None
    ) -> Dict[str, Any]:
        """
        Get user's analysis history with pagination.
        
        Args:
            page: Page number (1-based)
            page_size: Number of results per page
            current_user: Current authenticated user
            
        Returns:
            Dict containing paginated analysis history
            
        Raises:
            HTTPException: If user not authenticated or validation errors
        """
        try:
            # Require authentication for history
            if not current_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            # Validate pagination parameters
            if page < 1:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Page must be >= 1"
                )
            
            if not 1 <= page_size <= 100:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Page size must be between 1 and 100"
                )
            
            # Get database session
            db = await self.get_db_session()
            
            # Get analysis history
            analyses, total_count = await self.ai_analysis_service.get_user_analysis_history(
                db=db,
                user_id=current_user.id,
                page=page,
                page_size=page_size
            )
            
            # Format response
            analysis_list = []
            for analysis in analyses:
                analysis_list.append({
                    "id": str(analysis.id),
                    "url": analysis.url,
                    "domain": analysis.domain,
                    "content_summary": analysis.content_summary,
                    "quality_metrics": analysis.quality_metrics,
                    "topic_categories": analysis.topic_categories,
                    "sentiment_analysis": analysis.sentiment_analysis,
                    "seo_metrics": analysis.seo_metrics,
                    "content_length": analysis.content_length,
                    "language": analysis.language,
                    "reading_level": analysis.reading_level,
                    "overall_quality_score": analysis.overall_quality_score,
                    "readability_score": analysis.readability_score,
                    "trustworthiness_score": analysis.trustworthiness_score,
                    "professionalism_score": analysis.professionalism_score,
                    "processing_status": analysis.processing_status.value,
                    "processing_time_ms": analysis.processing_time_ms,
                    "created_at": analysis.created_at,
                    "processed_at": analysis.processed_at
                })
            
            has_next = (page * page_size) < total_count
            
            return {
                "analyses": analysis_list,
                "total_count": total_count,
                "page": page,
                "page_size": page_size,
                "has_next": has_next
            }
            
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Failed to get analysis history for user {current_user.id if current_user else 'None'}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve analysis history"
            )

    async def get_domain_stats(
        self,
        domain: str,
        current_user: Optional[User] = None
    ) -> Dict[str, Any]:
        """
        Get domain analysis statistics.
        
        Args:
            domain: Domain to get statistics for
            current_user: Current authenticated user
            
        Returns:
            Dict containing domain statistics
            
        Raises:
            HTTPException: If validation errors occur
        """
        try:
            # Validate domain
            if not domain or len(domain.strip()) == 0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Domain is required"
                )
            
            # Get database session
            db = await self.get_db_session()
            
            # Get domain statistics
            stats = await self.ai_analysis_service.get_domain_statistics(
                db=db,
                domain=domain.strip().lower(),
                user_id=current_user.id if current_user else None
            )
            
            return {
                "domain": domain.strip().lower(),
                "total_analyses": stats.get("total_analyses", 0),
                "avg_quality_score": stats.get("avg_quality_score", 0.0),
                "avg_trustworthiness_score": stats.get("avg_trustworthiness_score", 0.0),
                "completed_analyses": stats.get("completed_analyses", 0),
                "success_rate": stats.get("success_rate", 0.0)
            }
            
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Failed to get domain stats for {domain}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve domain statistics"
            )

    async def retry_analysis(
        self,
        analysis_id: str,
        current_user: Optional[User] = None
    ) -> Dict[str, Any]:
        """
        Retry a failed analysis.
        
        Args:
            analysis_id: UUID of the analysis to retry
            current_user: Current authenticated user
            
        Returns:
            Dict containing updated analysis results
            
        Raises:
            HTTPException: If analysis not found or cannot be retried
        """
        try:
            # Validate UUID format
            try:
                uuid.UUID(analysis_id)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid analysis ID format"
                )
            
            # Get database session
            db = await self.get_db_session()
            
            # Retry analysis
            analysis = await self.ai_analysis_service.retry_analysis(
                db=db,
                analysis_id=analysis_id,
                user_id=current_user.id if current_user else None
            )
            
            if not analysis:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Analysis not found or cannot be retried"
                )
            
            # Log retry operation
            self.log_operation(
                "AI analysis retry initiated",
                user_id=current_user.id if current_user else None,
                details={"analysis_id": str(analysis.id)}
            )
            
            return {
                "id": str(analysis.id),
                "url": analysis.url,
                "domain": analysis.domain,
                "content_summary": analysis.content_summary,
                "quality_metrics": analysis.quality_metrics,
                "topic_categories": analysis.topic_categories,
                "sentiment_analysis": analysis.sentiment_analysis,
                "seo_metrics": analysis.seo_metrics,
                "content_length": analysis.content_length,
                "language": analysis.language,
                "reading_level": analysis.reading_level,
                "overall_quality_score": analysis.overall_quality_score,
                "readability_score": analysis.readability_score,
                "trustworthiness_score": analysis.trustworthiness_score,
                "professionalism_score": analysis.professionalism_score,
                "processing_status": analysis.processing_status.value,
                "processing_time_ms": analysis.processing_time_ms,
                "created_at": analysis.created_at,
                "processed_at": analysis.processed_at
            }
            
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Failed to retry analysis {analysis_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retry analysis"
            )

    async def get_service_status(self) -> Dict[str, Any]:
        """
        Get AI service status and health information.
        
        Returns:
            Dict containing service status information
        """
        try:
            # Get service status
            status_info = await self.ai_analysis_service.get_service_status()
            
            return {
                "service_status": "healthy" if status_info.get("healthy", False) else "unhealthy",
                "models_loaded": status_info.get("models_loaded", False),
                "processing_queue_size": status_info.get("queue_size", 0),
                "last_health_check": status_info.get("last_check"),
                "version": status_info.get("version", "unknown")
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get service status: {e}")
            return {
                "service_status": "unhealthy",
                "models_loaded": False,
                "processing_queue_size": 0,
                "last_health_check": None,
                "version": "unknown",
                "error": str(e)
            }