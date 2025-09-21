#!/usr/bin/env python3
"""
LinkShield Backend AI Analysis Controller

    Controller for handling AI analysis business logic including content analysis,
    quality scoring, similarity detection, and intelligent insights management.
"""

import hashlib
import uuid
from datetime import datetime, timezone
from http.client import HTTPException
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

from fastapi import BackgroundTasks
from sqlalchemy import select, and_, or_, desc, func
from starlette import status
from starlette.requests import Request

from src.controllers.base_controller import BaseController
from src.services.ai_analysis_service import AIAnalysisService, AIAnalysisException
from src.services.ai_service import AIService
from src.services.security_service import SecurityService
from src.authentication.auth_service import AuthService
from src.services.email_service import EmailService
from src.models.ai_analysis import ProcessingStatus, AnalysisType, AIAnalysis, ContentSimilarity
from src.models.task import TaskStatus, TaskType, TaskPriority
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
        ai_analysis_service: AIAnalysisService,
        ai_service: AIService,
        security_service: SecurityService,
        auth_service: AuthService,
        email_service: EmailService
    ):
        """
        Initialize the AI analysis controller.
        
        Args:
            ai_analysis_service: AI analysis service instance
            ai_service: AI service for pure business logic analysis
            security_service: Security service for validation
            auth_service: Authentication service for user operations
            email_service: Email service for notifications
        """
        super().__init__(security_service, auth_service, email_service)
        self.ai_analysis_service = ai_analysis_service
        self.ai_service = ai_service

    async def analyze_content(
        self,
        request: Request,
        url: str,
        content: str,
        analysis_types: Optional[List[AnalysisType]] = None,
        current_user: Optional[User] = None,
        background_tasks: Optional[BackgroundTasks] = None,
        callback_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Analyze web content using AI-powered analysis.
        
        Args:
            request: FastAPI request object for rate limiting
            url: URL to analyze
            content: Content to analyze
            analysis_types: Specific analysis types to perform
            current_user: Current authenticated user
            background_tasks: FastAPI background tasks for async processing
            callback_url: Optional webhook URL for completion notification
            
        Returns:
            Dict containing analysis results or task information for async processing
            
        Raises:
            AIAnalysisException: If analysis fails or validation errors occur
        """
        try:
            # Determine if should process async
            should_process_async = (
                background_tasks is not None and 
                (len(content) > 10000 or callback_url is not None)
            )
            
            if should_process_async:
                # Create background task for async processing
                async with self.get_db_session() as db:
                    task_tracking_service = get_task_tracking_service()
                    
                    task = await task_tracking_service.create_task(
                        db=db,
                        task_type=TaskType.AI_ANALYSIS,
                        priority=TaskPriority.NORMAL,
                        user_id=current_user.id,
                        metadata={
                            "url": url,
                            "content_length": len(content),
                            "analysis_types": [at.value for at in analysis_types] if analysis_types else None,
                            "callback_url": callback_url
                        }
                    )
                    
                    # Add background task
                    background_tasks.add_task(
                        self._process_analysis_async,
                        task_id=str(task.id),
                        url=url,
                        content=content,
                        analysis_types=analysis_types,
                        user_id=current_user.id,
                        callback_url=callback_url
                    )
                    
                    return {
                        "task_id": str(task.id),
                        "status": "processing",
                        "message": "Analysis queued for processing",
                        "url": url,
                        "estimated_completion_time": task.estimated_completion_time,
                        "created_at": task.created_at
                    }
            
            # Process synchronously
            async with self.get_db_session() as db:
                # Create analysis record
                analysis = await self._create_analysis_record(
                    db=db,
                    url=url,
                    content=content,
                    user_id=current_user.id if current_user else None,
                    analysis_types=analysis_types
                )
                
                # Perform AI analysis using pure business logic service
                ai_results = await self.ai_service.analyze_content(content, url)
                
                # Update analysis record with results
                await self._update_analysis_with_results(db, analysis, ai_results)
                
                # Commit changes
                await db.commit()
                await db.refresh(analysis)
                
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
                
        except Exception as e:
            logger.error(f"Error in analyze_content: {str(e)}")
            raise AIAnalysisException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Analysis failed: {str(e)}"
            )


    async def _process_analysis_async(
        self,
        task_id: str,
        url: str,
        content: str,
        analysis_types: Optional[List[AnalysisType]] = None,
        user_id: Optional[int] = None,
        callback_url: Optional[str] = None
    ) -> None:
        """
        Process AI analysis asynchronously in the background.
        
        Args:
            task_id: ID of the background task
            url: URL to analyze
            content: Content to analyze
            analysis_types: Specific analysis types to perform
            user_id: ID of the user requesting analysis
            callback_url: Optional webhook URL for completion notification
        """
        task_tracking_service = get_task_tracking_service()
        webhook_service = get_webhook_service()
        
        try:
            # Get database session using context manager
            async with self.get_db_session() as db:
                # Update task status to running
                await task_tracking_service.update_task_status(
                    db=db,
                    task_id=task_id,
                    status=TaskStatus.RUNNING,
                    progress=10
                )
                
                # Initialize AI service
                await self.ai_analysis_service.initialize()
                
                # Update progress
                await task_tracking_service.update_task_status(
                    db=db,
                    task_id=task_id,
                    status=TaskStatus.RUNNING,
                    progress=25
                )
                
                # Perform the actual analysis
                analysis = await self._create_analysis_record(
                    db=db,
                    url=url,
                    content=content,
                    user_id=user_id,
                    analysis_types=analysis_types
                )
                
                # Perform AI analysis using pure business logic service
                ai_results = await self.ai_service.analyze_content(content, url)
                
                # Update analysis record with results
                await self._update_analysis_with_results(db, analysis, ai_results)
                
                # Commit changes
                await db.commit()
                await db.refresh(analysis)
                
                # Update progress
                await task_tracking_service.update_task_status(
                    db=db,
                    task_id=task_id,
                    status=TaskStatus.RUNNING,
                    progress=90
                )
                
                # Prepare result data
                result_data = {
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
                
                # Complete the task
                await task_tracking_service.complete_task(
                    db=db,
                    task_id=task_id,
                    result=result_data
                )
                
                # Send webhook notification if callback URL provided
                if callback_url:
                    webhook_payload = {
                        "event": "ai_analysis_completed",
                        "task_id": task_id,
                        "analysis": result_data,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                    
                    await webhook_service.send_webhook(
                        url=callback_url,
                        payload=webhook_payload,
                        event_type="ai_analysis_completed",
                        user_id=user_id
                    )
                
                # Log successful completion
                self.log_operation(
                    "AI content analysis completed asynchronously",
                    user_id=user_id,
                    details={
                        "task_id": task_id,
                        "analysis_id": str(analysis.id),
                        "url": url,
                        "content_length": len(content),
                        "callback_url": callback_url
                    }
                )
            
        except Exception as e:
            # Handle failure
            self.logger.error(f"Async AI analysis failed for task {task_id}: {e}")
            
            try:
                # Mark task as failed using context manager
                async with self.get_db_session() as db:
                    await task_tracking_service.fail_task(
                        db=db,
                        task_id=task_id,
                        error=str(e)
                    )
                    
                    # Send failure webhook if callback URL provided
                    if callback_url:
                        webhook_payload = {
                            "event": "ai_analysis_failed",
                            "task_id": task_id,
                            "error": str(e),
                            "url": url,
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        }
                        
                        await webhook_service.send_webhook(
                            url=callback_url,
                            payload=webhook_payload,
                            event_type="ai_analysis_failed",
                            user_id=user_id
                        )
                
            except Exception as cleanup_error:
                self.logger.error(f"Failed to handle async analysis failure for task {task_id}: {cleanup_error}")

    async def retry_analysis(
        self,
        analysis_id: str,
        current_user: User,
        background_tasks: Optional[BackgroundTasks] = None,
        callback_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Retry a failed analysis with optional async processing.
        
        Args:
            analysis_id: ID of the analysis to retry
            current_user: Current authenticated user
            background_tasks: Optional background tasks for async processing
            callback_url: Optional webhook URL for completion notification
            
        Returns:
            Dict containing retry results or task information
            
        Raises:
            AIAnalysisException: If retry fails or analysis not found
        """
        try:
            # Validate UUID format
            try:
                uuid.UUID(analysis_id)
            except ValueError:
                raise AIAnalysisException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid analysis ID format"
                )
            
            # Get database session using context manager
            async with self.get_db_session() as db:
                # Get original analysis
                original_analysis = await self.ai_analysis_service.get_analysis(
                    db=db,
                    analysis_id=analysis_id,
                    user_id=current_user.id
                )
                
                if not original_analysis:
                    raise AIAnalysisException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Analysis not found"
                    )
                
                # Check if user owns this analysis
                if original_analysis.user_id != current_user.id:
                    raise AIAnalysisException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Access denied to this analysis"
                    )
                
                # Check if analysis actually failed
                if original_analysis.processing_status != ProcessingStatus.FAILED:
                    raise AIAnalysisException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Can only retry failed analyses"
                    )
                
                # Get original content (this would need to be stored or retrieved)
                # For now, we'll assume the content is available in metadata or similar
                content = original_analysis.metadata.get("original_content", "")
                if not content:
                    raise AIAnalysisException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Original content not available for retry"
                    )
                
                # Determine if should process async
                should_process_async = (
                    background_tasks is not None and 
                    (len(content) > 10000 or callback_url is not None)
                )
                
                if should_process_async:
                    # Create background task for async retry
                    task_tracking_service = get_task_tracking_service()
                    
                    task = await task_tracking_service.create_task(
                        db=db,
                        task_type=TaskType.AI_ANALYSIS_RETRY,
                        priority=TaskPriority.HIGH,
                        user_id=current_user.id,
                        metadata={
                            "original_analysis_id": analysis_id,
                            "url": original_analysis.url,
                            "content_length": len(content),
                            "callback_url": callback_url
                        }
                    )
                    
                    # Add background task
                    background_tasks.add_task(
                        self._process_retry_async,
                        task_id=str(task.id),
                        original_analysis_id=analysis_id,
                        url=original_analysis.url,
                        content=content,
                        user_id=current_user.id,
                        callback_url=callback_url
                    )
                    
                    return {
                        "task_id": str(task.id),
                        "status": "processing",
                        "message": "Analysis retry queued for processing",
                        "original_analysis_id": analysis_id,
                        "url": original_analysis.url,
                        "estimated_completion_time": task.estimated_completion_time,
                        "created_at": task.created_at
                    }
                
                # Process retry synchronously
                new_analysis = await self.ai_analysis_service.retry_analysis(
                    db=db,
                    analysis_id=analysis_id,
                    user_id=current_user.id
                )
                
                return {
                    "id": str(new_analysis.id),
                    "original_analysis_id": analysis_id,
                    "url": new_analysis.url,
                    "domain": new_analysis.domain,
                    "content_summary": new_analysis.content_summary,
                    "quality_metrics": new_analysis.quality_metrics,
                    "topic_categories": new_analysis.topic_categories,
                    "sentiment_analysis": new_analysis.sentiment_analysis,
                    "seo_metrics": new_analysis.seo_metrics,
                    "content_length": new_analysis.content_length,
                    "language": new_analysis.language,
                    "reading_level": new_analysis.reading_level,
                    "overall_quality_score": new_analysis.overall_quality_score,
                    "readability_score": new_analysis.readability_score,
                    "trustworthiness_score": new_analysis.trustworthiness_score,
                    "professionalism_score": new_analysis.professionalism_score,
                    "processing_status": new_analysis.processing_status.value,
                    "processing_time_ms": new_analysis.processing_time_ms,
                    "created_at": new_analysis.created_at,
                    "processed_at": new_analysis.processed_at
                }

        except Exception as e:
            self.logger.error(f"Analysis retry failed for {analysis_id}: {e}")
            raise AIAnalysisException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Analysis retry failed"
            )

    async def _process_retry_async(
        self,
        task_id: str,
        original_analysis_id: str,
        url: str,
        content: str,
        user_id: int,
        callback_url: Optional[str] = None
    ) -> None:
        """
        Process analysis retry asynchronously in the background.
        
        Args:
            task_id: ID of the background task
            original_analysis_id: ID of the original failed analysis
            url: URL to analyze
            content: Content to analyze
            user_id: ID of the user requesting retry
            callback_url: Optional webhook URL for completion notification
        """
        task_tracking_service = get_task_tracking_service()
        webhook_service = get_webhook_service()
        
        try:
            # Get database session using context manager
            async with self.get_db_session() as db:
                # Update task status
                await task_tracking_service.update_task_status(
                    db=db,
                    task_id=task_id,
                    status=TaskStatus.RUNNING,
                    progress=10
                )
                
                # Perform retry
                new_analysis = await self.ai_analysis_service.retry_analysis(
                    db=db,
                    analysis_id=original_analysis_id,
                    user_id=user_id
                )
                
                # Prepare result data
                result_data = {
                    "id": str(new_analysis.id),
                    "original_analysis_id": original_analysis_id,
                    "url": new_analysis.url,
                    "domain": new_analysis.domain,
                    "content_summary": new_analysis.content_summary,
                    "quality_metrics": new_analysis.quality_metrics,
                    "topic_categories": new_analysis.topic_categories,
                    "sentiment_analysis": new_analysis.sentiment_analysis,
                    "seo_metrics": new_analysis.seo_metrics,
                    "content_length": new_analysis.content_length,
                    "language": new_analysis.language,
                    "reading_level": new_analysis.reading_level,
                    "overall_quality_score": new_analysis.overall_quality_score,
                    "readability_score": new_analysis.readability_score,
                    "trustworthiness_score": new_analysis.trustworthiness_score,
                    "professionalism_score": new_analysis.professionalism_score,
                    "processing_status": new_analysis.processing_status.value,
                    "processing_time_ms": new_analysis.processing_time_ms,
                    "created_at": new_analysis.created_at,
                    "processed_at": new_analysis.processed_at
                }
                
                # Complete the task
                await task_tracking_service.complete_task(
                    db=db,
                    task_id=task_id,
                    result=result_data
                )
                
                # Send webhook notification if callback URL provided
                if callback_url:
                    webhook_payload = {
                        "event": "ai_analysis_retry_completed",
                        "task_id": task_id,
                        "original_analysis_id": original_analysis_id,
                        "analysis": result_data,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                    
                    await webhook_service.send_webhook(
                        url=callback_url,
                        payload=webhook_payload,
                        event_type="ai_analysis_retry_completed",
                        user_id=user_id
                    )
            
        except Exception as e:
            # Handle failure
            self.logger.error(f"Async analysis retry failed for task {task_id}: {e}")
            
            try:
                # Mark task as failed using context manager
                async with self.get_db_session() as db:
                    await task_tracking_service.fail_task(
                        db=db,
                        task_id=task_id,
                        error=str(e)
                    )
                    
                    if callback_url:
                        webhook_payload = {
                            "event": "ai_analysis_retry_failed",
                            "task_id": task_id,
                            "original_analysis_id": original_analysis_id,
                            "error": str(e),
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        }
                        
                        await webhook_service.send_webhook(
                            url=callback_url,
                            payload=webhook_payload,
                            event_type="ai_analysis_retry_failed",
                            user_id=user_id
                        )
                
            except Exception as cleanup_error:
                self.logger.error(f"Failed to handle async retry failure for task {task_id}: {cleanup_error}")

    async def get_service_status(self) -> Dict[str, Any]:
        """
        Get AI analysis service status including model health and performance metrics.
        
        Returns:
            Dict containing service status information
        """
        try:
            # Initialize service if needed
            await self.ai_analysis_service.initialize()
            
            # Get service status
            status_info = await self.ai_analysis_service.get_service_status()
            
            return status_info
            
        except Exception as e:
            self.logger.error(f"Failed to get service status: {e}")
            raise AIAnalysisException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve service status")
            
        except AIAnalysisException:
            raise
        except Exception as e:
            self.logger.error(f"AI analysis failed: {e}")
            raise AIAnalysisException(
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
            AIAnalysisException: If analysis not found or access denied
        """
        try:
            # Validate UUID format
            try:
                uuid.UUID(analysis_id)
            except ValueError:
                raise AIAnalysisException(
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
                raise AIAnalysisException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Analysis not found"
                )
            
            # Check access permissions
            if current_user and analysis.user_id and analysis.user_id != current_user.id:
                raise AIAnalysisException(
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
            
        except AIAnalysisException:
            raise
        except Exception as e:
            self.logger.error(f"Failed to get analysis {analysis_id}: {e}")
            raise AIAnalysisException(
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
            AIAnalysisException: If analysis not found or validation errors
        """
        try:
            # Validate parameters
            try:
                uuid.UUID(analysis_id)
            except ValueError:
                raise AIAnalysisException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid analysis ID format"
                )
            
            if not 0.0 <= similarity_threshold <= 1.0:
                raise AIAnalysisException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Similarity threshold must be between 0.0 and 1.0"
                )
            
            if not 1 <= limit <= 100:
                raise AIAnalysisException(
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
            raise AIAnalysisException(
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
            AIAnalysisException: If user not authenticated or validation errors
        """
        try:
            # Require authentication for history
            if not current_user:
                raise AIAnalysisException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            # Validate pagination parameters
            if page < 1:
                raise AIAnalysisException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Page must be >= 1"
                )
            
            if not 1 <= page_size <= 100:
                raise AIAnalysisException(
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
            
        except Exception as e:
            self.logger.error(f"Failed to get analysis history for user {current_user.id if current_user else 'None'}: {e}")
            raise AIAnalysisException(
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
            AIAnalysisException: If validation errors occur
        """
        try:
            # Validate domain
            if not domain or len(domain.strip()) == 0:
                raise AIAnalysisException(
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
            
        except AIAnalysisException:
            raise
        except Exception as e:
            self.logger.error(f"Failed to get domain stats for {domain}: {e}")
            raise AIAnalysisException(
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
            AIAnalysisException: If analysis not found or cannot be retried
        """
        try:
            # Validate UUID format
            try:
                uuid.UUID(analysis_id)
            except ValueError:
                raise AIAnalysisException(
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
                raise AIAnalysisException(
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
            
        except AIAnalysisException:
            raise
        except Exception as e:
            self.logger.error(f"Failed to retry analysis {analysis_id}: {e}")
            raise AIAnalysisException(
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

    async def _create_analysis_record(
        self,
        db,
        url: str,
        content: str,
        user_id: Optional[str] = None,
        check_id: Optional[str] = None,
        analysis_types: Optional[List[AnalysisType]] = None
    ) -> AIAnalysis:
        """
        Create a new AI analysis record in the database.
        
        Args:
            db: Database session
            url: URL being analyzed
            content: Content to analyze
            user_id: Optional user ID
            check_id: Optional URL check ID
            analysis_types: Specific analysis types to perform
            
        Returns:
            AIAnalysis: Created analysis record
        """
        # Generate content hash for deduplication
        content_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
        
        # Extract domain from URL
        domain = urlparse(url).netloc if url else None
        
        # Create new analysis record
        analysis = AIAnalysis(
            user_id=user_id,
            check_id=check_id,
            url=url,
            content_hash=content_hash,
            domain=domain,
            content_length=len(content),
            processing_status=ProcessingStatus.PROCESSING,
            analysis_types=[at.value for at in analysis_types] if analysis_types else None
        )
        
        db.add(analysis)
        await db.commit()
        await db.refresh(analysis)
        
        return analysis

    async def _update_analysis_with_results(
        self,
        db,
        analysis: AIAnalysis,
        ai_results: Dict[str, Any]
    ) -> None:
        """
        Update analysis record with AI analysis results.
        
        Args:
            db: Database session
            analysis: Analysis record to update
            ai_results: Results from AI analysis
        """
        start_time = datetime.now(timezone.utc)
        
        try:
            # Calculate processing time
            processing_time = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
            
            # Extract content summary
            if 'content_summary' in ai_results:
                analysis.content_summary = ai_results['content_summary']
            
            # Store quality metrics
            quality_data = ai_results.get('quality_analysis', {})
            analysis.quality_metrics = quality_data
            analysis.overall_quality_score = quality_data.get('overall_score', 0)
            analysis.readability_score = quality_data.get('readability_score', 0)
            analysis.trustworthiness_score = quality_data.get('trustworthiness_score', 0)
            analysis.professionalism_score = quality_data.get('professionalism_score', 0)
            
            # Store topic classification
            if 'topic_analysis' in ai_results:
                analysis.topic_categories = ai_results['topic_analysis']
            
            # Store sentiment analysis
            if 'sentiment_analysis' in ai_results:
                analysis.sentiment_analysis = ai_results['sentiment_analysis']
            
            # Store SEO metrics
            if 'seo_analysis' in ai_results:
                analysis.seo_metrics = ai_results['seo_analysis']
            
            # Store language detection
            if 'language' in ai_results:
                analysis.language = ai_results['language']
            
            # Store processing metadata
            analysis.processing_time_ms = processing_time
            analysis.model_versions = ai_results.get('model_versions', {})
            
            # Update status
            analysis.processing_status = ProcessingStatus.COMPLETED
            analysis.processed_at = datetime.now(timezone.utc)
            
        except Exception as e:
            # Update status to failed
            analysis.processing_status = ProcessingStatus.FAILED
            analysis.processed_at = datetime.now(timezone.utc)
            self.logger.error(f"Failed to update analysis with results: {e}")
            raise
