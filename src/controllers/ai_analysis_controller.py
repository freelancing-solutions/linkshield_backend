"""AI Analysis Controller with integrated webhook and background task support."""

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
from contextlib import asynccontextmanager

from fastapi import HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from starlette.requests import Request

from src.controllers import BaseController

from src.services.ai_analysis_service import AIAnalysisService, AIAnalysisException
from src.services.ai_service import AIService
from src.services.security_service import SecurityService
from src.authentication.auth_service import AuthService
from src.services.email_service import EmailService
from src.models.ai_analysis import ProcessingStatus, AnalysisType, AIAnalysis
from src.models.task import TaskType, TaskPriority
from src.models.user import User


class AIAnalysisController(BaseController):
    """AI analysis controller with background task and webhook support."""

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
            ai_analysis_service: AI analysis service for processing
            ai_service: AI service for analysis operations
            security_service: Security service for validation
            auth_service: Authentication service
            email_service: Email service for notifications
            
        Raises:
            ValueError: If any required service is None
        """
        # Validate required services
        if ai_analysis_service is None:
            raise ValueError("ai_analysis_service cannot be None")
        if ai_service is None:
            raise ValueError("ai_service cannot be None")
        if security_service is None:
            raise ValueError("security_service cannot be None")
        if auth_service is None:
            raise ValueError("auth_service cannot be None")
        if email_service is None:
            raise ValueError("email_service cannot be None")
            
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
        """Analyze content with background task support."""
        try:
            # Determine processing mode
            should_process_async = (
                    background_tasks is not None and
                    (len(content) > 10000 or callback_url is not None)
            )

            if should_process_async:
                # Create background task
                task_id = await self.add_background_task_with_tracking(
                    background_tasks=background_tasks,
                    task_func=self._analyze_content_task,
                    task_type=TaskType.AI_ANALYSIS,
                    task_data={
                        "url": url,
                        "content_length": len(content),
                        "analysis_types": [at.value for at in analysis_types] if analysis_types else None
                    },
                    user_id=current_user.id if current_user else None,
                    priority=TaskPriority.NORMAL,
                    callback_url=callback_url,
                    # Task function arguments
                    url=url,
                    content=content,
                    analysis_types=analysis_types,
                )

                return {
                    "task_id": task_id,
                    "status": "processing",
                    "message": "AI analysis queued for background processing",
                    "url": url,
                    "content_length": len(content)
                }

            # Process synchronously
            return await self._analyze_content_sync(url, content, analysis_types, current_user)

        except Exception as e:
            self.logger.error(f"Analysis failed: {str(e)}")
            raise HTTPException(500, f"Analysis failed: {str(e)}")

    async def _analyze_content_task(
            self,
            task_id: str,
            url: str,
            content: str,
            analysis_types: Optional[List[AnalysisType]] = None,
            user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """Background task for AI content analysis."""
        try:
            # Update progress
            await self.update_task_progress(task_id, 10)

            async with self.get_db_session() as db:
                # Create analysis record
                analysis = await self._create_analysis_record(
                    db=db,
                    url=url,
                    content=content,
                    user_id=user_id,
                    analysis_types=analysis_types
                )

                await self.update_task_progress(task_id, 30)

                # Initialize AI service
                await self.ai_analysis_service.initialize()

                await self.update_task_progress(task_id, 50)

                # Perform AI analysis
                ai_results = await self.ai_service.analyze_content(content, url)

                await self.update_task_progress(task_id, 80)

                # Update analysis with results
                await self._update_analysis_with_results(db, analysis, ai_results)
                # Commit handled by context manager
                await db.refresh(analysis)

                await self.update_task_progress(task_id, 100)

                # Return structured result
                return self._format_analysis_response(analysis)

        except Exception as e:
            self.logger.error(f"Background analysis task {task_id} failed: {str(e)}")
            raise

    async def _analyze_content_sync(
            self,
            url: str,
            content: str,
            analysis_types: Optional[List[AnalysisType]] = None,
            current_user: Optional[User] = None
    ) -> Dict[str, Any]:
        """Synchronous content analysis."""
        async with self.get_db_session() as db:
            # Create analysis record
            analysis = await self._create_analysis_record(
                db=db,
                url=url,
                content=content,
                user_id=current_user.id if current_user else None,
                analysis_types=analysis_types
            )

            # Perform AI analysis
            ai_results = await self.ai_service.analyze_content(content, url)

            # Update analysis with results
            await self._update_analysis_with_results(db, analysis, ai_results)
            # Commit handled by context manager
            await db.refresh(analysis)

            return self._format_analysis_response(analysis)

    async def retry_analysis(
            self,
            analysis_id: str,
            user_id: str,
            background_tasks: Optional[BackgroundTasks] = None,
            callback_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """Retry failed analysis with background task support."""
        try:
            # Validate analysis ID
            try:
                uuid.UUID(analysis_id)
            except ValueError:
                raise HTTPException(400, "Invalid analysis ID format")

            analysis = await self.get_analysis(analysis_id=analysis_id)

            if not analysis:
                raise HTTPException(404, "Analysis not found")

            if analysis.user_id != user_id:
                raise HTTPException(403, "Access denied")

            if analysis.processing_status != ProcessingStatus.FAILED:
                raise HTTPException(400, "Can only retry failed analyses")

            # Get original content
            content = analysis.metadata.get("original_content", "")
            if not content:
                raise HTTPException(400, "Original content not available for retry")

            # Determine if async processing needed
            should_process_async = (
                    background_tasks is not None and
                    (len(content) > 10000 or callback_url is not None)
            )

            if should_process_async:
                # Create retry task
                task_id = await self.add_background_task_with_tracking(
                    background_tasks=background_tasks,
                    task_func=self._retry_analysis_task,
                    task_type=TaskType.AI_ANALYSIS,
                    task_data={
                        "original_analysis_id": analysis_id,
                        "url": analysis.url,
                        "content_length": len(content)
                    },
                    user_id=user_id,
                    priority=TaskPriority.HIGH,
                    callback_url=callback_url,
                    # Task arguments
                    original_analysis_id=analysis_id,
                    url=analysis.url,
                    content=content,
                )

                return {
                    "task_id": task_id,
                    "status": "processing",
                    "message": "Analysis retry queued for processing",
                    "original_analysis_id": analysis_id
                }

            # Process retry synchronously
            new_analysis = await self.retry_analysis(
                analysis_id=analysis_id,
                user_id=user_id
            )

            return self._format_analysis_response(new_analysis)

        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Analysis retry failed: {str(e)}")
            raise HTTPException(500, "Analysis retry failed")

    async def _retry_analysis_task(
            self,
            task_id: str,
            original_analysis_id: str,
            url: str,
            content: str,
            user_id: int
    ) -> Dict[str, Any]:
        """Background task for analysis retry."""
        try:
            await self.update_task_progress(task_id, 20)

            async with self.get_db_session() as db:
                # Perform retry
                new_analysis = await self.retry_analysis(
                    analysis_id=original_analysis_id,
                    user_id=user_id,
                )

                await self.update_task_progress(task_id, 100)

                result = self._format_analysis_response(new_analysis)
                result["original_analysis_id"] = original_analysis_id

                return result

        except Exception as e:
            self.logger.error(f"Retry task {task_id} failed: {str(e)}")
            raise

    async def get_analysis(self, analysis_id: str) -> Optional[AIAnalysis]:
        """Get analysis by ID."""
        async with self.get_db_session() as db:
            # Use async ORM API instead of sync db.query
            
            stmt = select(AIAnalysis).where(AIAnalysis.id == analysis_id)
            result = await db.execute(stmt)
            return result.scalar_one_or_none()


    async def get_analysis_history(
            self,
            page: int = 1,
            page_size: int = 20,
            current_user: Optional[User] = None
    ) -> Dict[str, Any]:
        """Get user's analysis history."""
        if not current_user:
            raise HTTPException(401, "Authentication required")

        if page < 1 or not 1 <= page_size <= 100:
            raise HTTPException(400, "Invalid pagination parameters")

        async with self.get_db_session() as db:
            analyses, total_count = await self.ai_analysis_service.get_user_analysis_history(
                db=db,
                user_id=current_user.id,
                page=page,
                page_size=page_size
            )

            analysis_list = [self._format_analysis_response(analysis) for analysis in analyses]

            return {
                "analyses": analysis_list,
                "total_count": total_count,
                "page": page,
                "page_size": page_size,
                "has_next": (page * page_size) < total_count
            }

    async def find_similar_content(
            self,
            analysis_id: str,
            similarity_threshold: float = 0.7,
            limit: int = 10,
            current_user: Optional[User] = None
    ) -> Dict[str, Any]:
        """Find similar content."""
        try:
            uuid.UUID(analysis_id)
        except ValueError:
            raise HTTPException(400, "Invalid analysis ID format")

        if not 0.0 <= similarity_threshold <= 1.0:
            raise HTTPException(400, "Similarity threshold must be between 0.0 and 1.0")

        if not 1 <= limit <= 100:
            raise HTTPException(400, "Limit must be between 1 and 100")

        async with self.get_db_session() as db:
            similar_content = await self.ai_analysis_service.find_similar_content(
                db=db,
                analysis_id=analysis_id,
                similarity_threshold=similarity_threshold,
                limit=limit,
                user_id=current_user.id if current_user else None
            )

            results = []
            for similarity in similar_content:
                results.append({
                    "id": str(similarity.id),
                    "target_analysis": self._format_analysis_response(similarity.target_analysis),
                    "similarity_score": similarity.similarity_score,
                    "similarity_type": similarity.similarity_type,
                    "confidence_score": similarity.confidence_score,
                    "matching_elements": similarity.matching_elements
                })

            return {"similar_content": results}

    async def get_domain_stats(
            self,
            domain: str,
            current_user: Optional[User] = None
    ) -> Dict[str, Any]:
        """Get domain analysis statistics."""
        if not domain or not domain.strip():
            raise HTTPException(400, "Domain is required")

        async with self.get_db_session() as db:
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

    async def get_service_status(self) -> Dict[str, Any]:
        """Get AI service status."""
        try:
            await self.ai_analysis_service.initialize()
            status_info = await self.ai_analysis_service.get_service_status()

            return {
                "service_status": "healthy" if status_info.get("healthy", False) else "unhealthy",
                "models_loaded": status_info.get("models_loaded", False),
                "processing_queue_size": status_info.get("queue_size", 0),
                "last_health_check": status_info.get("last_check"),
                "version": status_info.get("version", "unknown")
            }
        except Exception as e:
            self.logger.error(f"Service status check failed: {e}")
            return {
                "service_status": "unhealthy",
                "models_loaded": False,
                "processing_queue_size": 0,
                "error": str(e)
            }

    async def _create_analysis_record(
            self,
            db: AsyncSession,
            url: str,
            content: str,
            user_id: Optional[int] = None,
            analysis_types: Optional[List[AnalysisType]] = None
    ) -> AIAnalysis:
        """Create analysis record."""
        content_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
        domain = urlparse(url).netloc if url else None

        analysis = AIAnalysis(
            user_id=user_id,
            url=url,
            content_hash=content_hash,
            domain=domain,
            content_length=len(content),
            processing_status=ProcessingStatus.PROCESSING,
            analysis_types=[at.value for at in analysis_types] if analysis_types else None,
            metadata={"original_content": content}  # Store for retries
        )

        db.add(analysis)
        # Commit handled by context manager
        await db.refresh(analysis)

        return analysis

    async def _update_analysis_with_results(
            self,
            db: AsyncSession,
            analysis: AIAnalysis,
            ai_results: Dict[str, Any]
    ) -> None:
        """Update analysis with AI results."""
        start_time = datetime.now(timezone.utc)

        try:
            processing_time = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)

            # Update analysis fields
            analysis.content_summary = ai_results.get('content_summary')

            quality_data = ai_results.get('quality_analysis', {})
            analysis.quality_metrics = quality_data
            analysis.overall_quality_score = quality_data.get('overall_score', 0)
            analysis.readability_score = quality_data.get('readability_score', 0)
            analysis.trustworthiness_score = quality_data.get('trustworthiness_score', 0)
            analysis.professionalism_score = quality_data.get('professionalism_score', 0)

            analysis.topic_categories = ai_results.get('topic_analysis')
            analysis.sentiment_analysis = ai_results.get('sentiment_analysis')
            analysis.seo_metrics = ai_results.get('seo_analysis')
            analysis.language = ai_results.get('language')
            analysis.reading_level = ai_results.get('reading_level')

            analysis.processing_time_ms = processing_time
            analysis.model_versions = ai_results.get('model_versions', {})
            analysis.processing_status = ProcessingStatus.COMPLETED
            analysis.processed_at = datetime.now(timezone.utc)

        except Exception as e:
            analysis.processing_status = ProcessingStatus.FAILED
            analysis.processed_at = datetime.now(timezone.utc)
            self.logger.error(f"Failed to update analysis: {e}")
            raise

    def _format_analysis_response(self, analysis: AIAnalysis) -> Dict[str, Any]:
        """Format analysis for API response."""
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