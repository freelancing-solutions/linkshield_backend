#!/usr/bin/env python3
"""
LinkShield Backend AI Analysis Service

Service for managing AI-powered content analysis with database integration.
Handles content analysis, quality scoring, and intelligent insights storage.
"""

import asyncio
import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, desc, func
from sqlalchemy.orm import selectinload

from src.models.ai_analysis import (
    AIAnalysis, 
    ContentSimilarity, 
    AIModelMetrics,
    ProcessingStatus,
    AnalysisType
)
from src.models.url_check import URLCheck
from src.models.user import User
from src.services.ai_service import AIService, AIServiceError
from src.config.settings import get_settings


class AIAnalysisService:
    """
    Service for AI-powered content analysis with database integration.
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.ai_service = AIService()
        self._initialized = False
    
    async def initialize(self) -> None:
        """
        Initialize the AI analysis service.
        """
        if not self._initialized:
            await self.ai_service.initialize_models()
            self._initialized = True
    
    def _generate_content_hash(self, content: str) -> str:
        """
        Generate SHA-256 hash for content deduplication.
        """
        return hashlib.sha256(content.encode('utf-8')).hexdigest()
    
    async def analyze_content(
        self,
        db: AsyncSession,
        url: str,
        content: str,
        user_id: Optional[str] = None,
        check_id: Optional[str] = None,
        analysis_types: Optional[List[AnalysisType]] = None
    ) -> AIAnalysis:
        """
        Perform comprehensive AI analysis on content and store results.
        
        Args:
            db: Database session
            url: URL being analyzed
            content: Content to analyze
            user_id: Optional user ID
            check_id: Optional URL check ID
            analysis_types: Specific analysis types to perform
        
        Returns:
            AIAnalysis: Analysis results
        """
        if not self._initialized:
            await self.initialize()
        
        # Generate content hash for deduplication
        content_hash = self._generate_content_hash(content)
        domain = urlparse(url).netloc
        
        # Check if analysis already exists
        existing_analysis = await self._get_existing_analysis(db, content_hash)
        if existing_analysis and existing_analysis.processing_status == ProcessingStatus.COMPLETED:
            # Update associations if needed
            if check_id and not existing_analysis.check_id:
                existing_analysis.check_id = check_id
            if user_id and not existing_analysis.user_id:
                existing_analysis.user_id = user_id
            await db.commit()
            return existing_analysis
        
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
        
        try:
            # Perform AI analysis
            start_time = datetime.now(timezone.utc)
            ai_results = await self.ai_service.analyze_content(content, url)
            processing_time = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
            
            # Extract and store analysis results
            await self._store_analysis_results(analysis, ai_results, processing_time)
            
            # Update status
            analysis.processing_status = ProcessingStatus.COMPLETED
            analysis.processed_at = datetime.now(timezone.utc)
            
            await db.commit()
            await db.refresh(analysis)
            
            # Update model metrics
            await self._update_model_metrics(db, ai_results, processing_time, success=True)
            
            return analysis
            
        except Exception as e:
            # Handle analysis failure
            analysis.processing_status = ProcessingStatus.FAILED
            analysis.error_message = str(e)
            analysis.retry_count += 1
            
            await db.commit()
            await self._update_model_metrics(db, {}, 0, success=False)
            
            raise AIServiceError(f"AI analysis failed: {str(e)}")
    
    async def _get_existing_analysis(self, db: AsyncSession, content_hash: str) -> Optional[AIAnalysis]:
        """
        Get existing analysis by content hash.
        """
        result = await db.execute(
            select(AIAnalysis).where(AIAnalysis.content_hash == content_hash)
        )
        return result.scalar_one_or_none()
    
    async def _store_analysis_results(self, analysis: AIAnalysis, ai_results: Dict[str, Any], processing_time: int) -> None:
        """
        Store AI analysis results in the database model.
        """
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
    
    async def find_similar_content(
        self,
        db: AsyncSession,
        analysis_id: str,
        similarity_threshold: float = 0.8,
        limit: int = 10
    ) -> List[ContentSimilarity]:
        """
        Find similar content based on analysis results.
        
        Args:
            db: Database session
            analysis_id: Source analysis ID
            similarity_threshold: Minimum similarity score
            limit: Maximum number of results
        
        Returns:
            List of similar content matches
        """
        # Get source analysis
        source_analysis = await db.get(AIAnalysis, analysis_id)
        if not source_analysis:
            return []
        
        # Find potential matches based on domain, topic, or quality score
        similar_analyses = await db.execute(
            select(AIAnalysis)
            .where(
                and_(
                    AIAnalysis.id != analysis_id,
                    AIAnalysis.processing_status == ProcessingStatus.COMPLETED,
                    or_(
                        AIAnalysis.domain == source_analysis.domain,
                        func.abs(AIAnalysis.overall_quality_score - source_analysis.overall_quality_score) < 20
                    )
                )
            )
            .limit(limit * 2)  # Get more candidates for similarity calculation
        )
        
        candidates = similar_analyses.scalars().all()
        similarities = []
        
        for candidate in candidates:
            # Calculate similarity score (simplified implementation)
            similarity_score = await self._calculate_similarity(
                source_analysis, candidate
            )
            
            if similarity_score >= similarity_threshold:
                # Create or update similarity record
                similarity = ContentSimilarity(
                    source_analysis_id=analysis_id,
                    target_analysis_id=str(candidate.id),
                    similarity_score=similarity_score,
                    similarity_type="semantic",
                    confidence_score=int(similarity_score * 100),
                    algorithm_version="1.0"
                )
                
                db.add(similarity)
                similarities.append(similarity)
        
        await db.commit()
        return similarities[:limit]
    
    async def _calculate_similarity(self, analysis1: AIAnalysis, analysis2: AIAnalysis) -> float:
        """
        Calculate similarity score between two analyses.
        
        This is a simplified implementation. In production, you would use
        vector embeddings and cosine similarity.
        """
        score = 0.0
        factors = 0
        
        # Domain similarity
        if analysis1.domain == analysis2.domain:
            score += 0.3
        factors += 1
        
        # Quality score similarity
        if analysis1.overall_quality_score and analysis2.overall_quality_score:
            quality_diff = abs(analysis1.overall_quality_score - analysis2.overall_quality_score)
            quality_similarity = max(0, 1 - (quality_diff / 100))
            score += quality_similarity * 0.2
        factors += 1
        
        # Language similarity
        if analysis1.language == analysis2.language:
            score += 0.1
        factors += 1
        
        # Topic similarity (simplified)
        if analysis1.topic_categories and analysis2.topic_categories:
            # This would be more sophisticated with actual topic vectors
            score += 0.4
        factors += 1
        
        return score / factors if factors > 0 else 0.0
    
    async def get_user_analysis_history(
        self,
        db: AsyncSession,
        user_id: str,
        limit: int = 50,
        offset: int = 0
    ) -> List[AIAnalysis]:
        """
        Get user's AI analysis history.
        """
        result = await db.execute(
            select(AIAnalysis)
            .where(AIAnalysis.user_id == user_id)
            .order_by(desc(AIAnalysis.created_at))
            .limit(limit)
            .offset(offset)
        )
        return result.scalars().all()
    
    async def get_domain_analysis_stats(
        self,
        db: AsyncSession,
        domain: str
    ) -> Dict[str, Any]:
        """
        Get analysis statistics for a domain.
        """
        result = await db.execute(
            select(
                func.count(AIAnalysis.id).label('total_analyses'),
                func.avg(AIAnalysis.overall_quality_score).label('avg_quality'),
                func.avg(AIAnalysis.trustworthiness_score).label('avg_trustworthiness'),
                func.count(
                    AIAnalysis.id.filter(AIAnalysis.processing_status == ProcessingStatus.COMPLETED)
                ).label('completed_analyses')
            )
            .where(AIAnalysis.domain == domain)
        )
        
        stats = result.first()
        
        return {
            'domain': domain,
            'total_analyses': stats.total_analyses or 0,
            'avg_quality_score': float(stats.avg_quality or 0),
            'avg_trustworthiness_score': float(stats.avg_trustworthiness or 0),
            'completed_analyses': stats.completed_analyses or 0,
            'success_rate': (stats.completed_analyses / stats.total_analyses * 100) if stats.total_analyses else 0
        }
    
    async def _update_model_metrics(
        self,
        db: AsyncSession,
        ai_results: Dict[str, Any],
        processing_time: int,
        success: bool
    ) -> None:
        """
        Update AI model performance metrics.
        """
        # This would track metrics for different models used
        # Implementation depends on specific model tracking requirements
        pass
    
    async def retry_failed_analysis(
        self,
        db: AsyncSession,
        analysis_id: str
    ) -> AIAnalysis:
        """
        Retry a failed AI analysis.
        """
        analysis = await db.get(AIAnalysis, analysis_id)
        if not analysis or analysis.processing_status != ProcessingStatus.FAILED:
            raise ValueError("Analysis not found or not in failed state")
        
        if analysis.retry_count >= 3:
            raise ValueError("Maximum retry attempts exceeded")
        
        # Reset status and retry
        analysis.processing_status = ProcessingStatus.PENDING
        analysis.error_message = None
        
        await db.commit()
        
        # Re-analyze (this would need the original content)
        # For now, just update the status
        return analysis