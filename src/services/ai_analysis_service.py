#!/usr/bin/env python3
"""
LinkShield Backend AI Analysis Service

Pure AI analysis service for content processing and quality scoring.
Database operations are handled by controllers.
"""

import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

from src.config.settings import get_settings
from src.models.ai_analysis import (
    ProcessingStatus,
    AnalysisType
)
from src.services.ai_service import AIService, AIServiceError

class AIAnalysisException(HTTPException):
    def __init__(self, status_code: int, detail: str):
        super().__init__(status_code=status_code, detail=detail)


class AIAnalysisService:
    """
    Pure AI analysis service for content processing and quality scoring.
    Database operations are handled by controllers.
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
        url: str,
        content: str,
        analysis_types: Optional[List[AnalysisType]] = None
    ) -> Dict[str, Any]:
        """
        Perform comprehensive AI analysis on content and return results.
        Database operations are handled by controllers.
        
        Args:
            url: URL being analyzed
            content: Content to analyze
            analysis_types: Specific analysis types to perform
        
        Returns:
            Dict containing analysis results and metadata
        """
        if not self._initialized:
            await self.initialize()
        
        # Generate content hash for deduplication
        content_hash = self._generate_content_hash(content)
        domain = urlparse(url).netloc
        
        try:
            # Perform AI analysis
            start_time = datetime.now(timezone.utc)
            ai_results = await self.ai_service.analyze_content(content, url)
            processing_time = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
            
            # Return structured analysis data
            return {
                "content_hash": content_hash,
                "domain": domain,
                "content_length": len(content),
                "processing_status": ProcessingStatus.COMPLETED.value,
                "processing_time_ms": processing_time,
                "processed_at": datetime.now(timezone.utc).isoformat(),
                "analysis_types": [at.value for at in analysis_types] if analysis_types else None,
                "ai_results": ai_results,
                "content_summary": ai_results.get('content_summary'),
                "quality_metrics": ai_results.get('quality_analysis', {}),
                "overall_quality_score": ai_results.get('quality_analysis', {}).get('overall_score', 0),
                "readability_score": ai_results.get('quality_analysis', {}).get('readability_score', 0),
                "trustworthiness_score": ai_results.get('quality_analysis', {}).get('trustworthiness_score', 0),
                "professionalism_score": ai_results.get('quality_analysis', {}).get('professionalism_score', 0),
                "topic_categories": ai_results.get('topic_analysis'),
                "sentiment_analysis": ai_results.get('sentiment_analysis'),
                "seo_metrics": ai_results.get('seo_analysis'),
                "language": ai_results.get('language'),
                "model_versions": ai_results.get('model_versions', {})
            }
            
        except Exception as e:
            # Return error data
            return {
                "content_hash": content_hash,
                "domain": domain,
                "content_length": len(content),
                "processing_status": ProcessingStatus.FAILED.value,
                "error_message": str(e),
                "processed_at": datetime.now(timezone.utc).isoformat()
            }
    
    def calculate_similarity(self, analysis1_data: Dict[str, Any], analysis2_data: Dict[str, Any]) -> float:
        """
        Calculate similarity score between two analysis data sets.
        
        This is a simplified implementation. In production, you would use
        vector embeddings and cosine similarity.
        """
        score = 0.0
        factors = 0
        
        # Domain similarity
        if analysis1_data.get("domain") == analysis2_data.get("domain"):
            score += 0.3
        factors += 1
        
        # Quality score similarity
        quality1 = analysis1_data.get("overall_quality_score", 0)
        quality2 = analysis2_data.get("overall_quality_score", 0)
        if quality1 and quality2:
            quality_diff = abs(quality1 - quality2)
            quality_similarity = max(0, 1 - (quality_diff / 100))
            score += quality_similarity * 0.2
        factors += 1
        
        # Language similarity
        if analysis1_data.get("language") == analysis2_data.get("language"):
            score += 0.1
        factors += 1
        
        # Topic similarity (simplified)
        if analysis1_data.get("topic_categories") and analysis2_data.get("topic_categories"):
            # This would be more sophisticated with actual topic vectors
            score += 0.4
        factors += 1
        
        return score / factors if factors > 0 else 0.0
    
    def process_analysis_metrics(self, analysis_data_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Process analysis metrics from a list of analysis data.
        
        Args:
            analysis_data_list: List of analysis data dictionaries
            
        Returns:
            Aggregated metrics
        """
        if not analysis_data_list:
            return {
                'total_analyses': 0,
                'avg_quality_score': 0,
                'avg_trustworthiness_score': 0,
                'completed_analyses': 0,
                'success_rate': 0
            }
        
        total_analyses = len(analysis_data_list)
        completed_analyses = sum(1 for data in analysis_data_list 
                               if data.get('processing_status') == ProcessingStatus.COMPLETED.value)
        
        quality_scores = [data.get('overall_quality_score', 0) 
                         for data in analysis_data_list 
                         if data.get('overall_quality_score')]
        
        trustworthiness_scores = [data.get('trustworthiness_score', 0) 
                                for data in analysis_data_list 
                                if data.get('trustworthiness_score')]
        
        return {
            'total_analyses': total_analyses,
            'avg_quality_score': sum(quality_scores) / len(quality_scores) if quality_scores else 0,
            'avg_trustworthiness_score': sum(trustworthiness_scores) / len(trustworthiness_scores) if trustworthiness_scores else 0,
            'completed_analyses': completed_analyses,
            'success_rate': (completed_analyses / total_analyses * 100) if total_analyses else 0
        }
    
    def format_similarity_data(
        self,
        source_analysis_id: str,
        target_analysis_id: str,
        similarity_score: float,
        similarity_type: str = "semantic",
        algorithm_version: str = "1.0"
    ) -> Dict[str, Any]:
        """
        Format similarity data for storage.
        
        Args:
            source_analysis_id: Source analysis ID
            target_analysis_id: Target analysis ID
            similarity_score: Calculated similarity score
            similarity_type: Type of similarity calculation
            algorithm_version: Version of similarity algorithm
            
        Returns:
            Formatted similarity data
        """
        return {
            "source_analysis_id": source_analysis_id,
            "target_analysis_id": target_analysis_id,
            "similarity_score": similarity_score,
            "similarity_type": similarity_type,
            "confidence_score": int(similarity_score * 100),
            "algorithm_version": algorithm_version,
            "created_at": datetime.now(timezone.utc).isoformat()
        }