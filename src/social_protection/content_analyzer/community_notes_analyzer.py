#!/usr/bin/env python3
"""
Community Notes Analyzer for Social Media Protection.

This module provides specialized analysis for content that might trigger
Community Notes or fact-checking mechanisms on social media platforms.
"""

import re
import asyncio
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass
from datetime import datetime, timezone
from collections import Counter

from src.services.ai_service import AIService
from src.config.settings import get_settings


@dataclass
class CommunityNotesResult:
    """Result of Community Notes trigger analysis."""
    trigger_risk: bool
    risk_score: int  # 0-100
    trigger_factors: List[str]
    content_categories: List[str]
    recommendations: List[str]
    fact_check_likelihood: float  # 0.0-1.0
    misinformation_indicators: List[str]
    confidence_score: float  # 0.0-1.0
    analysis_timestamp: str


class CommunityNotesAnalyzer:
    """
    Analyzes content for potential Community Notes triggers.
    
    This analyzer identifies content patterns that commonly trigger
    fact-checking mechanisms, Community Notes, or similar crowdsourced
    verification systems on social media platforms.
    """
    
    def __init__(self, ai_service: AIService):
        self.ai_service = ai_service
        self.settings = get_settings()
        
        # Community Notes trigger patterns
        self.trigger_patterns = {
            "health_misinformation": [
                r"cure\s+for\s+\w+",
                r"doctors\s+don't\s+want\s+you\s+to\s+know",
                r"big\s+pharma\s+conspiracy",
                r"natural\s+remedy\s+that\s+works",
                r"miracle\s+cure",
                r"government\s+hiding\s+cure"
            ],
            "election_claims": [
                r"election\s+was\s+stolen",
                r"voter\s+fraud",
                r"rigged\s+election",
                r"fake\s+ballots",
                r"dead\s+people\s+voting"
            ],
            "conspiracy_theories": [
                r"deep\s+state",
                r"shadow\s+government",
                r"false\s+flag",
                r"crisis\s+actors",
                r"cover\s+up",
                r"they\s+don't\s+want\s+you\s+to\s+know"
            ],
            "financial_scams": [
                r"guaranteed\s+returns",
                r"get\s+rich\s+quick",
                r"investment\s+opportunity",
                r"limited\s+time\s+offer",
                r"insider\s+information",
                r"secret\s+method"
            ],
            "false_statistics": [
                r"\d+%\s+of\s+\w+\s+are",
                r"studies\s+show",
                r"research\s+proves",
                r"scientists\s+discovered",
                r"new\s+study\s+reveals"
            ]
        }
        
        # Misinformation indicators
        self.misinformation_indicators = [
            "mainstream media won't tell you",
            "they're trying to silence",
            "wake up people",
            "do your own research",
            "question everything",
            "the truth is out there",
            "open your eyes",
            "sheep mentality"
        ]
        
        # Fact-check trigger words
        self.fact_check_triggers = [
            "breaking news",
            "exclusive report",
            "leaked documents",
            "insider reveals",
            "shocking truth",
            "exposed",
            "bombshell",
            "whistleblower"
        ]

    async def analyze_community_notes_risk(
        self,
        content: str,
        platform: str = "twitter",
        metadata: Optional[Dict[str, Any]] = None
    ) -> CommunityNotesResult:
        """
        Analyze content for Community Notes trigger risk.
        
        Args:
            content: The content text to analyze
            platform: Social media platform name
            metadata: Additional content metadata
            
        Returns:
            CommunityNotesResult with trigger risk analysis
        """
        try:
            content_lower = content.lower()
            
            # Initialize analysis results
            trigger_factors = []
            content_categories = []
            misinformation_indicators = []
            recommendations = []
            
            # Check for trigger patterns by category
            for category, patterns in self.trigger_patterns.items():
                category_matches = 0
                for pattern in patterns:
                    if re.search(pattern, content_lower):
                        category_matches += 1
                        trigger_factors.append(f"{category}: {pattern}")
                
                if category_matches > 0:
                    content_categories.append(category)
                    if category_matches >= 2:
                        recommendations.append(f"High risk for {category} fact-checking")
            
            # Check for misinformation indicators
            for indicator in self.misinformation_indicators:
                if indicator in content_lower:
                    misinformation_indicators.append(indicator)
                    trigger_factors.append(f"misinformation_indicator: {indicator}")
            
            # Check for fact-check triggers
            fact_check_score = 0
            for trigger in self.fact_check_triggers:
                if trigger in content_lower:
                    fact_check_score += 1
                    trigger_factors.append(f"fact_check_trigger: {trigger}")
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(
                len(content_categories),
                len(misinformation_indicators),
                fact_check_score,
                len(trigger_factors)
            )
            
            # Determine if there's trigger risk
            trigger_risk = risk_score >= 40
            
            # Calculate fact-check likelihood
            fact_check_likelihood = min(1.0, (risk_score / 100) * 1.2)
            
            # Generate recommendations
            if not recommendations:
                if risk_score >= 60:
                    recommendations.append("High risk - consider revising content")
                elif risk_score >= 40:
                    recommendations.append("Medium risk - review for accuracy")
                else:
                    recommendations.append("Low risk - content appears safe")
            
            # Add specific recommendations based on categories
            if "health_misinformation" in content_categories:
                recommendations.append("Verify health claims with credible sources")
            if "election_claims" in content_categories:
                recommendations.append("Ensure election information is from official sources")
            if "conspiracy_theories" in content_categories:
                recommendations.append("Consider providing credible sources for claims")
            if "financial_scams" in content_categories:
                recommendations.append("Avoid investment advice without proper disclaimers")
            
            # Calculate confidence score
            confidence_score = self._calculate_confidence_score(
                len(trigger_factors),
                len(content_categories),
                len(misinformation_indicators)
            )
            
            return CommunityNotesResult(
                trigger_risk=trigger_risk,
                risk_score=risk_score,
                trigger_factors=trigger_factors,
                content_categories=content_categories,
                recommendations=recommendations,
                fact_check_likelihood=fact_check_likelihood,
                misinformation_indicators=misinformation_indicators,
                confidence_score=confidence_score,
                analysis_timestamp=datetime.now(timezone.utc).isoformat()
            )
            
        except Exception as e:
            # Return safe default result on error
            return CommunityNotesResult(
                trigger_risk=False,
                risk_score=0,
                trigger_factors=[],
                content_categories=[],
                recommendations=["Error in analysis - manual review recommended"],
                fact_check_likelihood=0.0,
                misinformation_indicators=[],
                confidence_score=0.0,
                analysis_timestamp=datetime.now(timezone.utc).isoformat()
            )

    def _calculate_risk_score(
        self,
        category_count: int,
        misinfo_count: int,
        fact_check_count: int,
        total_factors: int
    ) -> int:
        """Calculate overall risk score for Community Notes triggers."""
        score = 0
        
        # Base score from categories
        score += category_count * 25
        
        # Additional score from misinformation indicators
        score += misinfo_count * 15
        
        # Fact-check trigger bonus
        score += fact_check_count * 10
        
        # Total factors bonus
        score += min(20, total_factors * 2)
        
        return min(100, score)

    def _calculate_confidence_score(
        self,
        factor_count: int,
        category_count: int,
        misinfo_count: int
    ) -> float:
        """Calculate confidence score for the analysis."""
        # Base confidence
        confidence = 0.6
        
        # Increase confidence with more detected patterns
        if factor_count > 0:
            confidence += min(0.3, factor_count * 0.05)
        
        # High confidence for multiple categories
        if category_count > 1:
            confidence += 0.15
        
        # High confidence for misinformation indicators
        if misinfo_count > 0:
            confidence += min(0.2, misinfo_count * 0.1)
        
        return round(min(0.95, confidence), 2)

    async def analyze_batch_content(
        self,
        content_items: List[Dict[str, Any]]
    ) -> List[CommunityNotesResult]:
        """
        Analyze multiple content items for Community Notes risk.
        
        Args:
            content_items: List of content dictionaries
            
        Returns:
            List of CommunityNotesResult objects
        """
        tasks = []
        for item in content_items:
            task = self.analyze_community_notes_risk(
                content=item["content"],
                platform=item.get("platform", "twitter"),
                metadata=item.get("metadata")
            )
            tasks.append(task)
            
        return await asyncio.gather(*tasks)

    def get_risk_summary(self, results: List[CommunityNotesResult]) -> Dict[str, Any]:
        """
        Generate summary statistics for Community Notes risk analysis.
        
        Args:
            results: List of CommunityNotesResult objects
            
        Returns:
            Dictionary with summary statistics
        """
        if not results:
            return {}
            
        total_items = len(results)
        high_risk_items = sum(1 for r in results if r.risk_score >= 60)
        medium_risk_items = sum(1 for r in results if 40 <= r.risk_score < 60)
        low_risk_items = sum(1 for r in results if r.risk_score < 40)
        
        # Category distribution
        all_categories = []
        for result in results:
            all_categories.extend(result.content_categories)
        category_counts = Counter(all_categories)
        
        # Average scores
        avg_risk_score = sum(r.risk_score for r in results) / total_items
        avg_fact_check_likelihood = sum(r.fact_check_likelihood for r in results) / total_items
        
        return {
            "total_items": total_items,
            "risk_distribution": {
                "high_risk": high_risk_items,
                "medium_risk": medium_risk_items,
                "low_risk": low_risk_items
            },
            "average_risk_score": round(avg_risk_score, 2),
            "average_fact_check_likelihood": round(avg_fact_check_likelihood, 2),
            "category_distribution": dict(category_counts),
            "items_with_triggers": sum(1 for r in results if r.trigger_risk),
            "trigger_rate": sum(1 for r in results if r.trigger_risk) / total_items
        }

    async def get_content_recommendations(
        self,
        content: str,
        risk_result: CommunityNotesResult
    ) -> List[str]:
        """
        Get specific recommendations for improving content to reduce Community Notes risk.
        
        Args:
            content: Original content
            risk_result: Analysis result
            
        Returns:
            List of specific recommendations
        """
        recommendations = []
        
        if risk_result.risk_score >= 80:
            recommendations.append("Consider completely rewriting this content")
            recommendations.append("Verify all claims with multiple credible sources")
        elif risk_result.risk_score >= 60:
            recommendations.append("Significant revision needed to reduce fact-check risk")
            recommendations.append("Add credible sources to support claims")
        elif risk_result.risk_score >= 40:
            recommendations.append("Minor revisions recommended")
            recommendations.append("Consider adding context or disclaimers")
        
        # Category-specific recommendations
        for category in risk_result.content_categories:
            if category == "health_misinformation":
                recommendations.append("Consult medical professionals for health claims")
                recommendations.append("Include disclaimers about medical advice")
            elif category == "election_claims":
                recommendations.append("Use only official election sources")
                recommendations.append("Avoid unverified election information")
            elif category == "conspiracy_theories":
                recommendations.append("Focus on verifiable facts")
                recommendations.append("Avoid speculative language")
            elif category == "financial_scams":
                recommendations.append("Include proper financial disclaimers")
                recommendations.append("Avoid guarantees about returns")
        
        return recommendations