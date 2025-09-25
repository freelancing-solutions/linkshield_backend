#!/usr/bin/env python3
"""
Sentiment Analyzer for Social Media Content

Analyzes sentiment of mentions and content across social platforms
to detect reputation risks and brand perception changes.
"""

import asyncio
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from src.services.ai_service import AIService


@dataclass
class SentimentResult:
    """Sentiment analysis result"""
    content: str
    sentiment: str  # positive, negative, neutral
    confidence: float
    emotion: Optional[str]
    threat_level: str  # low, medium, high, critical
    keywords: List[str]
    timestamp: datetime


class SentimentAnalyzer:
    """
    Advanced sentiment analysis for social media content and brand mentions.
    """

    def __init__(self, ai_service: Optional[AIService] = None):
        self.ai_service = ai_service
        
        # Sentiment thresholds
        self.thresholds = {
            "negative_critical": 0.9,
            "negative_high": 0.7,
            "negative_medium": 0.5,
            "positive_threshold": 0.6
        }
        
        # Emotion keywords
        self.emotion_keywords = {
            "anger": ["angry", "furious", "outraged", "mad", "hate", "disgusted"],
            "frustration": ["frustrated", "annoyed", "irritated", "fed up"],
            "disappointment": ["disappointed", "let down", "failed", "terrible"],
            "fear": ["scared", "worried", "concerned", "afraid", "anxious"],
            "joy": ["happy", "excited", "thrilled", "amazing", "love"],
            "satisfaction": ["satisfied", "pleased", "good", "great", "excellent"]
        }

    async def analyze_sentiment(self, content: str, context: Optional[Dict] = None) -> SentimentResult:
        """
        Comprehensive sentiment analysis for social media content.
        
        Args:
            content: Text content to analyze
            context: Additional context (platform, author, etc.)
        
        Returns:
            SentimentResult with detailed analysis
        """
        try:
            # Use AI service for sentiment analysis
            if self.ai_service:
                ai_result = await self.ai_service._analyze_sentiment(content)
                sentiment = ai_result.get("sentiment", "neutral")
                confidence = ai_result.get("confidence", 0.5)
            else:
                # Fallback analysis
                sentiment, confidence = self._basic_sentiment_analysis(content)
            
            # Detect emotions
            emotion = self._detect_emotion(content)
            
            # Extract keywords
            keywords = self._extract_keywords(content)
            
            # Calculate threat level
            threat_level = self._calculate_threat_level(sentiment, confidence, emotion, keywords)
            
            return SentimentResult(
                content=content,
                sentiment=sentiment,
                confidence=confidence,
                emotion=emotion,
                threat_level=threat_level,
                keywords=keywords,
                timestamp=datetime.now(timezone.utc)
            )
            
        except Exception as e:
            # Return neutral result on error
            return SentimentResult(
                content=content,
                sentiment="neutral",
                confidence=0.0,
                emotion=None,
                threat_level="low",
                keywords=[],
                timestamp=datetime.now(timezone.utc)
            )

    async def analyze_batch(self, contents: List[str]) -> List[SentimentResult]:
        """
        Analyze sentiment for multiple content pieces in batch.
        """
        tasks = [self.analyze_sentiment(content) for content in contents]
        return await asyncio.gather(*tasks, return_exceptions=True)

    async def analyze_trend(self, results: List[SentimentResult], timeframe_hours: int = 24) -> Dict[str, Any]:
        """
        Analyze sentiment trends over time to detect reputation changes.
        """
        if not results:
            return {"trend": "stable", "risk_level": "low", "change_rate": 0}
        
        # Sort by timestamp
        sorted_results = sorted(results, key=lambda x: x.timestamp)
        
        # Calculate sentiment scores
        sentiment_scores = []
        for result in sorted_results:
            score = self._sentiment_to_score(result.sentiment, result.confidence)
            sentiment_scores.append(score)
        
        # Calculate trend
        if len(sentiment_scores) < 2:
            return {"trend": "insufficient_data", "risk_level": "low", "change_rate": 0}
        
        # Simple trend calculation
        early_avg = sum(sentiment_scores[:len(sentiment_scores)//2]) / (len(sentiment_scores)//2)
        late_avg = sum(sentiment_scores[len(sentiment_scores)//2:]) / (len(sentiment_scores) - len(sentiment_scores)//2)
        
        change_rate = late_avg - early_avg
        
        # Determine trend and risk
        if change_rate < -0.3:
            trend = "declining"
            risk_level = "high" if change_rate < -0.5 else "medium"
        elif change_rate > 0.3:
            trend = "improving"
            risk_level = "low"
        else:
            trend = "stable"
            risk_level = "low"
        
        # Count negative sentiments in recent period
        recent_negative = sum(1 for r in sorted_results[-10:] if r.sentiment == "negative")
        if recent_negative > 7:
            risk_level = "critical"
        
        return {
            "trend": trend,
            "risk_level": risk_level,
            "change_rate": change_rate,
            "total_analyzed": len(results),
            "recent_negative_count": recent_negative,
            "average_confidence": sum(r.confidence for r in results) / len(results)
        }

    def _basic_sentiment_analysis(self, content: str) -> tuple[str, float]:
        """
        Fallback sentiment analysis using keyword matching.
        """
        content_lower = content.lower()
        
        positive_words = [
            "good", "great", "excellent", "amazing", "wonderful", "fantastic", 
            "love", "like", "enjoy", "happy", "satisfied", "perfect", "awesome"
        ]
        
        negative_words = [
            "bad", "terrible", "awful", "horrible", "hate", "dislike", 
            "angry", "frustrated", "disappointed", "worst", "failed", "useless"
        ]
        
        positive_count = sum(1 for word in positive_words if word in content_lower)
        negative_count = sum(1 for word in negative_words if word in content_lower)
        
        if negative_count > positive_count and negative_count > 0:
            confidence = min(0.8, negative_count / 5)
            return "negative", confidence
        elif positive_count > negative_count and positive_count > 0:
            confidence = min(0.8, positive_count / 5)
            return "positive", confidence
        else:
            return "neutral", 0.5

    def _detect_emotion(self, content: str) -> Optional[str]:
        """
        Detect primary emotion in content.
        """
        content_lower = content.lower()
        emotion_scores = {}
        
        for emotion, keywords in self.emotion_keywords.items():
            score = sum(1 for keyword in keywords if keyword in content_lower)
            if score > 0:
                emotion_scores[emotion] = score
        
        if not emotion_scores:
            return None
        
        return max(emotion_scores.items(), key=lambda x: x[1])[0]

    def _extract_keywords(self, content: str) -> List[str]:
        """
        Extract relevant keywords from content.
        """
        # Simple keyword extraction
        words = content.lower().split()
        
        # Filter out common words and short words
        stop_words = {"the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for", "of", "with", "by", "is", "are", "was", "were"}
        keywords = [word.strip(".,!?;:") for word in words 
                   if len(word) > 3 and word not in stop_words]
        
        # Return unique keywords, limited to top 10
        return list(dict.fromkeys(keywords))[:10]

    def _calculate_threat_level(self, sentiment: str, confidence: float, emotion: Optional[str], keywords: List[str]) -> str:
        """
        Calculate threat level based on sentiment analysis results.
        """
        if sentiment == "negative":
            if confidence >= self.thresholds["negative_critical"]:
                return "critical"
            elif confidence >= self.thresholds["negative_high"]:
                return "high"
            elif confidence >= self.thresholds["negative_medium"]:
                return "medium"
            else:
                return "low"
        
        # Check for high-risk emotions
        if emotion in ["anger", "frustration"] and confidence > 0.6:
            return "high"
        
        # Check for reputation-damaging keywords
        damage_keywords = ["scam", "fraud", "fake", "lie", "cheat", "steal", "illegal"]
        if any(keyword in keywords for keyword in damage_keywords):
            return "high"
        
        return "low"

    def _sentiment_to_score(self, sentiment: str, confidence: float) -> float:
        """
        Convert sentiment to numeric score for trend analysis.
        """
        base_scores = {"positive": 1.0, "neutral": 0.0, "negative": -1.0}
        return base_scores.get(sentiment, 0.0) * confidence