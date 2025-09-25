#!/usr/bin/env python3
"""
Brand Monitor - Comprehensive Brand Reputation Monitoring

Monitors brand mentions, sentiment, and reputation across social platforms
with real-time alerts and trend analysis.
"""

import asyncio
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict

from .mention_detector import MentionDetector, Mention
from .sentiment_analyzer import SentimentAnalyzer, SentimentResult


@dataclass
class BrandAlert:
    """Brand monitoring alert"""
    alert_type: str  # mention_spike, negative_sentiment, crisis, trend_change
    severity: str    # low, medium, high, critical
    brand: str
    message: str
    data: Dict[str, Any]
    timestamp: datetime
    resolved: bool = False


@dataclass
class BrandMetrics:
    """Brand performance metrics"""
    total_mentions: int
    positive_mentions: int
    negative_mentions: int
    neutral_mentions: int
    sentiment_score: float
    trend: str
    risk_level: str
    top_platforms: List[str]
    timestamp: datetime


class BrandMonitor:
    """
    Comprehensive brand monitoring system with real-time analysis.
    """

    def __init__(self, mention_detector: Optional[MentionDetector] = None, 
                 sentiment_analyzer: Optional[SentimentAnalyzer] = None):
        self.mention_detector = mention_detector or MentionDetector()
        self.sentiment_analyzer = sentiment_analyzer or SentimentAnalyzer()
        
        # Monitoring configuration
        self.monitored_brands = {}
        self.alert_thresholds = {
            "mention_spike_multiplier": 3.0,  # 3x normal volume
            "negative_sentiment_threshold": 0.7,
            "crisis_keywords": ["scandal", "lawsuit", "investigation", "breach", "hack", "fraud"],
            "volume_window_hours": 24
        }
        
        # Data storage (in production, use proper database)
        self.mention_history = defaultdict(list)
        self.sentiment_history = defaultdict(list)
        self.alerts = []
        
        # Analysis cache
        self.baseline_metrics = {}
        self.current_metrics = {}

    def configure_brand_monitoring(self, brand_config: Dict[str, Dict[str, Any]]) -> None:
        """
        Configure brands for monitoring.
        
        Args:
            brand_config: Brand configuration with monitoring settings
        """
        self.monitored_brands = brand_config
        self.mention_detector.configure_brands(brand_config)

    async def monitor_content(self, content: str, platform: str, metadata: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Monitor content for brand mentions and sentiment.
        
        Args:
            content: Content to monitor
            platform: Source platform
            metadata: Additional metadata (author, timestamp, etc.)
        
        Returns:
            Monitoring results with mentions, sentiment, and alerts
        """
        results = {
            "mentions": [],
            "sentiment_analysis": [],
            "alerts": [],
            "metrics_updated": False
        }
        
        # Detect mentions
        mentions = await self.mention_detector.detect_mentions(content, platform)
        results["mentions"] = [asdict(mention) for mention in mentions]
        
        if not mentions:
            return results
        
        # Analyze sentiment for each mention
        sentiment_results = []
        for mention in mentions:
            sentiment = await self.sentiment_analyzer.analyze_sentiment(
                mention.sentiment_context, 
                {"platform": platform, "mention_type": mention.mention_type}
            )
            sentiment_results.append(sentiment)
            results["sentiment_analysis"].append(asdict(sentiment))
        
        # Store historical data
        timestamp = datetime.now(timezone.utc)
        for mention in mentions:
            self.mention_history[mention.matched_term].append({
                "mention": mention,
                "timestamp": timestamp,
                "platform": platform
            })
        
        for sentiment in sentiment_results:
            brand_key = mentions[sentiment_results.index(sentiment)].matched_term
            self.sentiment_history[brand_key].append(sentiment)
        
        # Check for alerts
        alerts = await self._check_alerts(mentions, sentiment_results, platform)
        results["alerts"] = [asdict(alert) for alert in alerts]
        
        # Update metrics
        if mentions:
            await self._update_brand_metrics()
            results["metrics_updated"] = True
        
        return results

    async def get_brand_metrics(self, brand: str, timeframe_hours: int = 24) -> Optional[BrandMetrics]:
        """
        Get comprehensive metrics for a specific brand.
        """
        if brand not in self.monitored_brands:
            return None
        
        # Get recent mentions and sentiment
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=timeframe_hours)
        
        recent_mentions = [
            entry for entry in self.mention_history[brand]
            if entry["timestamp"] > cutoff_time
        ]
        
        recent_sentiment = [
            sentiment for sentiment in self.sentiment_history[brand]
            if sentiment.timestamp > cutoff_time
        ]
        
        if not recent_mentions:
            return BrandMetrics(
                total_mentions=0,
                positive_mentions=0,
                negative_mentions=0,
                neutral_mentions=0,
                sentiment_score=0.5,
                trend="stable",
                risk_level="low",
                top_platforms=[],
                timestamp=datetime.now(timezone.utc)
            )
        
        # Calculate metrics
        total_mentions = len(recent_mentions)
        
        sentiment_counts = {"positive": 0, "negative": 0, "neutral": 0}
        sentiment_scores = []
        
        for sentiment in recent_sentiment:
            sentiment_counts[sentiment.sentiment] += 1
            score = self._sentiment_to_numeric(sentiment.sentiment, sentiment.confidence)
            sentiment_scores.append(score)
        
        avg_sentiment = sum(sentiment_scores) / len(sentiment_scores) if sentiment_scores else 0.5
        
        # Platform analysis
        platform_counts = defaultdict(int)
        for mention_entry in recent_mentions:
            platform_counts[mention_entry["platform"]] += 1
        
        top_platforms = sorted(platform_counts.items(), key=lambda x: x[1], reverse=True)
        top_platforms = [platform for platform, count in top_platforms[:3]]
        
        # Trend analysis
        trend_analysis = await self.sentiment_analyzer.analyze_trend(recent_sentiment, timeframe_hours)
        
        return BrandMetrics(
            total_mentions=total_mentions,
            positive_mentions=sentiment_counts["positive"],
            negative_mentions=sentiment_counts["negative"],
            neutral_mentions=sentiment_counts["neutral"],
            sentiment_score=avg_sentiment,
            trend=trend_analysis.get("trend", "stable"),
            risk_level=trend_analysis.get("risk_level", "low"),
            top_platforms=top_platforms,
            timestamp=datetime.now(timezone.utc)
        )

    async def get_active_alerts(self, severity_filter: Optional[str] = None) -> List[BrandAlert]:
        """
        Get active (unresolved) alerts, optionally filtered by severity.
        """
        active_alerts = [alert for alert in self.alerts if not alert.resolved]
        
        if severity_filter:
            active_alerts = [alert for alert in active_alerts if alert.severity == severity_filter]
        
        return sorted(active_alerts, key=lambda x: x.timestamp, reverse=True)

    async def resolve_alert(self, alert_timestamp: datetime) -> bool:
        """
        Mark an alert as resolved.
        """
        for alert in self.alerts:
            if alert.timestamp == alert_timestamp:
                alert.resolved = True
                return True
        return False

    async def _check_alerts(self, mentions: List[Mention], sentiment_results: List[SentimentResult], platform: str) -> List[BrandAlert]:
        """
        Check for various alert conditions.
        """
        alerts = []
        
        # Check for mention spikes
        spike_alerts = await self._check_mention_spikes(mentions, platform)
        alerts.extend(spike_alerts)
        
        # Check for negative sentiment alerts
        sentiment_alerts = await self._check_sentiment_alerts(sentiment_results)
        alerts.extend(sentiment_alerts)
        
        # Check for crisis keywords
        crisis_alerts = await self._check_crisis_alerts(mentions, sentiment_results)
        alerts.extend(crisis_alerts)
        
        # Store alerts
        self.alerts.extend(alerts)
        
        return alerts

    async def _check_mention_spikes(self, mentions: List[Mention], platform: str) -> List[BrandAlert]:
        """
        Check for unusual spikes in mention volume.
        """
        alerts = []
        
        # Group mentions by brand
        brand_mentions = defaultdict(int)
        for mention in mentions:
            brand_mentions[mention.matched_term] += 1
        
        # Check against baseline for each brand
        for brand, current_count in brand_mentions.items():
            baseline = self._get_baseline_mention_count(brand, platform)
            
            if baseline > 0 and current_count >= baseline * self.alert_thresholds["mention_spike_multiplier"]:
                alert = BrandAlert(
                    alert_type="mention_spike",
                    severity="high" if current_count >= baseline * 5 else "medium",
                    brand=brand,
                    message=f"Mention spike detected: {current_count} mentions (baseline: {baseline})",
                    data={
                        "current_count": current_count,
                        "baseline": baseline,
                        "multiplier": current_count / baseline,
                        "platform": platform
                    },
                    timestamp=datetime.now(timezone.utc)
                )
                alerts.append(alert)
        
        return alerts

    async def _check_sentiment_alerts(self, sentiment_results: List[SentimentResult]) -> List[BrandAlert]:
        """
        Check for negative sentiment alerts.
        """
        alerts = []
        
        for sentiment in sentiment_results:
            if (sentiment.sentiment == "negative" and 
                sentiment.confidence >= self.alert_thresholds["negative_sentiment_threshold"]):
                
                severity = "critical" if sentiment.threat_level == "critical" else "high"
                
                alert = BrandAlert(
                    alert_type="negative_sentiment",
                    severity=severity,
                    brand="detected_brand",  # Would need to map back to brand
                    message=f"High-confidence negative sentiment detected: {sentiment.emotion or 'negative'}",
                    data={
                        "sentiment": sentiment.sentiment,
                        "confidence": sentiment.confidence,
                        "emotion": sentiment.emotion,
                        "threat_level": sentiment.threat_level,
                        "keywords": sentiment.keywords,
                        "content_preview": sentiment.content[:100] + "..."
                    },
                    timestamp=sentiment.timestamp
                )
                alerts.append(alert)
        
        return alerts

    async def _check_crisis_alerts(self, mentions: List[Mention], sentiment_results: List[SentimentResult]) -> List[BrandAlert]:
        """
        Check for crisis-level events based on keywords and context.
        """
        alerts = []
        
        # Check mentions for crisis keywords
        for mention in mentions:
            content_lower = mention.text.lower()
            
            detected_keywords = []
            for keyword in self.alert_thresholds["crisis_keywords"]:
                if keyword in content_lower:
                    detected_keywords.append(keyword)
            
            if detected_keywords:
                alert = BrandAlert(
                    alert_type="crisis",
                    severity="critical",
                    brand=mention.matched_term,
                    message=f"Crisis keywords detected: {', '.join(detected_keywords)}",
                    data={
                        "crisis_keywords": detected_keywords,
                        "mention_type": mention.mention_type,
                        "confidence": mention.confidence,
                        "platform": mention.platform,
                        "content_preview": mention.text[:200] + "..."
                    },
                    timestamp=mention.timestamp
                )
                alerts.append(alert)
        
        # Check for multiple negative mentions in short time
        recent_negative = [s for s in sentiment_results 
                          if s.sentiment == "negative" and s.threat_level in ["high", "critical"]]
        
        if len(recent_negative) >= 3:
            alert = BrandAlert(
                alert_type="negative_trend",
                severity="high",
                brand="multiple_brands",
                message=f"Multiple high-threat negative mentions detected: {len(recent_negative)} in recent period",
                data={
                    "negative_count": len(recent_negative),
                    "threat_levels": [s.threat_level for s in recent_negative],
                    "emotions": [s.emotion for s in recent_negative if s.emotion]
                },
                timestamp=datetime.now(timezone.utc)
            )
            alerts.append(alert)
        
        return alerts

    def _get_baseline_mention_count(self, brand: str, platform: str, hours: int = 24) -> float:
        """
        Calculate baseline mention count for spike detection.
        """
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours * 7)  # 7-day lookback
        
        historical_mentions = [
            entry for entry in self.mention_history[brand]
            if entry["timestamp"] > cutoff_time and entry["platform"] == platform
        ]
        
        if len(historical_mentions) < 10:  # Not enough data
            return 1.0  # Conservative baseline
        
        # Group by day and calculate average
        daily_counts = defaultdict(int)
        for entry in historical_mentions:
            day_key = entry["timestamp"].strftime("%Y-%m-%d")
            daily_counts[day_key] += 1
        
        if not daily_counts:
            return 1.0
        
        return sum(daily_counts.values()) / len(daily_counts)

    def _sentiment_to_numeric(self, sentiment: str, confidence: float) -> float:
        """
        Convert sentiment to numeric score for calculations.
        """
        base_scores = {"positive": 0.8, "neutral": 0.5, "negative": 0.2}
        base_score = base_scores.get(sentiment, 0.5)
        
        # Weight by confidence
        if sentiment == "positive":
            return 0.5 + (confidence * 0.3)
        elif sentiment == "negative":
            return 0.5 - (confidence * 0.3)
        else:
            return 0.5

    async def _update_brand_metrics(self) -> None:
        """
        Update current brand metrics for all monitored brands.
        """
        for brand in self.monitored_brands:
            metrics = await self.get_brand_metrics(brand, 24)
            if metrics:
                self.current_metrics[brand] = metrics

    async def generate_report(self, brand: str, timeframe_hours: int = 24) -> Dict[str, Any]:
        """
        Generate comprehensive monitoring report for a brand.
        """
        metrics = await self.get_brand_metrics(brand, timeframe_hours)
        active_alerts = [alert for alert in self.alerts 
                        if alert.brand == brand and not alert.resolved]
        
        # Recent activity summary
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=timeframe_hours)
        recent_mentions = [
            entry for entry in self.mention_history[brand]
            if entry["timestamp"] > cutoff_time
        ]
        
        recent_sentiment = [
            sentiment for sentiment in self.sentiment_history[brand]
            if sentiment.timestamp > cutoff_time
        ]
        
        # Platform breakdown
        platform_activity = defaultdict(lambda: {"mentions": 0, "sentiment_avg": 0.5})
        for entry in recent_mentions:
            platform = entry["platform"]
            platform_activity[platform]["mentions"] += 1
        
        # Sentiment by platform
        for sentiment in recent_sentiment:
            # This is simplified - in practice you'd track platform per sentiment
            score = self._sentiment_to_numeric(sentiment.sentiment, sentiment.confidence)
            for platform in platform_activity:
                platform_activity[platform]["sentiment_avg"] = score  # Simplified
        
        report = {
            "brand": brand,
            "timeframe_hours": timeframe_hours,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "metrics": asdict(metrics) if metrics else None,
            "alerts": {
                "total_active": len(active_alerts),
                "by_severity": {
                    "critical": len([a for a in active_alerts if a.severity == "critical"]),
                    "high": len([a for a in active_alerts if a.severity == "high"]),
                    "medium": len([a for a in active_alerts if a.severity == "medium"]),
                    "low": len([a for a in active_alerts if a.severity == "low"])
                },
                "recent_alerts": [asdict(alert) for alert in active_alerts[-5:]]
            },
            "activity_summary": {
                "total_mentions": len(recent_mentions),
                "total_sentiment_analyses": len(recent_sentiment),
                "platform_breakdown": dict(platform_activity)
            },
            "recommendations": self._generate_recommendations(metrics, active_alerts)
        }
        
        return report

    def _generate_recommendations(self, metrics: Optional[BrandMetrics], alerts: List[BrandAlert]) -> List[str]:
        """
        Generate actionable recommendations based on monitoring data.
        """
        recommendations = []
        
        if not metrics:
            return ["Insufficient data for recommendations. Continue monitoring."]
        
        # Risk-based recommendations
        if metrics.risk_level == "critical":
            recommendations.append("URGENT: Implement crisis communication plan immediately")
            recommendations.append("Monitor social channels continuously for 24-48 hours")
            recommendations.append("Prepare official statement addressing concerns")
        
        elif metrics.risk_level == "high":
            recommendations.append("Increase monitoring frequency to hourly checks")
            recommendations.append("Prepare response templates for common concerns")
            recommendations.append("Consider proactive community engagement")
        
        # Sentiment-based recommendations
        if metrics.sentiment_score < 0.3:
            recommendations.append("Focus on positive content creation and engagement")
            recommendations.append("Address negative feedback promptly and professionally")
            recommendations.append("Consider influencer partnerships to improve sentiment")
        
        # Trend-based recommendations
        if metrics.trend == "declining":
            recommendations.append("Investigate root causes of declining sentiment")
            recommendations.append("Implement reputation recovery strategies")
            recommendations.append("Increase positive brand content frequency")
        
        # Alert-based recommendations
        critical_alerts = [a for a in alerts if a.severity == "critical"]
        if critical_alerts:
            recommendations.append("Address critical alerts within 1 hour")
            recommendations.append("Escalate to senior management immediately")
        
        # Platform-specific recommendations
        if len(metrics.top_platforms) == 1:
            recommendations.append("Diversify social media presence across platforms")
        
        if not recommendations:
            recommendations.append("Continue current monitoring. Brand health appears stable.")
        
        return recommendations