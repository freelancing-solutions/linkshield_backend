#!/usr/bin/env python3
"""
Brand Monitor - wired to MentionDetector, SentimentAnalyzer and ReputationTracker

This refactor wires the previously in-memory BrandMonitor into the production-ready
MentionDetector and ReputationTracker implementations created in the canvas.

Key changes:
- Injects ReputationTracker and uses it as the primary persistence & metrics engine
- Attaches numeric sentiment scores to Mention.metadata before persisting
- Keeps lightweight in-memory history for fast access / backward compatibility
- Preserves existing alerting logic but uses tracker metrics where appropriate
"""
from __future__ import annotations

import asyncio
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional

from .mention_detector import MentionDetector, Mention
from .sentiment_analyzer import SentimentAnalyzer, SentimentResult
from .reputation_tracker import ReputationTracker


@dataclass
class BrandAlert:
    """Brand monitoring alert"""

    alert_type: str  # mention_spike, negative_sentiment, crisis, trend_change
    severity: str  # low, medium, high, critical
    brand: str
    message: str
    data: Dict[str, Any]
    timestamp: datetime
    resolved: bool = False


@dataclass
class BrandSnapshot:
    """Brand performance snapshot (compatibility layer).

    This dataclass was renamed from `BrandSnapshot` to avoid a name clash with
    `reputation_tracker.BrandSnapshot`. It preserves the same fields used by
    the BrandMonitor compatibility layer.
    """

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
    """Comprehensive brand monitoring system with real-time analysis.

    This class is intended to be instantiated once (singleton) in your worker
    or application and configured with the brands to monitor.
    """

    def __init__(
        self,
        mention_detector: Optional[MentionDetector] = None,
        sentiment_analyzer: Optional[SentimentAnalyzer] = None,
        reputation_tracker: Optional[ReputationTracker] = None,
    ) -> None:
        self.mention_detector = mention_detector or MentionDetector()
        self.sentiment_analyzer = sentiment_analyzer or SentimentAnalyzer()
        self.reputation_tracker = reputation_tracker or ReputationTracker()

        # Monitoring configuration
        self.monitored_brands: Dict[str, Dict[str, Any]] = {}
        self.alert_thresholds = {
            "mention_spike_multiplier": 3.0,  # 3x normal volume
            "negative_sentiment_threshold": 0.7,
            "crisis_keywords": ["scandal", "lawsuit", "investigation", "breach", "hack", "fraud"],
            "volume_window_hours": 24,
        }

        # Lightweight in-memory caches (still useful for low-latency APIs)
        self.mention_history: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.sentiment_history: Dict[str, List[SentimentResult]] = defaultdict(list)
        self.alerts: List[BrandAlert] = []

        # Analysis cache
        self.baseline_metrics: Dict[str, Any] = {}
        self.current_metrics: Dict[str, BrandSnapshot] = {}

    def configure_brand_monitoring(self, brand_config: Dict[str, Dict[str, Any]]) -> None:
        """Configure brands for monitoring.

        Args:
            brand_config: Brand configuration with monitoring settings
        """
        self.monitored_brands = brand_config
        # Let the mention detector prepare regexes / patterns
        self.mention_detector.configure_brands(brand_config)

    async def monitor_content(self, content: str, platform: str, metadata: Optional[Dict] = None) -> Dict[str, Any]:
        """Monitor content for brand mentions and sentiment.

        Steps:
        1. Detect mentions
        2. Analyze sentiment for each mention
        3. Attach sentiment -> mention.metadata
        4. Persist mentions via ReputationTracker
        5. Run alert checks and update metrics
        """
        results = {"mentions": [], "sentiment_analysis": [], "alerts": [], "metrics_updated": False}
        if not content:
            return results

        # 1. Detect mentions
        mentions = await self.mention_detector.detect_mentions(content, platform, metadata or {})
        results["mentions"] = [asdict(m) for m in mentions]
        if not mentions:
            return results

        # 2. Analyze sentiment for each mention (concurrently)
        sentiment_tasks = [
            self.sentiment_analyzer.analyze_sentiment(m.sentiment_context, {"platform": platform, "mention_type": m.mention_type})
            for m in mentions
        ]
        sentiment_results = await asyncio.gather(*sentiment_tasks, return_exceptions=False)

        # 3. Attach sentiment scores to mention.metadata (expected by ReputationTracker)
        for mention, s in zip(mentions, sentiment_results):
            # Ensure mention.metadata exists
            mention.metadata = mention.metadata or {}
            # Numeric sentiment in [-1.0, 1.0] (use sentiment_analyzer's conversion)
            try:
                numeric = self.sentiment_analyzer._sentiment_to_score(s.sentiment, s.confidence)
            except Exception:
                # Fallback mapping
                if s.sentiment == "positive":
                    numeric = float(s.confidence)
                elif s.sentiment == "negative":
                    numeric = -float(s.confidence)
                else:
                    numeric = 0.0

            mention.metadata.update(
                {
                    "sentiment": numeric,
                    "sentiment_label": s.sentiment,
                    "sentiment_confidence": s.confidence,
                    "sentiment_emotion": s.emotion,
                    "sentiment_threat_level": s.threat_level,
                    "sentiment_keywords": s.keywords,
                }
            )

        # 4. Persist mentions via the ReputationTracker
        await self.reputation_tracker.add_mentions(mentions)

        # Also write to the lightweight in-memory caches for compatibility
        now = datetime.now(timezone.utc)
        for mention, s in zip(mentions, sentiment_results):
            brand = mention.matched_term
            self.mention_history[brand].append({"mention": mention, "timestamp": now, "platform": platform})
            self.sentiment_history[brand].append(s)

        results["sentiment_analysis"] = [asdict(s) for s in sentiment_results]

        # 5. Check alerts and update metrics
        alerts = await self._check_alerts(mentions, sentiment_results, platform)
        self.alerts.extend(alerts)
        results["alerts"] = [asdict(a) for a in alerts]

        # Update metrics using ReputationTracker and cache them
        for brand in {m.matched_term for m in mentions}:
            metrics = await self.reputation_tracker.get_brand_metrics(brand, window_seconds=self.alert_thresholds.get("volume_window_hours", 24) * 3600)
            # Map reputation_tracker.BrandSnapshot -> BrandMonitor.BrandSnapshot
            if metrics:
                mapped = BrandSnapshot(
                    total_mentions=metrics.mention_count,
                    positive_mentions=int((metrics.positive_ratio or 0.0) * (metrics.sentiment_count or 0)),
                    negative_mentions=int((metrics.negative_ratio or 0.0) * (metrics.sentiment_count or 0)),
                    neutral_mentions=max(0, metrics.mention_count - (metrics.sentiment_count or 0)),
                    sentiment_score=metrics.avg_sentiment or 0.0,
                    trend="improving" if (metrics.trend_score or 0) > 0.1 else ("declining" if (metrics.trend_score or 0) < -0.1 else "stable"),
                    risk_level="critical" if (metrics.avg_sentiment is not None and metrics.avg_sentiment < -0.5) else ("high" if (metrics.avg_sentiment is not None and metrics.avg_sentiment < -0.2) else "low"),
                    top_platforms=[],
                    timestamp=datetime.now(timezone.utc),
                )
                self.current_metrics[brand] = mapped

        results["metrics_updated"] = True
        return results

    async def get_brand_metrics(self, brand: str, timeframe_hours: int = 24) -> Optional[BrandSnapshot]:
        """Get comprehensive metrics for a specific brand.

        This method now defers to the ReputationTracker for accurate windowed
        metrics and converts the result into the BrandMonitor BrandSnapshot
        compatibility dataclass.
        """
        if brand not in self.monitored_brands:
            return None

        window_seconds = timeframe_hours * 3600
        rt_metrics = await self.reputation_tracker.get_brand_metrics(brand, window_seconds=window_seconds)
        if not rt_metrics:
            return BrandSnapshot(
                total_mentions=0,
                positive_mentions=0,
                negative_mentions=0,
                neutral_mentions=0,
                sentiment_score=0.5,
                trend="stable",
                risk_level="low",
                top_platforms=[],
                timestamp=datetime.now(timezone.utc),
            )

        bm = BrandSnapshot(
            total_mentions=rt_metrics.mention_count,
            positive_mentions=int((rt_metrics.positive_ratio or 0.0) * (rt_metrics.sentiment_count or 0)),
            negative_mentions=int((rt_metrics.negative_ratio or 0.0) * (rt_metrics.sentiment_count or 0)),
            neutral_mentions=max(0, rt_metrics.mention_count - (rt_metrics.sentiment_count or 0)),
            sentiment_score=rt_metrics.avg_sentiment or 0.0,
            trend="improving" if (rt_metrics.trend_score or 0) > 0.1 else ("declining" if (rt_metrics.trend_score or 0) < -0.1 else "stable"),
            risk_level="critical" if (rt_metrics.avg_sentiment is not None and rt_metrics.avg_sentiment < -0.5) else ("high" if (rt_metrics.avg_sentiment is not None and rt_metrics.avg_sentiment < -0.2) else "low"),
            top_platforms=[],
            timestamp=datetime.now(timezone.utc),
        )
        return bm

    async def get_active_alerts(self, severity_filter: Optional[str] = None) -> List[BrandAlert]:
        """Get active (unresolved) alerts, optionally filtered by severity."""
        active_alerts = [alert for alert in self.alerts if not alert.resolved]
        if severity_filter:
            active_alerts = [alert for alert in active_alerts if alert.severity == severity_filter]
        return sorted(active_alerts, key=lambda x: x.timestamp, reverse=True)

    async def resolve_alert(self, alert_timestamp: datetime) -> bool:
        """Mark an alert as resolved."""
        for alert in self.alerts:
            if alert.timestamp == alert_timestamp:
                alert.resolved = True
                return True
        return False

    async def _check_alerts(self, mentions: List[Mention], sentiment_results: List[SentimentResult], platform: str) -> List[BrandAlert]:
        """Check for various alert conditions."""
        alerts: List[BrandAlert] = []
        spike_alerts = await self._check_mention_spikes(mentions, platform)
        alerts.extend(spike_alerts)
        sentiment_alerts = await self._check_sentiment_alerts(sentiment_results, mentions)
        alerts.extend(sentiment_alerts)
        crisis_alerts = await self._check_crisis_alerts(mentions, sentiment_results)
        alerts.extend(crisis_alerts)
        return alerts

    async def _check_mention_spikes(self, mentions: List[Mention], platform: str) -> List[BrandAlert]:
        """Check for unusual spikes in mention volume using ReputationTracker baseline."""
        alerts: List[BrandAlert] = []
        brand_mentions: Dict[str, int] = defaultdict(int)
        for mention in mentions:
            brand_mentions[mention.matched_term] += 1

        for brand, current_count in brand_mentions.items():
            # Use reputation tracker to get baseline over the configured window
            baseline_window = self.alert_thresholds.get("volume_window_hours", 24) * 3600
            metrics = await self.reputation_tracker.get_brand_metrics(brand, window_seconds=baseline_window)
            baseline = metrics.mention_count / 24.0 if metrics and metrics.mention_count else 1.0
            if baseline > 0 and current_count >= baseline * self.alert_thresholds["mention_spike_multiplier"]:
                alert = BrandAlert(
                    alert_type="mention_spike",
                    severity="high" if current_count >= baseline * 5 else "medium",
                    brand=brand,
                    message=f"Mention spike detected: {current_count} mentions (baseline: {baseline:.2f})",
                    data={"current_count": current_count, "baseline": baseline, "multiplier": current_count / baseline, "platform": platform},
                    timestamp=datetime.now(timezone.utc),
                )
                alerts.append(alert)
        return alerts

    async def _check_sentiment_alerts(self, sentiment_results: List[SentimentResult], mentions: List[Mention]) -> List[BrandAlert]:
        """Check for negative sentiment alerts. Maps results back to mentions by order."""
        alerts: List[BrandAlert] = []
        for idx, sentiment in enumerate(sentiment_results):
            if sentiment.sentiment == "negative" and sentiment.confidence >= self.alert_thresholds["negative_sentiment_threshold"]:
                # Map back to mention
                matched_brand = mentions[idx].matched_term if idx < len(mentions) else "detected_brand"
                severity = "critical" if sentiment.threat_level == "critical" else "high"
                alert = BrandAlert(
                    alert_type="negative_sentiment",
                    severity=severity,
                    brand=matched_brand,
                    message=f"High-confidence negative sentiment detected: {sentiment.emotion or 'negative'}",
                    data={
                        "sentiment": sentiment.sentiment,
                        "confidence": sentiment.confidence,
                        "emotion": sentiment.emotion,
                        "threat_level": sentiment.threat_level,
                        "keywords": sentiment.keywords,
                        "content_preview": sentiment.content[:100] + "...",
                    },
                    timestamp=sentiment.timestamp,
                )
                alerts.append(alert)
        return alerts

    async def _check_crisis_alerts(self, mentions: List[Mention], sentiment_results: List[SentimentResult]) -> List[BrandAlert]:
        """Check for crisis-level events based on keywords and context."""
        alerts: List[BrandAlert] = []
        for mention in mentions:
            content_lower = mention.text.lower()
            detected_keywords: List[str] = []
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
                        "content_preview": mention.text[:200] + "...",
                    },
                    timestamp=mention.timestamp,
                )
                alerts.append(alert)

        # Check for multiple high-threat negative mentions
        recent_negative = [s for s in sentiment_results if s.sentiment == "negative" and s.threat_level in ["high", "critical"]]
        if len(recent_negative) >= 3:
            alert = BrandAlert(
                alert_type="negative_trend",
                severity="high",
                brand="multiple_brands",
                message=f"Multiple high-threat negative mentions detected: {len(recent_negative)} in recent period",
                data={"negative_count": len(recent_negative), "threat_levels": [s.threat_level for s in recent_negative], "emotions": [s.emotion for s in recent_negative if s.emotion]},
                timestamp=datetime.now(timezone.utc),
            )
            alerts.append(alert)

        return alerts

    def _get_baseline_mention_count(self, brand: str, platform: str, hours: int = 24) -> float:
        """(Deprecated) Calculate baseline mention count for spike detection using in-memory history.

        This kept for backward compatibility; new logic uses ReputationTracker.get_brand_metrics.
        """
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours * 7)
        historical_mentions = [entry for entry in self.mention_history[brand] if entry["timestamp"] > cutoff_time and entry["platform"] == platform]
        if len(historical_mentions) < 10:
            return 1.0
        daily_counts: Dict[str, int] = defaultdict(int)
        for entry in historical_mentions:
            day_key = entry["timestamp"].strftime("%Y-%m-%d")
            daily_counts[day_key] += 1
        if not daily_counts:
            return 1.0
        return sum(daily_counts.values()) / len(daily_counts)

    def _sentiment_to_numeric(self, sentiment: str, confidence: float) -> float:
        """Convert sentiment to numeric score for calculations.

        Kept as compatibility helper; prefer the SentimentAnalyzer._sentiment_to_score for coherence.
        """
        base_scores = {"positive": 0.8, "neutral": 0.5, "negative": 0.2}
        base_score = base_scores.get(sentiment, 0.5)
        if sentiment == "positive":
            return 0.5 + (confidence * 0.3)
        elif sentiment == "negative":
            return 0.5 - (confidence * 0.3)
        else:
            return 0.5

    async def _update_brand_metrics(self) -> None:
        """Update current brand metrics for all monitored brands using ReputationTracker."""
        for brand in self.monitored_brands:
            metrics = await self.get_brand_metrics(brand, 24)
            if metrics:
                self.current_metrics[brand] = metrics

    async def generate_report(self, brand: str, timeframe_hours: int = 24) -> Dict[str, Any]:
        """Generate comprehensive monitoring report for a brand."""
        metrics = await self.get_brand_metrics(brand, timeframe_hours)
        active_alerts = [alert for alert in self.alerts if alert.brand == brand and not alert.resolved]
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=timeframe_hours)
        recent_mentions = [entry for entry in self.mention_history[brand] if entry["timestamp"] > cutoff_time]
        recent_sentiment = [s for s in self.sentiment_history[brand] if s.timestamp > cutoff_time]

        platform_activity: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"mentions": 0, "sentiment_avg": 0.5})
        for entry in recent_mentions:
            platform = entry["platform"]
            platform_activity[platform]["mentions"] += 1
        # Sentiment by platform - simplified approximation
        score = 0.5
        if recent_sentiment:
            score = sum(self.sentiment_analyzer._sentiment_to_score(s.sentiment, s.confidence) for s in recent_sentiment) / len(recent_sentiment)
        for platform in platform_activity:
            platform_activity[platform]["sentiment_avg"] = score

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
                    "low": len([a for a in active_alerts if a.severity == "low"]),
                },
                "recent_alerts": [asdict(alert) for alert in active_alerts[-5:]],
            },
            "activity_summary": {"total_mentions": len(recent_mentions), "total_sentiment_analyses": len(recent_sentiment), "platform_breakdown": dict(platform_activity)},
            "recommendations": self._generate_recommendations(metrics, active_alerts),
        }
        return report

    def _generate_recommendations(self, metrics: Optional[BrandSnapshot], alerts: List[BrandAlert]) -> List[str]:
        """Generate actionable recommendations based on monitoring data."""
        recommendations: List[str] = []
        if not metrics:
            return ["Insufficient data for recommendations. Continue monitoring."]

        if metrics.risk_level == "critical":
            recommendations.append("URGENT: Implement crisis communication plan immediately")
            recommendations.append("Monitor social channels continuously for 24-48 hours")
            recommendations.append("Prepare official statement addressing concerns")
        elif metrics.risk_level == "high":
            recommendations.append("Increase monitoring frequency to hourly checks")
            recommendations.append("Prepare response templates for common concerns")
            recommendations.append("Consider proactive community engagement")

        if metrics.sentiment_score < 0.3:
            recommendations.append("Focus on positive content creation and engagement")
            recommendations.append("Address negative feedback promptly and professionally")
            recommendations.append("Consider influencer partnerships to improve sentiment")

        if metrics.trend == "declining":
            recommendations.append("Investigate root causes of declining sentiment")
            recommendations.append("Implement reputation recovery strategies")
            recommendations.append("Increase positive brand content frequency")

        critical_alerts = [a for a in alerts if a.severity == "critical"]
        if critical_alerts:
            recommendations.append("Address critical alerts within 1 hour")
            recommendations.append("Escalate to senior management immediately")

        if len(metrics.top_platforms) == 1:
            recommendations.append("Diversify social media presence across platforms")

        if not recommendations:
            recommendations.append("Continue current monitoring. Brand health appears stable.")

        return recommendations
