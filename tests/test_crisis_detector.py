#!/usr/bin/env python3
"""
Unit tests for CrisisDetector

Tests crisis detection logic including signal calculation, severity mapping,
hysteresis logic, AI integration, and alert persistence.
"""

import sys
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Import database and models first to avoid circular imports
from src.config.database import Base
from src.models.social_protection import CrisisAlertORM, CrisisStateORM

# Import crisis detector components directly
import importlib
crisis_detector_core = importlib.import_module('src.social_protection.crisis_detector.core')
CrisisDetector = crisis_detector_core.CrisisDetector
CrisisReport = crisis_detector_core.CrisisReport

reputation_tracker_module = importlib.import_module('src.social_protection.reputation_monitor.reputation_tracker')
ReputationTracker = reputation_tracker_module.ReputationTracker
BrandMetrics = reputation_tracker_module.BrandMetrics
InMemoryPersistence = reputation_tracker_module.InMemoryPersistence


# Test database setup
@pytest.fixture
async def test_db():
    """Create an in-memory test database."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    async_session = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    
    async with async_session() as session:
        yield session
    
    await engine.dispose()


@pytest.fixture
def mock_reputation_tracker():
    """Create a mock ReputationTracker."""
    tracker = MagicMock(spec=ReputationTracker)
    tracker.persistence = InMemoryPersistence()
    return tracker


@pytest.fixture
def mock_ai_service():
    """Create a mock AI service."""
    ai_service = AsyncMock()
    ai_service.analyze_content = AsyncMock(return_value={
        "summary": "Test crisis summary",
        "analysis": "Detailed analysis of the crisis situation"
    })
    return ai_service


@pytest.fixture
def crisis_detector(mock_reputation_tracker, mock_ai_service):
    """Create a CrisisDetector instance with mocked dependencies."""
    config = {
        "min_mentions": 5,
        "weights": {
            "volume": 0.30,
            "sentiment": 0.25,
            "keywords": 0.20,
            "emotion": 0.10,
            "amplification": 0.10,
            "cross_platform": 0.05
        },
        "crisis_keywords": [
            "scandal", "breach", "lawsuit", "fraud", "hack"
        ],
        "hysteresis_windows_required": 2,
        "cooldown_seconds": 900
    }
    
    return CrisisDetector(
        reputation_tracker=mock_reputation_tracker,
        ai_service=mock_ai_service,
        config=config
    )


class TestCrisisDetectorSignalCalculation:
    """Test signal calculation logic."""
    
    @pytest.mark.asyncio
    async def test_volume_signal_calculation(self, crisis_detector, test_db, mock_reputation_tracker):
        """Test volume spike signal calculation."""
        # Setup mock metrics with high trend score
        mock_metrics = BrandMetrics(
            brand="TestBrand",
            window_seconds=3600,
            mention_count=100,
            unique_mentions=80,
            sentiment_count=100,
            avg_sentiment=0.0,
            positive_ratio=0.5,
            negative_ratio=0.5,
            trend_score=5.0,  # High trend score
            last_mention_at=datetime.now(timezone.utc)
        )
        
        mock_reputation_tracker.get_brand_metrics = AsyncMock(return_value=mock_metrics)
        mock_reputation_tracker.persistence.range = AsyncMock(return_value=[
            {"text_snippet": f"Mention {i}", "metadata": {}} for i in range(100)
        ])
        mock_reputation_tracker.get_trending_brands = AsyncMock(return_value=[])
        
        report = await crisis_detector.evaluate_brand("TestBrand", test_db, window_seconds=3600)
        
        assert report.brand == "TestBrand"
        assert report.score > 0.0
        assert "volume_spike" in report.reasons
    
    @pytest.mark.asyncio
    async def test_sentiment_signal_calculation(self, crisis_detector, test_db, mock_reputation_tracker):
        """Test sentiment deterioration signal calculation."""
        # Setup mock metrics with negative sentiment
        mock_metrics = BrandMetrics(
            brand="TestBrand",
            window_seconds=3600,
            mention_count=50,
            unique_mentions=40,
            sentiment_count=50,
            avg_sentiment=-0.8,  # Very negative sentiment
            positive_ratio=0.1,
            negative_ratio=0.9,
            trend_score=1.0,
            last_mention_at=datetime.now(timezone.utc)
        )
        
        mock_reputation_tracker.get_brand_metrics = AsyncMock(return_value=mock_metrics)
        mock_reputation_tracker.persistence.range = AsyncMock(return_value=[
            {"text_snippet": f"Negative mention {i}", "metadata": {}} for i in range(50)
        ])
        mock_reputation_tracker.get_trending_brands = AsyncMock(return_value=[])
        
        report = await crisis_detector.evaluate_brand("TestBrand", test_db, window_seconds=3600)
        
        assert report.score > 0.0
        assert "negative_sentiment" in report.reasons
    
    @pytest.mark.asyncio
    async def test_crisis_keywords_detection(self, crisis_detector, test_db, mock_reputation_tracker):
        """Test crisis keyword detection."""
        mock_metrics = BrandMetrics(
            brand="TestBrand",
            window_seconds=3600,
            mention_count=20,
            unique_mentions=20,
            sentiment_count=20,
            avg_sentiment=0.0,
            positive_ratio=0.5,
            negative_ratio=0.5,
            trend_score=1.0,
            last_mention_at=datetime.now(timezone.utc)
        )
        
        # Include crisis keywords in mentions
        mentions = [
            {"text_snippet": "Major scandal involving TestBrand", "metadata": {}},
            {"text_snippet": "Data breach at TestBrand", "metadata": {}},
            {"text_snippet": "Lawsuit filed against TestBrand", "metadata": {}},
        ] + [{"text_snippet": f"Normal mention {i}", "metadata": {}} for i in range(17)]
        
        mock_reputation_tracker.get_brand_metrics = AsyncMock(return_value=mock_metrics)
        mock_reputation_tracker.persistence.range = AsyncMock(return_value=mentions)
        mock_reputation_tracker.get_trending_brands = AsyncMock(return_value=[])
        
        report = await crisis_detector.evaluate_brand("TestBrand", test_db, window_seconds=3600)
        
        assert "crisis_keywords" in report.reasons
        assert report.score > 0.0


class TestCrisisDetectorSeverityMapping:
    """Test severity level mapping."""
    
    @pytest.mark.asyncio
    async def test_ok_severity(self, crisis_detector, test_db, mock_reputation_tracker):
        """Test OK severity for low scores."""
        mock_metrics = BrandMetrics(
            brand="TestBrand",
            window_seconds=3600,
            mention_count=10,
            unique_mentions=10,
            sentiment_count=10,
            avg_sentiment=0.5,  # Positive sentiment
            positive_ratio=0.8,
            negative_ratio=0.2,
            trend_score=0.5,  # Low trend
            last_mention_at=datetime.now(timezone.utc)
        )
        
        mock_reputation_tracker.get_brand_metrics = AsyncMock(return_value=mock_metrics)
        mock_reputation_tracker.persistence.range = AsyncMock(return_value=[
            {"text_snippet": f"Positive mention {i}", "metadata": {}} for i in range(10)
        ])
        mock_reputation_tracker.get_trending_brands = AsyncMock(return_value=[])
        
        report = await crisis_detector.evaluate_brand("TestBrand", test_db, window_seconds=3600)
        
        assert report.severity == "ok"
        assert report.score < 0.4
    
    @pytest.mark.asyncio
    async def test_warning_severity(self, crisis_detector, test_db, mock_reputation_tracker):
        """Test warning severity for moderate scores."""
        mock_metrics = BrandMetrics(
            brand="TestBrand",
            window_seconds=3600,
            mention_count=50,
            unique_mentions=40,
            sentiment_count=50,
            avg_sentiment=-0.3,
            positive_ratio=0.3,
            negative_ratio=0.7,
            trend_score=2.5,
            last_mention_at=datetime.now(timezone.utc)
        )
        
        mock_reputation_tracker.get_brand_metrics = AsyncMock(return_value=mock_metrics)
        mock_reputation_tracker.persistence.range = AsyncMock(return_value=[
            {"text_snippet": f"Concerning mention {i}", "metadata": {}} for i in range(50)
        ])
        mock_reputation_tracker.get_trending_brands = AsyncMock(return_value=[])
        
        report = await crisis_detector.evaluate_brand("TestBrand", test_db, window_seconds=3600)
        
        assert report.severity == "warning"
        assert 0.4 <= report.score < 0.65
    
    @pytest.mark.asyncio
    async def test_critical_severity(self, crisis_detector, test_db, mock_reputation_tracker):
        """Test critical severity for high scores."""
        mock_metrics = BrandMetrics(
            brand="TestBrand",
            window_seconds=3600,
            mention_count=200,
            unique_mentions=150,
            sentiment_count=200,
            avg_sentiment=-0.9,  # Very negative
            positive_ratio=0.05,
            negative_ratio=0.95,
            trend_score=10.0,  # Very high trend
            last_mention_at=datetime.now(timezone.utc)
        )
        
        # Include many crisis keywords and negative emotions
        mentions = [
            {
                "text_snippet": f"scandal breach lawsuit fraud hack {i}",
                "metadata": {
                    "sentiment_emotion": "anger",
                    "author_verified": True
                }
            } for i in range(200)
        ]
        
        mock_reputation_tracker.get_brand_metrics = AsyncMock(return_value=mock_metrics)
        mock_reputation_tracker.persistence.range = AsyncMock(return_value=mentions)
        mock_reputation_tracker.get_trending_brands = AsyncMock(return_value=[
            {"brand": "TestBrand", "score": 100}
        ])
        
        report = await crisis_detector.evaluate_brand("TestBrand", test_db, window_seconds=3600)
        
        assert report.severity == "critical"
        assert report.score >= 0.85


class TestCrisisDetectorHysteresis:
    """Test hysteresis logic to prevent alert flapping."""
    
    @pytest.mark.asyncio
    async def test_consecutive_windows_required(self, crisis_detector, test_db, mock_reputation_tracker):
        """Test that alerts require consecutive high windows."""
        mock_metrics = BrandMetrics(
            brand="TestBrand",
            window_seconds=3600,
            mention_count=50,
            unique_mentions=40,
            sentiment_count=50,
            avg_sentiment=-0.5,
            positive_ratio=0.2,
            negative_ratio=0.8,
            trend_score=3.0,
            last_mention_at=datetime.now(timezone.utc)
        )
        
        mentions = [
            {
                "text_snippet": f"scandal breach {i}",
                "metadata": {"sentiment_emotion": "anger"}
            } for i in range(50)
        ]
        
        mock_reputation_tracker.get_brand_metrics = AsyncMock(return_value=mock_metrics)
        mock_reputation_tracker.persistence.range = AsyncMock(return_value=mentions)
        mock_reputation_tracker.get_trending_brands = AsyncMock(return_value=[])
        
        # First evaluation - should not create alert yet
        report1 = await crisis_detector.evaluate_brand("TestBrand", test_db, window_seconds=3600)
        assert report1.severity in ["warning", "high"]
        
        # Check that no alert was created yet
        from sqlalchemy import select
        stmt = select(CrisisAlertORM).where(CrisisAlertORM.brand == "TestBrand")
        result = await test_db.execute(stmt)
        alerts = result.scalars().all()
        assert len(alerts) == 0
        
        # Second evaluation - should create alert now
        report2 = await crisis_detector.evaluate_brand("TestBrand", test_db, window_seconds=3600)
        
        # Check that alert was created
        result = await test_db.execute(stmt)
        alerts = result.scalars().all()
        assert len(alerts) == 1
        assert alerts[0].brand == "TestBrand"
    
    @pytest.mark.asyncio
    async def test_cooldown_period(self, crisis_detector, test_db, mock_reputation_tracker):
        """Test cooldown period prevents rapid alert creation."""
        mock_metrics = BrandMetrics(
            brand="TestBrand",
            window_seconds=3600,
            mention_count=50,
            unique_mentions=40,
            sentiment_count=50,
            avg_sentiment=-0.5,
            positive_ratio=0.2,
            negative_ratio=0.8,
            trend_score=3.0,
            last_mention_at=datetime.now(timezone.utc)
        )
        
        mentions = [
            {
                "text_snippet": f"scandal breach {i}",
                "metadata": {"sentiment_emotion": "anger"}
            } for i in range(50)
        ]
        
        mock_reputation_tracker.get_brand_metrics = AsyncMock(return_value=mock_metrics)
        mock_reputation_tracker.persistence.range = AsyncMock(return_value=mentions)
        mock_reputation_tracker.get_trending_brands = AsyncMock(return_value=[])
        
        # Create initial alerts
        await crisis_detector.evaluate_brand("TestBrand", test_db, window_seconds=3600)
        await crisis_detector.evaluate_brand("TestBrand", test_db, window_seconds=3600)
        
        # Check initial alert count
        from sqlalchemy import select
        stmt = select(CrisisAlertORM).where(CrisisAlertORM.brand == "TestBrand")
        result = await test_db.execute(stmt)
        initial_alerts = result.scalars().all()
        initial_count = len(initial_alerts)
        
        # Evaluate again immediately - should not create new alert due to cooldown
        await crisis_detector.evaluate_brand("TestBrand", test_db, window_seconds=3600)
        
        result = await test_db.execute(stmt)
        alerts_after = result.scalars().all()
        assert len(alerts_after) == initial_count  # No new alerts during cooldown


class TestCrisisDetectorAIIntegration:
    """Test AI service integration."""
    
    @pytest.mark.asyncio
    async def test_ai_summary_generation(self, crisis_detector, test_db, mock_reputation_tracker, mock_ai_service):
        """Test AI-generated crisis summary."""
        mock_metrics = BrandMetrics(
            brand="TestBrand",
            window_seconds=3600,
            mention_count=20,
            unique_mentions=20,
            sentiment_count=20,
            avg_sentiment=-0.3,
            positive_ratio=0.3,
            negative_ratio=0.7,
            trend_score=2.0,
            last_mention_at=datetime.now(timezone.utc)
        )
        
        mentions = [
            {"text_snippet": f"Crisis mention {i}", "metadata": {}} for i in range(20)
        ]
        
        mock_reputation_tracker.get_brand_metrics = AsyncMock(return_value=mock_metrics)
        mock_reputation_tracker.persistence.range = AsyncMock(return_value=mentions)
        mock_reputation_tracker.get_trending_brands = AsyncMock(return_value=[])
        
        report = await crisis_detector.evaluate_brand("TestBrand", test_db, window_seconds=3600)
        
        # Verify AI service was called
        mock_ai_service.analyze_content.assert_called_once()
        
        # Verify summary was included
        assert report.summary is not None
        assert "Test crisis summary" in report.summary or "Detailed analysis" in report.summary
    
    @pytest.mark.asyncio
    async def test_ai_failure_graceful_handling(self, crisis_detector, test_db, mock_reputation_tracker, mock_ai_service):
        """Test graceful handling of AI service failures."""
        # Make AI service fail
        mock_ai_service.analyze_content = AsyncMock(side_effect=Exception("AI service error"))
        
        mock_metrics = BrandMetrics(
            brand="TestBrand",
            window_seconds=3600,
            mention_count=20,
            unique_mentions=20,
            sentiment_count=20,
            avg_sentiment=-0.3,
            positive_ratio=0.3,
            negative_ratio=0.7,
            trend_score=2.0,
            last_mention_at=datetime.now(timezone.utc)
        )
        
        mentions = [
            {"text_snippet": f"Crisis mention {i}", "metadata": {}} for i in range(20)
        ]
        
        mock_reputation_tracker.get_brand_metrics = AsyncMock(return_value=mock_metrics)
        mock_reputation_tracker.persistence.range = AsyncMock(return_value=mentions)
        mock_reputation_tracker.get_trending_brands = AsyncMock(return_value=[])
        
        # Should not raise exception
        report = await crisis_detector.evaluate_brand("TestBrand", test_db, window_seconds=3600)
        
        # Report should still be generated without AI summary
        assert report.brand == "TestBrand"
        assert report.summary is None  # AI failed, so no summary


class TestCrisisDetectorAlertPersistence:
    """Test alert persistence and retrieval."""
    
    @pytest.mark.asyncio
    async def test_alert_creation(self, crisis_detector, test_db, mock_reputation_tracker):
        """Test crisis alert creation and persistence."""
        mock_metrics = BrandMetrics(
            brand="TestBrand",
            window_seconds=3600,
            mention_count=50,
            unique_mentions=40,
            sentiment_count=50,
            avg_sentiment=-0.5,
            positive_ratio=0.2,
            negative_ratio=0.8,
            trend_score=3.0,
            last_mention_at=datetime.now(timezone.utc)
        )
        
        mentions = [
            {
                "text_snippet": f"scandal breach {i}",
                "metadata": {"sentiment_emotion": "anger"}
            } for i in range(50)
        ]
        
        mock_reputation_tracker.get_brand_metrics = AsyncMock(return_value=mock_metrics)
        mock_reputation_tracker.persistence.range = AsyncMock(return_value=mentions)
        mock_reputation_tracker.get_trending_brands = AsyncMock(return_value=[])
        
        # Trigger alert creation (need 2 consecutive windows)
        await crisis_detector.evaluate_brand("TestBrand", test_db, window_seconds=3600)
        await crisis_detector.evaluate_brand("TestBrand", test_db, window_seconds=3600)
        
        # Retrieve alerts
        alerts = await crisis_detector.get_crisis_alerts(test_db, brand="TestBrand")
        
        assert len(alerts) > 0
        alert = alerts[0]
        assert alert.brand == "TestBrand"
        assert alert.score > 0.0
        assert alert.severity in ["warning", "high", "critical"]
        assert not alert.resolved
    
    @pytest.mark.asyncio
    async def test_get_crisis_history(self, crisis_detector, test_db, mock_reputation_tracker):
        """Test retrieving crisis history."""
        mock_metrics = BrandMetrics(
            brand="TestBrand",
            window_seconds=3600,
            mention_count=50,
            unique_mentions=40,
            sentiment_count=50,
            avg_sentiment=-0.5,
            positive_ratio=0.2,
            negative_ratio=0.8,
            trend_score=3.0,
            last_mention_at=datetime.now(timezone.utc)
        )
        
        mentions = [
            {
                "text_snippet": f"scandal breach {i}",
                "metadata": {"sentiment_emotion": "anger"}
            } for i in range(50)
        ]
        
        mock_reputation_tracker.get_brand_metrics = AsyncMock(return_value=mock_metrics)
        mock_reputation_tracker.persistence.range = AsyncMock(return_value=mentions)
        mock_reputation_tracker.get_trending_brands = AsyncMock(return_value=[])
        
        # Create alerts
        await crisis_detector.evaluate_brand("TestBrand", test_db, window_seconds=3600)
        await crisis_detector.evaluate_brand("TestBrand", test_db, window_seconds=3600)
        
        # Get history
        history = await crisis_detector.get_crisis_history(test_db, "TestBrand", days=30)
        
        assert len(history) > 0
        assert all(alert.brand == "TestBrand" for alert in history)
    
    @pytest.mark.asyncio
    async def test_update_alert_status(self, crisis_detector, test_db, mock_reputation_tracker):
        """Test updating alert resolution status."""
        mock_metrics = BrandMetrics(
            brand="TestBrand",
            window_seconds=3600,
            mention_count=50,
            unique_mentions=40,
            sentiment_count=50,
            avg_sentiment=-0.5,
            positive_ratio=0.2,
            negative_ratio=0.8,
            trend_score=3.0,
            last_mention_at=datetime.now(timezone.utc)
        )
        
        mentions = [
            {
                "text_snippet": f"scandal breach {i}",
                "metadata": {"sentiment_emotion": "anger"}
            } for i in range(50)
        ]
        
        mock_reputation_tracker.get_brand_metrics = AsyncMock(return_value=mock_metrics)
        mock_reputation_tracker.persistence.range = AsyncMock(return_value=mentions)
        mock_reputation_tracker.get_trending_brands = AsyncMock(return_value=[])
        
        # Create alert
        await crisis_detector.evaluate_brand("TestBrand", test_db, window_seconds=3600)
        await crisis_detector.evaluate_brand("TestBrand", test_db, window_seconds=3600)
        
        # Get alert
        alerts = await crisis_detector.get_crisis_alerts(test_db, brand="TestBrand")
        alert = alerts[0]
        
        # Update status
        updated_alert = await crisis_detector.update_alert_status(
            test_db,
            str(alert.id),
            resolved=True
        )
        
        assert updated_alert is not None
        assert updated_alert.resolved
        assert updated_alert.resolved_at is not None


class TestCrisisDetectorEdgeCases:
    """Test edge cases and error handling."""
    
    @pytest.mark.asyncio
    async def test_insufficient_mentions(self, crisis_detector, test_db, mock_reputation_tracker):
        """Test handling of insufficient mentions."""
        mock_metrics = BrandMetrics(
            brand="TestBrand",
            window_seconds=3600,
            mention_count=2,  # Below minimum threshold
            unique_mentions=2,
            sentiment_count=2,
            avg_sentiment=0.0,
            positive_ratio=0.5,
            negative_ratio=0.5,
            trend_score=0.0,
            last_mention_at=datetime.now(timezone.utc)
        )
        
        mock_reputation_tracker.get_brand_metrics = AsyncMock(return_value=mock_metrics)
        mock_reputation_tracker.persistence.range = AsyncMock(return_value=[])
        mock_reputation_tracker.get_trending_brands = AsyncMock(return_value=[])
        
        report = await crisis_detector.evaluate_brand("TestBrand", test_db, window_seconds=3600)
        
        assert report.score == 0.0
        assert report.severity == "ok"
        assert len(report.reasons) == 0
    
    @pytest.mark.asyncio
    async def test_no_metrics_available(self, crisis_detector, test_db, mock_reputation_tracker):
        """Test handling when no metrics are available."""
        mock_reputation_tracker.get_brand_metrics = AsyncMock(return_value=None)
        mock_reputation_tracker.persistence.range = AsyncMock(return_value=[])
        mock_reputation_tracker.get_trending_brands = AsyncMock(return_value=[])
        
        report = await crisis_detector.evaluate_brand("TestBrand", test_db, window_seconds=3600)
        
        assert report.score == 0.0
        assert report.severity == "ok"
    
    @pytest.mark.asyncio
    async def test_evaluate_all_brands(self, crisis_detector, test_db, mock_reputation_tracker):
        """Test evaluating multiple brands."""
        mock_reputation_tracker.get_trending_brands = AsyncMock(return_value=[
            {"brand": "Brand1", "score": 10},
            {"brand": "Brand2", "score": 8},
            {"brand": "Brand3", "score": 6}
        ])
        
        # Mock metrics for each brand
        mock_metrics = BrandMetrics(
            brand="TestBrand",
            window_seconds=3600,
            mention_count=10,
            unique_mentions=10,
            sentiment_count=10,
            avg_sentiment=0.0,
            positive_ratio=0.5,
            negative_ratio=0.5,
            trend_score=1.0,
            last_mention_at=datetime.now(timezone.utc)
        )
        
        mock_reputation_tracker.get_brand_metrics = AsyncMock(return_value=mock_metrics)
        mock_reputation_tracker.persistence.range = AsyncMock(return_value=[
            {"text_snippet": f"Mention {i}", "metadata": {}} for i in range(10)
        ])
        
        reports = await crisis_detector.evaluate_all_brands(test_db, window_seconds=3600, limit=10)
        
        assert len(reports) == 3
        assert all(isinstance(report, CrisisReport) for report in reports)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
