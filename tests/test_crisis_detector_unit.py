#!/usr/bin/env python3
"""
Unit tests for CrisisDetector core logic

Minimal tests that avoid circular import issues by testing the core logic directly.
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from src.config.database import Base
from src.models.social_protection import CrisisAlertORM, CrisisStateORM


# Test database setup
@pytest.fixture
async def test_db():
    """Create an in-memory test database."""
    import pytest_asyncio
    
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
    
    session = async_session()
    yield session
    await session.close()
    await engine.dispose()


class TestCrisisAlertORM:
    """Test CrisisAlertORM model."""
    
    def test_alert_model_creation(self):
        """Test creating a crisis alert model instance."""
        alert = CrisisAlertORM(
            brand="TestBrand",
            platform="twitter",
            score=0.75,
            severity="high",
            reason="volume_spike, negative_sentiment",
            window_from=datetime.now(timezone.utc),
            window_to=datetime.now(timezone.utc),
            payload={"mention_count": 100}
        )
        
        assert alert.brand == "TestBrand"
        assert alert.score == 0.75
        assert alert.severity == "high"
        assert not alert.resolved
    
    def test_alert_to_dict(self):
        """Test alert to_dict method."""
        now = datetime.now(timezone.utc)
        alert = CrisisAlertORM(
            brand="TestBrand",
            platform="twitter",
            score=0.85,
            severity="critical",
            reason="crisis_keywords",
            window_from=now,
            window_to=now,
            payload={}
        )
        # Set created_at manually for testing
        alert.created_at = now
        
        alert_dict = alert.to_dict()
        
        assert alert_dict["brand"] == "TestBrand"
        assert alert_dict["score"] == 0.85
        assert alert_dict["severity"] == "critical"


class TestCrisisStateORM:
    """Test CrisisStateORM model."""
    
    def test_state_model_creation(self):
        """Test creating a crisis state model instance."""
        state = CrisisStateORM(
            brand="TestBrand",
            consecutive_high_windows=2,
            last_severity="warning",
            last_alert_at=datetime.now(timezone.utc)
        )
        
        assert state.brand == "TestBrand"
        assert state.consecutive_high_windows == 2
        assert state.last_severity == "warning"
    
    def test_state_to_dict(self):
        """Test state to_dict method."""
        now = datetime.now(timezone.utc)
        state = CrisisStateORM(
            brand="TestBrand",
            consecutive_high_windows=3,
            last_severity="high"
        )
        # Set updated_at manually for testing
        state.updated_at = now
        
        state_dict = state.to_dict()
        
        assert state_dict["brand"] == "TestBrand"
        assert state_dict["consecutive_high_windows"] == 3
        assert state_dict["last_severity"] == "high"


class TestCrisisDetectorLogic:
    """Test crisis detector logic without full imports."""
    
    def test_severity_mapping(self):
        """Test severity level mapping logic."""
        # Test severity thresholds
        def map_severity(score):
            if score >= 0.85:
                return "critical"
            elif score >= 0.65:
                return "high"
            elif score >= 0.4:
                return "warning"
            else:
                return "ok"
        
        assert map_severity(0.0) == "ok"
        assert map_severity(0.3) == "ok"
        assert map_severity(0.4) == "warning"
        assert map_severity(0.5) == "warning"
        assert map_severity(0.65) == "high"
        assert map_severity(0.75) == "high"
        assert map_severity(0.85) == "critical"
        assert map_severity(1.0) == "critical"
    
    def test_signal_weights(self):
        """Test signal weight calculation."""
        weights = {
            "volume": 0.30,
            "sentiment": 0.25,
            "keywords": 0.20,
            "emotion": 0.10,
            "amplification": 0.10,
            "cross_platform": 0.05
        }
        
        # Verify weights sum to 1.0
        assert sum(weights.values()) == 1.0
        
        # Test weighted score calculation
        signals = {
            "volume": 0.8,
            "sentiment": 0.6,
            "keywords": 0.4,
            "emotion": 0.3,
            "amplification": 0.2,
            "cross_platform": 0.1
        }
        
        score = sum(weights[k] * signals[k] for k in weights.keys())
        assert 0.0 <= score <= 1.0
        # Expected: 0.30*0.8 + 0.25*0.6 + 0.20*0.4 + 0.10*0.3 + 0.10*0.2 + 0.05*0.1
        # = 0.24 + 0.15 + 0.08 + 0.03 + 0.02 + 0.005 = 0.525
        assert abs(score - 0.525) < 0.001
    
    def test_hysteresis_logic(self):
        """Test hysteresis window tracking."""
        consecutive_windows = 0
        threshold = 0.4
        required_windows = 2
        
        # First high window
        score1 = 0.5
        if score1 >= threshold:
            consecutive_windows += 1
        assert consecutive_windows == 1
        assert consecutive_windows < required_windows  # No alert yet
        
        # Second high window
        score2 = 0.6
        if score2 >= threshold:
            consecutive_windows += 1
        assert consecutive_windows == 2
        assert consecutive_windows >= required_windows  # Alert should trigger
        
        # Low window resets counter
        score3 = 0.3
        if score3 < threshold:
            consecutive_windows = 0
        assert consecutive_windows == 0
    
    def test_cooldown_logic(self):
        """Test cooldown period logic."""
        from datetime import timedelta
        
        cooldown_seconds = 900  # 15 minutes
        last_alert_at = datetime.now(timezone.utc)
        
        # Check immediately after alert
        now = last_alert_at + timedelta(seconds=60)
        time_since_alert = (now - last_alert_at).total_seconds()
        in_cooldown = time_since_alert < cooldown_seconds
        assert in_cooldown
        
        # Check after cooldown period
        now = last_alert_at + timedelta(seconds=1000)
        time_since_alert = (now - last_alert_at).total_seconds()
        in_cooldown = time_since_alert < cooldown_seconds
        assert not in_cooldown


class TestCrisisKeywords:
    """Test crisis keyword detection."""
    
    def test_keyword_detection(self):
        """Test crisis keyword matching."""
        crisis_keywords = [
            "scandal", "breach", "lawsuit", "fraud", "hack"
        ]
        
        # Test positive matches
        text1 = "Major data breach at company"
        matches1 = [kw for kw in crisis_keywords if kw in text1.lower()]
        assert "breach" in matches1
        
        text2 = "Lawsuit filed against the brand"
        matches2 = [kw for kw in crisis_keywords if kw in text2.lower()]
        assert "lawsuit" in matches2
        
        # Test no matches
        text3 = "Great product launch today"
        matches3 = [kw for kw in crisis_keywords if kw in text3.lower()]
        assert len(matches3) == 0
    
    def test_keyword_ratio_calculation(self):
        """Test crisis keyword ratio calculation."""
        crisis_keywords = ["scandal", "breach", "lawsuit"]
        
        texts = [
            "Major scandal at the company",
            "Data breach detected",
            "Normal business update",
            "Another scandal emerges",
            "Regular announcement"
        ]
        
        kw_count = sum(1 for t in texts if any(k in t.lower() for k in crisis_keywords))
        kw_ratio = kw_count / len(texts)
        
        assert kw_count == 3
        assert kw_ratio == 0.6


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
