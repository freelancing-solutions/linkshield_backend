"""
Tests for ContentRiskAnalyzer AI integration.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from src.social_protection.content_analyzer.content_risk_analyzer import ContentRiskAnalyzer
from src.services.ai_service import AIService


@pytest.fixture
def mock_ai_service():
    """Create a mock AI service."""
    ai_service = Mock(spec=AIService)
    ai_service.analyze_content = AsyncMock()
    return ai_service


@pytest.fixture
def content_risk_analyzer(mock_ai_service):
    """Create ContentRiskAnalyzer with mocked AI service."""
    return ContentRiskAnalyzer(ai_service=mock_ai_service)


@pytest.mark.asyncio
async def test_analyze_content_risk_with_ai_integration(content_risk_analyzer, mock_ai_service):
    """Test that analyze_content_risk integrates AI analysis."""
    # Arrange
    test_content =